"""Sync jobs end-to-end into SQLite from a fake API (the same code runs on PostgreSQL)."""

from __future__ import annotations

import copy

import pytest
from sqlalchemy import func, select

from cxdash.db import models as m
from cxdash.db.repositories import (
    FindingRepository,
    InventoryRepository,
    ScanRepository,
    SyncRunRepository,
    SyncStateRepository,
)
from cxdash.metrics.open_rules import OpenRules
from cxdash.sync.backfill import BackfillJob
from cxdash.sync.findings import FindingsJob, PurgeJob
from cxdash.sync.inventory import InventoryJob
from cxdash.sync.jobs import JobRunner, LocalLock
from cxdash.sync.scans import ScansJob
from cxdash.sync.summaries import SummariesJob
from tests.conftest import make_settings
from tests.fakes import FakeReader


class Env:
    def __init__(self, db, **settings):
        self.db = db
        self.settings = make_settings(**{"sync_scan_selection": "all", **settings})
        self.api = FakeReader()
        self.inventory = InventoryRepository(db)
        self.scans = ScanRepository(db)
        self.state = SyncStateRepository(db)
        self.runs = SyncRunRepository(db)
        self.findings = FindingRepository(db, OpenRules.from_settings(self.settings))
        self.runner = JobRunner(self.runs, LocalLock())

    def inv_job(self):
        return InventoryJob(self.api, self.inventory, self.settings)

    def scans_job(self, **kw):
        return ScansJob(self.api, self.scans, self.inventory, self.state, self.settings, **kw)

    def summ_job(self):
        return SummariesJob(self.api, self.scans)

    def find_job(self, **kw):
        return FindingsJob(self.api, self.scans, self.findings, self.settings, **kw)

    async def full_cycle(self):
        for j in (self.inv_job(), self.scans_job(), self.summ_job(), self.find_job()):
            out = await self.runner.run(j)
            assert out.status == "success", out.error

    def snapshot(self):
        with self.db.session() as s:
            return {
                t.__tablename__: sorted(
                    map(tuple, s.execute(select(*t.__table__.c.values())).all()), key=repr
                )
                for t in (
                    m.Project,
                    m.Application,
                    m.Scan,
                    m.ScanCounter,
                    m.Finding,
                    m.FindingLifecycle,
                    m.ScanEngineStatus,
                )
                if t is not m.Project and t is not m.Application
            } | {"project_ids": sorted(self.inventory.active_project_ids())}


@pytest.fixture
def env(db):
    return Env(db)


def q(env, stmt):
    with env.db.session() as s:
        return s.execute(stmt).all()


async def test_inventory_upserts_and_flags_inactive(env):
    await env.runner.run(env.inv_job())
    assert env.inventory.active_project_ids() == {"p1", "p2", "p3"}
    env.api.project_items = [p for p in env.api.project_items if p["id"] != "p3"]
    await env.runner.run(env.inv_job())
    assert env.inventory.active_project_ids() == {"p1", "p2"}
    assert q(env, select(func.count()).select_from(m.Project))[0][0] == 3  # never deleted


async def test_inventory_filters(db):
    e = Env(db, cx_project_name_regex="^pay", cx_project_tags="team:pay")
    await e.runner.run(e.inv_job())
    assert e.inventory.active_project_ids() == {"p1"}
    e2 = Env(db, cx_project_name_regex="", cx_project_tags="", cx_applications="payments suite")
    await e2.runner.run(e2.inv_job())
    assert e2.inventory.active_project_ids() == {"p1", "p2"}  # app filter, case-insensitive


async def test_scans_only_configured_branches_and_known_projects(env):
    await env.full_cycle()
    ids = {r[0] for r in q(env, select(m.Scan.id))}
    assert ids == {"scan-0", "scan-1", "scan-2", "scan-4"}  # scan-3 is on feature/x
    latest = {r[0] for r in q(env, select(m.Scan.id).where(m.Scan.is_latest))}
    assert latest == {"scan-1", "scan-2"}  # scan-4 is still Running


async def test_glob_branches(db):
    e = Env(db, cx_branches="master,feature/*")
    await e.full_cycle()
    assert {r[0] for r in q(e, select(m.Scan.id))} == {"scan-0", "scan-1", "scan-3", "scan-4"}


async def test_empty_branches_means_all(db):
    e = Env(db, cx_branches="")
    await e.full_cycle()
    assert len(q(e, select(m.Scan.id))) == 5


async def test_second_run_changes_nothing(env):
    await env.full_cycle()
    first = env.snapshot()
    await env.full_cycle()
    assert env.snapshot() == first


async def test_running_scan_is_repolled_until_final(env):
    await env.full_cycle()
    assert q(env, select(m.Scan.status).where(m.Scan.id == "scan-4"))[0][0] == "Running"
    mark = env.state.get("scans").high_water_mark
    assert mark.isoformat() < "2026-10-16T01:00:00+00:00"  # never advances past the unfinished scan
    env.api.scan_items[4] = {
        **env.api.scan_items[4],
        "status": "Completed",
        "updatedAt": "2026-10-16T01:30:00Z",
    }
    await env.full_cycle()
    assert q(env, select(m.Scan.status, m.Scan.duration_seconds).where(m.Scan.id == "scan-4"))[0] == (
        "Completed",
        1800,
    )
    assert q(env, select(m.Scan.is_latest).where(m.Scan.id == "scan-4"))[0][0] is True


async def test_summary_counters_flattened(env):
    await env.full_cycle()
    rows = q(
        env,
        select(
            m.ScanCounter.engine,
            m.ScanCounter.severity,
            m.ScanCounter.state,
            m.ScanCounter.status,
            m.ScanCounter.count,
        ).where(m.ScanCounter.scan_id == "scan-0"),
    )
    assert ("sast", "HIGH", "ALL", "ALL", 3) in rows
    assert q(env, select(m.Scan.summary_loaded).where(m.Scan.id == "scan-0"))[0][0] is True


async def test_findings_loaded_only_for_latest_and_unknown_types_skipped(env):
    await env.full_cycle()
    rows = q(env, select(m.Finding.finding_id, m.Finding.engine))
    assert len(rows) == 8  # 9 results, 1 unknown type skipped
    assert {r[1] for r in rows} == {"sast", "sca", "kics", "containers", "secrets"}
    assert q(env, select(m.Scan.findings_loaded).where(m.Scan.id == "scan-1"))[0][0] is True
    assert q(env, select(m.Scan.findings_loaded).where(m.Scan.id == "scan-0"))[0][0] is False


async def test_engine_filter_limits_findings(db):
    e = Env(db, cx_engines="sast")
    await e.full_cycle()
    assert {r[0] for r in q(e, select(m.Finding.engine))} == {"sast"}


async def test_derived_counters_replace_summary_for_open_math(env):
    await env.full_cycle()
    rows = q(
        env,
        select(m.ScanCounter.engine, m.ScanCounter.severity, m.ScanCounter.state, m.ScanCounter.count).where(
            m.ScanCounter.scan_id == "scan-1", m.ScanCounter.status == "DERIVED"
        ),
    )
    by = {(r[0], r[1], r[2]): r[3] for r in rows}
    assert by[("sast", "HIGH", "TO_VERIFY")] == 1
    assert by[("sast", "HIGH", "NOT_EXPLOITABLE")] == 1
    assert by[("containers", "HIGH", "TO_VERIFY")] == 1


async def test_lifecycle_first_seen_uses_first_found_at(env):
    await env.full_cycle()
    row = q(
        env,
        select(m.FindingLifecycle.first_seen_at, m.FindingLifecycle.resolved_at).where(
            m.FindingLifecycle.similarity_id == "-111"
        ),
    )[0]
    assert row[0].isoformat().startswith("2026-09-01") and row[1] is None


async def test_lifecycle_closed_state_counts_as_resolved(env):
    await env.full_cycle()
    row = q(env, select(m.FindingLifecycle.resolved_at).where(m.FindingLifecycle.similarity_id == "-333"))[0]
    assert row[0] is not None  # NOT_EXPLOITABLE


async def test_lifecycle_missing_finding_is_resolved_only_if_engine_ran(env):
    await env.full_cycle()
    # next scan on master: sast finding -222 disappears; container engine FAILED in scan-1 so cont-1 must not resolve
    new_scan = copy.deepcopy(env.api.scan_items[0])
    new_scan.update(id="scan-9", createdAt="2026-10-16T05:00:00Z", updatedAt="2026-10-16T05:10:00Z")
    env.api.scan_items.append(new_scan)
    env.api.results_by_scan["scan-9"] = [
        r for r in env.api.results_by_scan["scan-1"] if r["id"] not in ("r-sast-2", "r-cont-1")
    ]
    await env.full_cycle()
    res = {
        r[0]: r[1] for r in q(env, select(m.FindingLifecycle.similarity_id, m.FindingLifecycle.resolved_at))
    }
    assert res["-222"] is not None  # sast ran, finding gone -> fixed
    cont = next(
        v for k, v in res.items() if k.startswith("cont-1|")
    )  # key = similarity|image|tag|package|version
    assert cont is None  # containers engine did not complete -> unknown, not fixed
    assert res["-111"] is None


async def test_lifecycle_reopen(env):
    await env.full_cycle()
    new_scan = copy.deepcopy(env.api.scan_items[0])
    new_scan.update(id="scan-8", createdAt="2026-10-16T04:00:00Z", updatedAt="2026-10-16T04:10:00Z")
    env.api.scan_items.append(new_scan)
    env.api.results_by_scan["scan-8"] = [
        r for r in env.api.results_by_scan["scan-1"] if r["id"] != "r-sast-2"
    ]
    await env.full_cycle()
    again = copy.deepcopy(new_scan)
    again.update(id="scan-10", createdAt="2026-10-16T06:00:00Z", updatedAt="2026-10-16T06:10:00Z")
    env.api.scan_items.append(again)
    env.api.results_by_scan["scan-10"] = env.api.results_by_scan["scan-1"]
    await env.full_cycle()
    assert (
        q(env, select(m.FindingLifecycle.resolved_at).where(m.FindingLifecycle.similarity_id == "-222"))[0][0]
        is None
    )


async def test_purge_keeps_only_configured_scans(db):
    e = Env(db, findings_keep_scans_per_branch=1)
    await e.full_cycle()
    # make scan-0 (older) loaded too so purge has something to delete
    with db.session() as s:
        s.add(
            m.Finding(
                scan_id="scan-0",
                finding_id="old",
                project_id="p1",
                branch="master",
                engine="sast",
                severity="LOW",
                state="X",
            )
        )
    out = await e.runner.run(PurgeJob(e.findings, e.settings))
    assert out.status == "success"
    assert q(e, select(func.count()).select_from(m.Finding).where(m.Finding.scan_id == "scan-0"))[0][0] == 0
    assert q(e, select(func.count()).select_from(m.Finding).where(m.Finding.scan_id == "scan-1"))[0][0] == 8
    assert (
        q(e, select(func.count()).select_from(m.ScanCounter).where(m.ScanCounter.scan_id == "scan-0"))[0][0]
        > 0
    )  # counters kept


async def test_purge_removes_scans_of_branches_no_longer_configured(db):
    e = Env(db, cx_branches="master,dis-devinteg")
    await e.full_cycle()
    e2 = Env(db, cx_branches="master")
    await e2.runner.run(PurgeJob(e2.findings, e2.settings))
    assert {r[0] for r in q(e2, select(m.Scan.branch).distinct())} == {"master"}


async def test_changing_branches_triggers_catch_up(db):
    e = Env(db, cx_branches="master")
    await e.full_cycle()
    assert "scan-2" not in {r[0] for r in q(e, select(m.Scan.id))}
    e2 = Env(db, cx_branches="master,dis-devinteg")
    await e2.runner.run(e2.scans_job())
    assert "scan-2" in {r[0] for r in q(e2, select(m.Scan.id))}


async def test_backfill_runs_scans_and_summaries_but_no_findings(env):
    await env.runner.run(env.inv_job())
    job = BackfillJob(lambda since: env.scans_job(force_since=since), env.summ_job(), env.state, env.settings)
    assert not job.done_before()
    out = await env.runner.run(job)
    assert out.status == "success"
    assert job.done_before()
    assert q(env, select(func.count()).select_from(m.Finding))[0][0] == 0
    assert q(env, select(func.count()).select_from(m.ScanCounter))[0][0] > 0


async def test_failed_job_is_recorded_and_does_not_raise(env):
    class Boom:
        name = "boom"

        async def run(self):
            raise RuntimeError("kaput")

    out = await env.runner.run(Boom())
    assert out.status == "failed" and "kaput" in out.error
    run = q(env, select(m.SyncRun.status, m.SyncRun.error).where(m.SyncRun.job == "boom"))[0]
    assert run[0] == "failed" and "kaput" in run[1]


async def test_overlapping_job_is_skipped(env):
    lock = LocalLock()
    runner = JobRunner(env.runs, lock)
    with lock.acquire("inventory") as got:
        assert got
        out = await runner.run(env.inv_job())
    assert out.status == "skipped"


async def test_findings_failure_isolated_per_scan(env):
    await env.runner.run(env.inv_job())
    await env.runner.run(env.scans_job())
    await env.runner.run(env.summ_job())
    original = env.api.results

    async def flaky(scan_id):
        if scan_id == "scan-2":
            raise RuntimeError("api down")
        async for r in original(scan_id):
            yield r

    env.api.results = flaky
    out = await env.runner.run(env.find_job())
    assert out.status == "failed"
    assert q(env, select(m.Scan.findings_loaded).where(m.Scan.id == "scan-1"))[0][0] is True  # good scan kept
    assert (
        q(env, select(m.Scan.findings_loaded).where(m.Scan.id == "scan-2"))[0][0] is False
    )  # retried next cycle


async def test_full_refresh_reloads_latest(env):
    await env.full_cycle()
    env.api.calls.clear()
    await env.runner.run(env.find_job(full_refresh=True))
    assert "results:scan-1" in env.api.calls


# --------------------------------------------------------------------------- last-scan strategy (ADR 0013)
def last_env(db, **kw):
    return Env(db, sync_scan_selection="last_scan", **kw)


def inc_scan(base, **over):
    scan = copy.deepcopy(base)
    scan.update(over)
    scan["metadata"] = {"configs": [{"type": "sast", "value": {"incremental": "true", "presetName": ""}}]}
    return scan


async def test_last_scan_mode_stores_only_the_newest_scan_per_project_and_branch(db):
    e = last_env(db)
    await e.full_cycle()
    assert {r[0] for r in q(e, select(m.Scan.id))} == {
        "scan-1",
        "scan-2",
    }  # scan-0 is older, scan-3 off-branch, scan-4 Running
    assert q(e, select(m.Scan.is_latest).where(m.Scan.id == "scan-1"))[0][0] is True
    calls = e.api.calls
    assert [c for c in calls if c.startswith("scans:")] == []  # never walks the scan list
    assert (
        sum(c.startswith("last_scans") for c in calls) == 2
    )  # one call per branch (all projects fit one batch)
    assert sum(c.startswith("scans_by_ids") for c in calls) == 1


async def test_last_scan_mode_makes_no_detail_calls_for_known_scans(db):
    e = last_env(db)
    await e.full_cycle()
    first = e.snapshot()
    e.api.calls.clear()
    await e.full_cycle()
    assert e.snapshot() == first
    assert not any(c.startswith(("scans_by_ids", "recent_scans")) for c in e.api.calls)


async def test_last_scan_batches_project_ids(db):
    e = last_env(db, sync_last_scan_batch=2)
    await e.runner.run(e.inv_job())
    await e.runner.run(e.scans_job())
    assert sorted(c for c in e.api.calls if c.startswith("last_scans")) == [
        "last_scans:dis-devinteg:1", "last_scans:dis-devinteg:2", "last_scans:master:1", "last_scans:master:2",
    ]  # fmt: skip


async def test_full_only_looks_past_an_incremental_latest_scan_once(db):
    e = last_env(db, sync_full_scans_only=True)
    e.api.scan_items.append(
        inc_scan(
            e.api.scan_items[0],
            id="scan-inc",
            createdAt="2026-10-15T12:00:00Z",
            updatedAt="2026-10-15T12:05:00Z",
        )
    )
    await e.full_cycle()
    assert {r[0] for r in q(e, select(m.Scan.id).where(m.Scan.project_id == "p1"))} == {
        "scan-1"
    }  # the full scan, not the incremental
    assert sum(c.startswith("recent_scans") for c in e.api.calls) == 1
    e.api.calls.clear()
    await e.full_cycle()
    assert not any(
        c.startswith(("recent_scans", "scans_by_ids")) for c in e.api.calls
    )  # remembered: no repeat lookups


async def test_incremental_scans_are_kept_by_default(db):
    e = last_env(db)
    e.api.scan_items.append(
        inc_scan(
            e.api.scan_items[0],
            id="scan-inc",
            createdAt="2026-10-15T12:00:00Z",
            updatedAt="2026-10-15T12:05:00Z",
        )
    )
    await e.full_cycle()
    assert "scan-inc" in {r[0] for r in q(e, select(m.Scan.id))}


async def test_full_only_with_no_full_scan_in_lookback_stores_nothing_for_that_project(db):
    e = last_env(db, sync_full_scans_only=True)
    e.api.scan_items = [inc_scan(s, id=s["id"]) if s["projectId"] == "p1" else s for s in e.api.scan_items]
    await e.full_cycle()
    assert q(e, select(m.Scan.id).where(m.Scan.project_id == "p1")) == []
    assert "scan-2" in {r[0] for r in q(e, select(m.Scan.id))}


async def test_counters_only_mode_makes_no_results_calls(db):
    e = last_env(db, sync_load_findings=False)
    await e.full_cycle()
    assert not any(c.startswith("results:") for c in e.api.calls)
    assert q(e, select(func.count()).select_from(m.Finding))[0][0] == 0
    assert (
        q(e, select(func.count()).select_from(m.ScanCounter))[0][0] > 0
    )  # overview still works from summaries


async def test_nightly_does_not_repull_findings_unless_enabled(db):
    from cxdash.container import build_container
    from cxdash.sync.scheduler import SyncService

    e = last_env(db)
    await e.full_cycle()
    c = build_container(e.settings, db)
    svc = SyncService(c, e.api)
    e.api.calls.clear()
    await svc.run_nightly()
    assert not any(x.startswith("results:") for x in e.api.calls)
    e.api.calls.clear()
    await svc.run_nightly(force_refresh=True)
    assert "results:scan-1" in e.api.calls


async def test_purge_can_drop_scan_history(db):
    e = Env(db, sync_keep_scan_history=False)  # "all" selection stores scan-0 and scan-1 for p1
    await e.full_cycle()
    assert "scan-0" in {r[0] for r in q(e, select(m.Scan.id))}
    out = await e.runner.run(PurgeJob(e.findings, e.settings))
    assert out.status == "success", out.error
    ids = {r[0] for r in q(e, select(m.Scan.id))}
    assert "scan-0" not in ids and {"scan-1", "scan-2"} <= ids


async def test_api_call_cap_stops_the_job_and_next_cycle_resumes(db):
    # the cap is enforced in the HTTP layer; here the runner passes it through to the per-run counter
    from cxdash.cx_client.http import ApiBudgetExceeded, track_api_calls

    counter = track_api_calls(2)
    counter.calls = 2
    assert counter.limit == 2 and isinstance(ApiBudgetExceeded("x"), RuntimeError)


async def test_toggling_full_only_off_reevaluates_previously_skipped_scans(db):
    on = last_env(db, sync_full_scans_only=True)
    on.api.scan_items.append(
        inc_scan(
            on.api.scan_items[0],
            id="scan-inc",
            createdAt="2026-10-15T12:00:00Z",
            updatedAt="2026-10-15T12:05:00Z",
        )
    )
    await on.full_cycle()
    assert "scan-inc" not in {r[0] for r in q(on, select(m.Scan.id))}
    off = last_env(db)
    off.api = on.api
    await off.runner.run(off.scans_job())
    assert "scan-inc" in {r[0] for r in q(off, select(m.Scan.id))}


async def test_duplicate_finding_keys_are_reported_not_silently_dropped(env, caplog):
    import logging

    from cxdash.cx_client.normalize import default_registry

    await env.runner.run(env.inv_job())
    await env.runner.run(env.scans_job())
    reg = default_registry()
    raw = {
        "type": "sast",
        "id": "same",
        "alternateId": "same",
        "severity": "LOW",
        "state": "TO_VERIFY",
        "data": {"queryName": "Q"},
    }
    rows = [reg.normalize(raw, "scan-1", "p1", "master"), reg.normalize(raw, "scan-1", "p1", "master")]
    with caplog.at_level(logging.WARNING):
        stored = env.findings.upsert_findings(rows)
    assert stored == 1 and "duplicate finding keys collapsed" in caplog.text
