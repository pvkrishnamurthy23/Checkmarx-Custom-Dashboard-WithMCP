"""Write-side repositories (one small class per aggregate; SRP / ISP).

Every method opens its own short transaction through ``Database.session()`` so
they are safe to call from worker threads.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, select, true, update

from cxdash.cx_client.models import ApplicationModel, CounterRow, NormalizedFinding, ProjectModel, ScanModel
from cxdash.db import models as m
from cxdash.db.session import Database
from cxdash.db.upsert import upsert
from cxdash.domain import COUNTER_DERIVED, FINAL_SCAN_STATUSES, USABLE_SCAN_STATUSES, is_final
from cxdash.metrics.open_rules import OpenRules
from cxdash.scope import branch_matches

log = logging.getLogger(__name__)


def _rowcount(result: Any) -> int:
    return int(getattr(result, "rowcount", 0) or 0)


def utcnow() -> datetime:
    return datetime.now(UTC)


class SyncStateRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def get(self, job: str) -> m.SyncState | None:
        with self._db.session() as s:
            return s.get(m.SyncState, job)

    def set(self, job: str, high_water_mark: datetime | None, details: dict[str, Any] | None = None) -> None:
        with self._db.session() as s:
            upsert(
                s,
                m.SyncState.__table__,
                [{"job": job, "high_water_mark": high_water_mark, "details": details}],
                ["job"],
            )


class SyncRunRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def start(self, job: str) -> int:
        with self._db.session() as s:
            run = m.SyncRun(job=job, started_at=utcnow(), status="running")
            s.add(run)
            s.flush()
            return run.id

    def finish(self, run_id: int, status: str, records: int, api_calls: int, error: str | None) -> None:
        with self._db.session() as s:
            s.execute(
                update(m.SyncRun)
                .where(m.SyncRun.id == run_id)
                .values(ended_at=utcnow(), status=status, records=records, api_calls=api_calls, error=error)
            )

    def last_success(self, job: str) -> datetime | None:
        with self._db.session() as s:
            return s.scalar(
                select(func.max(m.SyncRun.ended_at)).where(
                    m.SyncRun.job == job, m.SyncRun.status == "success"
                )
            )

    def mark_orphans_failed(self) -> int:
        """Runs left 'running' by a crashed worker are closed on the next start."""
        with self._db.session() as s:
            res = s.execute(
                update(m.SyncRun)
                .where(m.SyncRun.status == "running")
                .values(status="failed", ended_at=utcnow(), error="worker restarted while running")
            )
            return _rowcount(res)


class SyncRequestRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def enqueue(self, requested_by: str, job: str = "scans", params: dict[str, Any] | None = None) -> int:
        with self._db.session() as s:
            req = m.SyncRequest(requested_by=requested_by, job=job, params=params, requested_at=utcnow())
            s.add(req)
            s.flush()
            return req.id

    def last_request_at(self, requested_by: str) -> datetime | None:
        with self._db.session() as s:
            return s.scalar(
                select(func.max(m.SyncRequest.requested_at)).where(m.SyncRequest.requested_by == requested_by)
            )

    def claim_pending(self) -> list[tuple[int, str, dict[str, Any] | None]]:
        with self._db.session() as s:
            rows = s.execute(
                select(m.SyncRequest.id, m.SyncRequest.job, m.SyncRequest.params)
                .where(m.SyncRequest.picked_at.is_(None))
                .order_by(m.SyncRequest.id)
            ).all()
            if rows:
                s.execute(
                    update(m.SyncRequest)
                    .where(m.SyncRequest.id.in_([r[0] for r in rows]))
                    .values(picked_at=utcnow())
                )
            return [(r[0], r[1], r[2]) for r in rows]


class InventoryRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def upsert_projects(self, projects: Sequence[ProjectModel]) -> int:
        rows = [
            {
                "id": p.id,
                "name": p.name,
                "repo_url": p.repoUrl,
                "main_branch": p.mainBranch,
                "groups": p.groups,
                "tags": p.tags,
                "application_ids": p.applicationIds,
                "active": True,
                "created_at": p.createdAt,
                "updated_at": utcnow(),
            }
            for p in projects
        ]
        with self._db.session() as s:
            return upsert(s, m.Project.__table__, rows, ["id"])

    def mark_inactive_except(self, active_ids: Iterable[str]) -> int:
        """Projects that disappeared (or fell out of scope) are flagged inactive, never deleted."""
        ids = list(active_ids)
        with self._db.session() as s:
            stmt = update(m.Project).where(m.Project.active.is_(True))
            if ids:
                stmt = stmt.where(m.Project.id.notin_(ids))
            return _rowcount(s.execute(stmt.values(active=False)))

    def upsert_applications(self, apps: Sequence[ApplicationModel]) -> int:
        rows = [
            {"id": a.id, "name": a.name, "criticality": a.criticality, "tags": a.tags, "updated_at": utcnow()}
            for a in apps
        ]
        with self._db.session() as s:
            return upsert(s, m.Application.__table__, rows, ["id"])

    def active_project_ids(self) -> set[str]:
        with self._db.session() as s:
            return set(s.scalars(select(m.Project.id).where(m.Project.active.is_(True))))


class ScanRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def upsert_scans(self, scans: Sequence[ScanModel]) -> int:
        scan_rows, status_rows = [], []
        for sc in scans:
            final = is_final(sc.status)
            completed = sc.updatedAt if final else None
            scan_rows.append(
                {
                    "id": sc.id,
                    "project_id": sc.projectId,
                    "branch": sc.branch,
                    "status": sc.status,
                    "initiator": sc.initiator,
                    "source_type": sc.sourceType,
                    "source_origin": sc.sourceOrigin,
                    "engines": sorted({k for e in sc.engines for k in sc.engine_keys(e)}),
                    "created_at": sc.createdAt,
                    "completed_at": completed,
                    "duration_seconds": int((completed - sc.createdAt).total_seconds())
                    if completed
                    else None,
                }
            )
            for d in sc.statusDetails:
                for key in sc.engine_keys(d.name):
                    status_rows.append(
                        {"scan_id": sc.id, "engine": key, "status": d.status, "details": d.details}
                    )
        update_cols = [
            "status", "initiator", "source_type", "source_origin", "engines",
            "completed_at", "duration_seconds",
        ]  # fmt: skip
        with self._db.session() as s:
            n = upsert(s, m.Scan.__table__, scan_rows, ["id"], update_cols=update_cols)
            upsert(s, m.ScanEngineStatus.__table__, status_rows, ["scan_id", "engine"])
            return n

    def existing_ids(self, scan_ids: Iterable[str]) -> set[str]:
        ids = list(scan_ids)
        found: set[str] = set()
        with self._db.session() as s:
            for i in range(0, len(ids), 500):
                found.update(s.scalars(select(m.Scan.id).where(m.Scan.id.in_(ids[i : i + 500]))))
        return found

    def ids_needing_summary(self) -> list[str]:
        with self._db.session() as s:
            return list(
                s.scalars(
                    select(m.Scan.id)
                    .where(
                        m.Scan.summary_loaded.is_(False), func.upper(m.Scan.status).in_(USABLE_SCAN_STATUSES)
                    )
                    .order_by(m.Scan.created_at.desc())
                )
            )

    def save_summary_counters(self, scan_ids: Sequence[str], rows: Sequence[CounterRow]) -> None:
        """Replace summary-sourced counters for the scans and flag them loaded (idempotent)."""
        with self._db.session() as s:
            s.execute(
                delete(m.ScanCounter).where(
                    m.ScanCounter.scan_id.in_(list(scan_ids)), m.ScanCounter.status != COUNTER_DERIVED
                )
            )
            upsert(
                s,
                m.ScanCounter.__table__,
                [r.model_dump() for r in rows],
                ["scan_id", "engine", "severity", "state", "status"],
            )
            s.execute(update(m.Scan).where(m.Scan.id.in_(list(scan_ids))).values(summary_loaded=True))

    def recompute_latest(self) -> None:
        """One SQL statement: newest usable scan per (project, branch) is_latest (spec 7.1)."""
        ranked = (
            select(
                m.Scan.id,
                func.row_number()
                .over(partition_by=(m.Scan.project_id, m.Scan.branch), order_by=m.Scan.created_at.desc())
                .label("rn"),
            )
            .where(func.upper(m.Scan.status).in_(USABLE_SCAN_STATUSES))
            .subquery()
        )
        latest_ids = select(ranked.c.id).where(ranked.c.rn == 1)
        with self._db.session() as s:
            s.execute(update(m.Scan).values(is_latest=m.Scan.id.in_(latest_ids)))

    def latest_scans_needing_findings(self, branches: Sequence[str]) -> list[m.Scan]:
        with self._db.session() as s:
            scans = list(
                s.scalars(select(m.Scan).where(m.Scan.is_latest.is_(True), m.Scan.findings_loaded.is_(False)))
            )
        return [sc for sc in scans if branch_matches(sc.branch, branches)]

    def mark_findings_loaded(self, scan_id: str) -> None:
        with self._db.session() as s:
            s.execute(update(m.Scan).where(m.Scan.id == scan_id).values(findings_loaded=True))

    def reset_findings_loaded(self) -> int:
        """Nightly full refresh: force the latest scans to be re-pulled."""
        with self._db.session() as s:
            return _rowcount(
                s.execute(update(m.Scan).where(m.Scan.is_latest.is_(True)).values(findings_loaded=False))
            )

    def engine_statuses(self, scan_id: str) -> dict[str, str]:
        with self._db.session() as s:
            rows = s.execute(
                select(m.ScanEngineStatus.engine, m.ScanEngineStatus.status).where(
                    m.ScanEngineStatus.scan_id == scan_id
                )
            ).all()
        return {r[0]: (r[1] or "") for r in rows}

    def oldest_unfinished_created_at(self) -> datetime | None:
        """Oldest scan that is not yet in a final status (it must be re-polled)."""
        with self._db.session() as s:
            return s.scalar(
                select(func.min(m.Scan.created_at)).where(
                    func.upper(m.Scan.status).notin_(FINAL_SCAN_STATUSES)
                )
            )

    def known_branches(self) -> list[str]:
        with self._db.session() as s:
            return list(s.scalars(select(m.Scan.branch).distinct()))


class FindingRepository:
    def __init__(self, db: Database, rules: OpenRules) -> None:
        self._db = db
        self._rules = rules

    def upsert_findings(self, findings: Sequence[NormalizedFinding]) -> int:
        rows = [
            {
                **f.model_dump(exclude={"severity", "raw_json"}),
                "severity": f.severity.value,
                "raw_json": f.raw_json,
            }
            for f in findings
        ]
        with self._db.session() as s:
            stored = upsert(s, m.Finding.__table__, rows, ["scan_id", "finding_id"], chunk_size=500)
        if stored < len(
            rows
        ):  # never lose findings silently: this means result ids are not unique for an engine
            log.warning("duplicate finding keys collapsed", extra={"received": len(rows), "stored": stored})
        return stored

    def delete_scan_findings(self, scan_id: str, engines: Sequence[str] | None = None) -> None:
        """Remove stale rows before a full re-pull so fixed findings do not linger."""
        with self._db.session() as s:
            stmt = delete(m.Finding).where(m.Finding.scan_id == scan_id)
            if engines:
                stmt = stmt.where(m.Finding.engine.in_(list(engines)))
            s.execute(stmt)

    def derive_counters(self, scan_id: str) -> int:
        """Replace DERIVED severity x state counters for the scan from its finding rows (ADR 0005)."""
        with self._db.session() as s:
            s.execute(
                delete(m.ScanCounter).where(
                    m.ScanCounter.scan_id == scan_id, m.ScanCounter.status == COUNTER_DERIVED
                )
            )
            status_ok = (
                (
                    m.Finding.status.is_(None)
                    | func.upper(m.Finding.status).notin_(sorted(self._rules.closed_statuses))
                )
                if self._rules.closed_statuses
                else true()
            )
            grouped = s.execute(
                select(m.Finding.engine, m.Finding.severity, m.Finding.state, func.count())
                .where(m.Finding.scan_id == scan_id, status_ok)
                .group_by(m.Finding.engine, m.Finding.severity, m.Finding.state)
            ).all()
            rows = [
                {
                    "scan_id": scan_id,
                    "engine": e,
                    "severity": sev,
                    "state": st.upper(),
                    "status": COUNTER_DERIVED,
                    "count": n,
                }
                for e, sev, st, n in grouped
            ]
            return upsert(
                s, m.ScanCounter.__table__, rows, ["scan_id", "engine", "severity", "state", "status"]
            )

    def update_lifecycle(self, scan: m.Scan, engines_ok: Sequence[str]) -> int:
        """seen -> upsert last_seen_at; missing from newest scan -> resolved_at (spec 7.1).

        Findings in a closed state/status count as resolved. Only engines that provably ran
        (``engines_ok`` plus any engine present in the scan) can resolve findings, so a skipped
        engine never produces false "fixes".
        """
        seen_at = scan.created_at
        resolved_stamp = scan.completed_at or scan.created_at
        with self._db.session() as s:
            current = s.execute(
                select(
                    m.Finding.engine,
                    m.Finding.similarity_id,
                    func.min(m.Finding.first_found_at),
                    func.max(m.Finding.severity),
                    func.max(m.Finding.state),
                    func.max(m.Finding.status),
                )
                .where(m.Finding.scan_id == scan.id, m.Finding.similarity_id.is_not(None))
                .group_by(m.Finding.engine, m.Finding.similarity_id)
            ).all()
            existing: dict[tuple[str, str | None], m.FindingLifecycle] = {
                (r.engine, r.similarity_id): r
                for r in s.scalars(
                    select(m.FindingLifecycle).where(
                        m.FindingLifecycle.project_id == scan.project_id,
                        m.FindingLifecycle.branch == scan.branch,
                    )
                )
            }
            present_engines = {c[0] for c in current}
            rows: list[dict[str, Any]] = []
            seen_keys: set[tuple[str, str | None]] = set()
            for engine, sim, first_found, severity, state, status in current:
                key = (engine, sim)
                seen_keys.add(key)
                old = existing.get(key)
                first_seen = min(x for x in (first_found, seen_at, old.first_seen_at if old else None) if x)
                is_open = self._rules.is_open(state, status)
                resolved = None if is_open else ((old.resolved_at if old else None) or resolved_stamp)
                rows.append(
                    {
                        "project_id": scan.project_id,
                        "branch": scan.branch,
                        "engine": engine,
                        "similarity_id": sim,
                        "first_seen_at": first_seen,
                        "last_seen_at": seen_at,
                        "resolved_at": resolved,
                        "last_severity": severity,
                        "last_state": state,
                    }
                )
            ran = set(engines_ok) | present_engines
            for (engine, sim), old in existing.items():
                if (engine, sim) in seen_keys or engine not in ran or old.resolved_at is not None:
                    continue
                rows.append(
                    {
                        "project_id": scan.project_id,
                        "branch": scan.branch,
                        "engine": engine,
                        "similarity_id": sim,
                        "first_seen_at": old.first_seen_at,
                        "last_seen_at": old.last_seen_at,
                        "resolved_at": resolved_stamp,
                        "last_severity": old.last_severity,
                        "last_state": old.last_state,
                    }
                )
            return upsert(
                s,
                m.FindingLifecycle.__table__,
                rows,
                ["project_id", "branch", "engine", "similarity_id"],
            )

    # ------------------------------------------------------------------ purge
    def purge_non_latest_scans(self) -> int:
        """SYNC_KEEP_SCAN_HISTORY=false: keep only the latest scan per project/branch (counters of older scans go too)."""
        with self._db.session() as s:
            ids = list(s.scalars(select(m.Scan.id).where(m.Scan.is_latest.is_(False))))
            for i in range(0, len(ids), 500):
                s.execute(delete(m.Scan).where(m.Scan.id.in_(ids[i : i + 500])))
            return len(ids)

    def purge(self, keep_scans_per_branch: int, branch_patterns: Sequence[str]) -> dict[str, int]:
        """Keep finding detail for the latest N scans per (project, branch); drop out-of-scope branches."""
        removed = {"findings": 0, "scans": 0}
        ranked = (
            select(
                m.Scan.id,
                func.row_number()
                .over(partition_by=(m.Scan.project_id, m.Scan.branch), order_by=m.Scan.created_at.desc())
                .label("rn"),
            )
            .where(func.upper(m.Scan.status).in_(FINAL_SCAN_STATUSES))
            .subquery()
        )
        stale = select(ranked.c.id).where(ranked.c.rn > keep_scans_per_branch)
        with self._db.session() as s:
            removed["findings"] = _rowcount(s.execute(delete(m.Finding).where(m.Finding.scan_id.in_(stale))))
            if branch_patterns:
                branches = list(s.scalars(select(m.Scan.branch).distinct()))
                out = [b for b in branches if not branch_matches(b, branch_patterns)]
                if out:
                    ids = list(s.scalars(select(m.Scan.id).where(m.Scan.branch.in_(out))))
                    for i in range(0, len(ids), 500):
                        s.execute(delete(m.Scan).where(m.Scan.id.in_(ids[i : i + 500])))
                    s.execute(delete(m.FindingLifecycle).where(m.FindingLifecycle.branch.in_(out)))
                    removed["scans"] = len(ids)
        return removed

    def purge_old_run_logs(self, days: int = 90) -> int:
        cutoff = utcnow() - timedelta(days=days)
        with self._db.session() as s:
            return _rowcount(s.execute(delete(m.SyncRun).where(m.SyncRun.started_at < cutoff)))
