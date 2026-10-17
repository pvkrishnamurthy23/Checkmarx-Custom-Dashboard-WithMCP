"""Exports, alerts, row-level scoping and worker wiring against a seeded SQLite database."""

from __future__ import annotations

import csv
import io
import logging
from datetime import timedelta

import httpx
import pytest
from flask import Flask
from openpyxl import load_workbook
from sqlalchemy import func, select

from cxdash.alerts.engine import AlertEngine, add_rule, render
from cxdash.alerts.notifiers import EmailNotifier, NotifyError, WebhookNotifier
from cxdash.alerts.rules import AlertCandidate
from cxdash.container import build_container
from cxdash.db import models as m
from cxdash.db.base import Base
from cxdash.db.queries.base import utcnow
from cxdash.db.session import Database, build_engine
from cxdash.devtools.seed import seed_demo
from cxdash.exporting import csv_stream, sanitize_cell, xlsx_bytes
from cxdash.filters import FilterSpec
from cxdash.security.auth import build_authenticator, install_security
from cxdash.ui.exporters import install_export_routes
from tests.conftest import make_settings


@pytest.fixture
def env(tmp_path):
    url = f"sqlite:///{tmp_path / 'f.db'}"
    s = make_settings(
        database_url=url, alert_webhook_url="https://hooks.example.invalid/x", alert_cooldown_hours=24
    )
    eng = build_engine(url)
    Base.metadata.create_all(eng)
    db = Database(eng)
    seed_demo(db, s, projects=10)
    return s, build_container(s, db)


def server_for(s, c, **kw):
    app = Flask(__name__)
    install_security(app, s, build_authenticator(s))
    install_export_routes(app, c)
    return app


PROXY = {
    "auth_mode": "proxy_headers",
    "trusted_proxy_ips": "10.0.0.0/8",
    "role_admin_groups": "adm",
    "role_analyst_groups": "ana",
}
ENV = {"REMOTE_ADDR": "10.0.0.1"}


# ------------------------------------------------------------------ exports
def test_sanitize_cell_neutralises_formulas():
    for evil in ("=cmd|' /C calc'!A0", "+1+1", "-2+3", "@SUM(A1)", "\t=1", "\r=1"):
        assert sanitize_cell(evil).startswith("'")
    assert sanitize_cell("normal") == "normal" and sanitize_cell(5) == 5 and sanitize_cell(None) is None


def test_csv_stream_bom_and_escaping():
    rows = [{"title": '=HYPERLINK("http://x")', "project": 'a,"b"\nc', "severity": "HIGH"}]
    data = b"".join(csv_stream(rows, ["title", "project", "severity"]))
    assert data.startswith(b"\xef\xbb\xbf")
    parsed = list(csv.reader(io.StringIO(data.decode("utf-8-sig"))))
    assert parsed[1][0].startswith("'=") and parsed[1][1] == 'a,"b"\nc'


def test_xlsx_has_summary_and_data_and_sanitises():
    blob = xlsx_bytes(
        [{"title": "=1+1", "severity": "HIGH"}] * 3, {"Filters": "none", "Rows": 3}, ["title", "severity"]
    )
    wb = load_workbook(io.BytesIO(blob))
    assert wb.sheetnames == ["Summary", "Data"]
    assert [c.value for c in wb["Data"][2]] == ["'=1+1", "HIGH"]
    assert any(r[0].value == "Filters" for r in wb["Summary"].iter_rows())
    assert wb["Data"].max_row == 4


def test_export_routes_enforce_role_and_audit(env):
    _s0, c = env
    s = make_settings(database_url=str(c.settings.database_url.get_secret_value()), **PROXY)
    client = server_for(s, c).test_client()
    h = lambda g: {"X-Forwarded-User": "bob", "X-Forwarded-Groups": g}  # noqa: E731
    assert (
        client.get("/export/findings.csv", headers=h(""), environ_overrides=ENV).status_code == 403
    )  # viewer
    ok = client.get("/export/findings.csv?sev=HIGH&engines=sast", headers=h("ana"), environ_overrides=ENV)
    assert ok.status_code == 200 and ok.mimetype == "text/csv"
    rows = list(csv.DictReader(io.StringIO(ok.get_data(as_text=True).lstrip("﻿"))))
    assert rows and {r["engine"] for r in rows} == {"sast"} and {r["severity"] for r in rows} == {"HIGH"}
    xl = client.get("/export/findings.xlsx?engines=kics", headers=h("ana"), environ_overrides=ENV)
    assert xl.status_code == 200 and load_workbook(io.BytesIO(xl.data)).sheetnames == ["Summary", "Data"]
    html = client.get("/export/executive.html", headers=h("ana"), environ_overrides=ENV)
    assert html.status_code == 200 and "executive security summary" in html.get_data(as_text=True)
    audit = c.queries.users.audit_rows()
    assert {"export_csv", "export_xlsx", "export_exec_html"} <= {a["action"] for a in audit}
    assert all(a["user"] == "bob" for a in audit)


def test_export_ignores_bad_engine_param_and_respects_row_cap(env):
    _s0, c = env
    s = make_settings(database_url=str(c.settings.database_url.get_secret_value()), export_row_cap=7, **PROXY)
    cc = build_container(s, c.db)
    client = server_for(s, cc).test_client()
    r = client.get(
        "/export/findings.csv?engines=evil,sast",
        headers={"X-Forwarded-User": "a", "X-Forwarded-Groups": "ana"},
        environ_overrides=ENV,
    )
    rows = list(csv.DictReader(io.StringIO(r.get_data(as_text=True).lstrip("﻿"))))
    assert len(rows) == 7 and {x["engine"] for x in rows} == {"sast"}


def test_export_respects_row_level_scope(env, tmp_path):
    _s0, c = env
    scope = tmp_path / "scope_map.yaml"
    scope.write_text("team-pay: [Payments]\n", encoding="utf-8")
    s = make_settings(
        database_url=str(c.settings.database_url.get_secret_value()), scope_map_path=str(scope), **PROXY
    )
    cc = build_container(s, c.db)
    client = server_for(s, cc).test_client()
    h = {"X-Forwarded-User": "a", "X-Forwarded-Groups": "ana,team-pay"}
    scoped = list(
        csv.DictReader(
            io.StringIO(
                client.get("/export/findings.csv", headers=h, environ_overrides=ENV)
                .get_data(as_text=True)
                .lstrip("﻿")
            )
        )
    )
    full = list(
        csv.DictReader(
            io.StringIO(
                client.get(
                    "/export/findings.csv",
                    headers={**h, "X-Forwarded-Groups": "ana,adm"},
                    environ_overrides=ENV,
                )
                .get_data(as_text=True)
                .lstrip("﻿")
            )
        )
    )
    assert 0 < len(scoped) < len(full)  # an admin sees everything, a scoped analyst only their application
    nothing = client.get(
        "/export/findings.csv", headers={**h, "X-Forwarded-Groups": "ana"}, environ_overrides=ENV
    )
    assert list(csv.DictReader(io.StringIO(nothing.get_data(as_text=True).lstrip("﻿")))) == []


# ------------------------------------------------------------------ scoping on queries
def test_scope_applications_restricts_every_query(env):
    _, c = env
    q = c.queries
    full = q.overview.kpis(FilterSpec())["TOTAL"]
    pay = q.overview.kpis(FilterSpec(scope_applications=("Payments",)))["TOTAL"]
    none = q.overview.kpis(FilterSpec(scope_applications=()))["TOTAL"]
    assert 0 < pay < full and none == 0
    assert q.findings.count(FilterSpec(scope_applications=())) == 0
    assert q.projects.table(FilterSpec(scope_applications=())) == []
    # a client-chosen application cannot widen the server-side scope
    assert (
        q.overview.kpis(FilterSpec(applications=("Storefront",), scope_applications=("Payments",)))["TOTAL"]
        == 0
    )


# ------------------------------------------------------------------ alerts
class Recorder:
    def __init__(self, name="webhook", fail=False):
        self.name, self.fail, self.sent = name, fail, []

    def available(self):
        return True

    def send(self, subject, text, html, recipients):
        if self.fail:
            raise NotifyError("boom")
        self.sent.append((subject, text, html, recipients))


def test_add_rule_validation(env):
    _, c = env
    with pytest.raises(ValueError):
        add_rule(c, "x", "nope", {}, "webhook")
    with pytest.raises(ValueError):
        add_rule(c, "x", "threshold", {}, "pigeon")
    with pytest.raises(Exception):  # noqa: B017
        add_rule(c, "x", "weekly_digest", {"cron": "not a cron"}, "webhook")
    assert add_rule(c, "ok", "threshold", {"engine": "sast", "severity": "HIGH", "count": 1}, "webhook") > 0


def test_threshold_rule_fires_once_then_dedupes(env):
    _, c = env
    add_rule(c, "t", "threshold", {"engine": "sast", "severity": "HIGH", "count": 1}, "webhook")
    rec = Recorder()
    engine = AlertEngine(c, {"webhook": rec})
    assert engine.run() == 1
    assert engine.run() == 0  # cooldown: same condition does not notify again
    assert len(rec.sent) == 1 and "HIGH" in rec.sent[0][0]
    with c.db.session() as s:
        assert s.scalar(select(func.count()).select_from(m.AlertEvent)) == 1


def test_threshold_not_exceeded_is_silent_and_failed_send_is_retried(env):
    _, c = env
    add_rule(c, "t", "threshold", {"engine": "sast", "severity": "CRITICAL", "count": 10**6}, "webhook")
    assert AlertEngine(c, {"webhook": Recorder()}).run() == 0
    add_rule(c, "t2", "threshold", {"engine": "sca", "severity": "HIGH", "count": 0}, "webhook")
    assert AlertEngine(c, {"webhook": Recorder(fail=True)}).run() == 0  # nothing recorded on failure...
    good = Recorder()
    assert AlertEngine(c, {"webhook": good}).run() == 1  # ...so the next cycle retries
    assert len(good.sent) == 1


def test_new_severity_scan_failed_stale_rules(env):
    _, c = env
    add_rule(c, "n", "new_severity", {"severity": "MEDIUM"}, "webhook")
    add_rule(c, "s", "stale_project", {"days": 1}, "webhook")
    add_rule(c, "f", "scan_failed", {}, "webhook")
    with c.db.session() as s:  # make one scan failed
        sc = s.scalars(select(m.Scan).where(m.Scan.is_latest.is_(True))).first()
        sc.status = "Failed"
        sc.created_at = utcnow() - timedelta(hours=1)
    rec = Recorder()
    sent = AlertEngine(c, {"webhook": rec}).run()
    titles = " | ".join(x[0] for x in rec.sent)
    assert sent >= 2 and "Scan problem" in titles
    assert "new MEDIUM+" in titles or "without a completed scan" in titles


def test_sla_breach_rule_reports_only_new_crossings(env):
    _, c = env
    rid = add_rule(c, "sla", "sla_breach", {"severities": ["CRITICAL", "HIGH"]}, "webhook")
    rec = Recorder()
    engine = AlertEngine(c, {"webhook": rec})
    c.state.set(f"alert-rule-{rid}", utcnow() - timedelta(days=400))  # long ago: everything past SLA is "new"
    assert engine.run() == 1
    assert engine.run() == 0  # evaluation time advanced; nothing newly crossed


def test_weekly_digest_due_and_content(env):
    _, c = env
    rid = add_rule(c, "d", "weekly_digest", {"cron": "0 8 * * 1"}, "webhook")
    c.state.set(f"alert-rule-{rid}", utcnow() - timedelta(days=8))
    rec = Recorder()
    assert AlertEngine(c, {"webhook": rec}).run() == 1
    assert (
        "digest" in rec.sent[0][0].lower() and "Top projects" in rec.sent[0][1] and "<table" in rec.sent[0][2]
    )
    assert AlertEngine(c, {"webhook": rec}).run() == 0  # not due again until next cron fire


def test_templates_escape_untrusted_text():
    cand = AlertCandidate("f", "<script>alert(1)</script>", ["<img src=x onerror=alert(1)>"], "HIGH")
    html = render(cand, True)
    assert "<script>" not in html and "&lt;script&gt;" in html and "<img" not in html
    assert "<script>" in render(cand, False)  # plain text part is not HTML


def test_email_notifier_validates_and_sanitises_headers(monkeypatch):
    s = make_settings(smtp_host="smtp.example.invalid", alert_email_from="a@b.c", smtp_port=25)
    sent = {}

    class FakeSMTP:
        def __init__(self, *a, **k): ...
        def __enter__(self):
            return self

        def __exit__(self, *a): ...
        def send_message(self, msg):
            sent["msg"] = msg

    monkeypatch.setattr("cxdash.alerts.notifiers.smtplib.SMTP", FakeSMTP)
    n = EmailNotifier(s)
    n.send(
        "Subject\r\nBcc: attacker@evil.example", "t", "<p>h</p>", ["ok@x.io", "bad address", "a@b.c, d@e.f"]
    )
    msg = sent["msg"]
    assert "\n" not in msg["Subject"] and "Bcc" not in msg
    assert msg["To"] == "ok@x.io"
    with pytest.raises(NotifyError):
        n.send("s", "t", None, ["nope"])


def test_webhook_notifier_posts_and_reports_errors():
    s = make_settings(alert_webhook_url="https://hooks.example.invalid/abc")
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"], seen["url"] = request.content, str(request.url)
        return httpx.Response(200)

    WebhookNotifier(s, httpx.MockTransport(handler)).send("Sub", "Body", None, [])
    assert b"Sub" in seen["body"] and seen["url"] == "https://hooks.example.invalid/abc"
    with pytest.raises(NotifyError):
        WebhookNotifier(s, httpx.MockTransport(lambda r: httpx.Response(500))).send("s", "b", None, [])
    assert not WebhookNotifier(make_settings(alert_webhook_url="")).available()


# ------------------------------------------------------------------ misc
def test_logging_redacts_secrets_and_tokens():
    from cxdash.logging import JsonFormatter, RedactingFilter

    f = RedactingFilter(["super-secret-key-123"])
    rec = logging.LogRecord(
        "x",
        logging.INFO,
        "",
        0,
        "key=super-secret-key-123 Authorization: Bearer abc.def.ghi refresh_token=zzz999",
        None,
        None,
    )
    f.filter(rec)
    out = JsonFormatter().format(rec)
    assert "super-secret-key-123" not in out and "abc.def.ghi" not in out and "zzz999" not in out


def test_env_example_is_a_valid_configuration(tmp_path):
    from pathlib import Path

    from cxdash.config import Settings

    text = (Path(__file__).resolve().parents[2] / ".env.example").read_text(encoding="utf-8")
    import re

    text = text.replace("CX_TENANT=your-tenant-name", "CX_TENANT=t")
    text = re.sub(r"^CX_API_KEY=", "CX_API_KEY=abcdefgh", text, flags=re.M)
    f = tmp_path / ".env"
    f.write_text(text, encoding="utf-8")
    s = Settings(_env_file=str(f))  # type: ignore[call-arg]
    assert s.cx_branches == ("master", "dis-devinteg") and s.sync_findings_cron == "0 2 * * *"
    assert s.cx_closed_states == ("NOT_EXPLOITABLE",) and s.alert_webhook_url.get_secret_value() == ""


def test_cache_versioning_and_json_roundtrip():
    from cxdash.cache import MemoryBackend, QueryCache

    ver = ["v1"]
    calls = []
    cache = QueryCache(MemoryBackend(), 60, lambda: ver[0])
    cache._ver_cache = (0.0, "")
    compute = lambda: calls.append(1) or {"a": [1, 2]}  # noqa: E731
    assert cache.get_or_compute("q", "h", compute) == {"a": [1, 2]}
    assert cache.get_or_compute("q", "h", compute) == {"a": [1, 2]} and len(calls) == 1
    ver[0] = "v2"
    cache._ver_cache = (0.0, "")
    cache.get_or_compute("q", "h", compute)
    assert len(calls) == 2  # new sync -> new data version -> recompute


def test_deeplink_is_safe():
    from cxdash.cx_client.deeplink import build_deeplink

    url = build_deeplink(
        "https://eu.ast.checkmarx.net/",
        "{ui_base}/results/{scan_id}/{project_id}/{engine}",
        scan_id="s/1?x",
        project_id="p",
        engine="sast",
    )
    assert url == "https://eu.ast.checkmarx.net/results/s%2F1%3Fx/p/sast"
    assert (
        build_deeplink("javascript:alert(1)//", "{ui_base}/x", scan_id="s", project_id="p", engine="e")
        is None
    )


def test_run_demo_seed_idempotent(env):
    s, c = env
    before = c.queries.overview.kpis(FilterSpec())["TOTAL"]
    seed_demo(c.db, s, projects=10)
    assert c.queries.overview.kpis(FilterSpec())["TOTAL"] == before


async def test_worker_wiring_runs_a_full_cycle_and_processes_requests(env):
    """SyncService (the scheduler's collaborator) with a fake API: queue -> cycle -> sync_run rows."""
    from cxdash.sync.scheduler import SyncService, build_scheduler
    from tests.fakes import FakeReader

    _s, c = env
    api = FakeReader()
    svc = SyncService(c, api)
    assert (await svc.run_inventory()).status == "success"
    outcomes = await svc.run_scans_cycle()
    assert [o.job for o in outcomes] == ["scans", "summaries", "findings", "alerts"]
    assert all(o.status == "success" for o in outcomes)
    c.requests.enqueue("alice", "scans")
    await svc.process_requests()
    assert c.requests.claim_pending() == []  # drained
    nightly = await svc.run_nightly()
    assert [o.job for o in nightly] == ["findings", "purge"]
    sched = build_scheduler(svc)
    assert {j.id for j in sched.get_jobs()} == {"inventory", "scans-cycle", "nightly", "requests", "lag"}


def test_trend_carries_each_scan_forward_until_replaced(env):
    """Hand-built timeline: the difference-array trend must equal a naive day-by-day reconstruction."""
    from datetime import timedelta

    from cxdash.db.upsert import upsert

    _, c = env
    now = utcnow().replace(hour=12, minute=0, second=0, microsecond=0)
    with c.db.session() as s:
        for pid in ("trend-p1", "trend-p2"):
            upsert(
                s,
                m.Project.__table__,
                [
                    {
                        "id": pid,
                        "name": pid,
                        "active": True,
                        "groups": [],
                        "tags": {},
                        "application_ids": ["demo-app-0"],
                        "updated_at": now,
                    }
                ],
                ["id"],
            )
        specs = [  # (scan id, project, days ago, HIGH count)
            ("t-a1", "trend-p1", 10, 5),
            ("t-a2", "trend-p1", 4, 9),
            ("t-a3", "trend-p1", 4, 7),  # a3 same day, later hour
            ("t-b1", "trend-p2", 40, 3),
        ]
        for i, (sid, pid, ago, high) in enumerate(specs):
            created = now - timedelta(days=ago) + timedelta(minutes=i)
            upsert(
                s,
                m.Scan.__table__,
                [
                    {
                        "id": sid,
                        "project_id": pid,
                        "branch": "master",
                        "status": "Completed",
                        "engines": ["sast"],
                        "created_at": created,
                        "summary_loaded": True,
                        "findings_loaded": False,
                        "is_latest": False,
                    }
                ],
                ["id"],
            )
            upsert(
                s,
                m.ScanCounter.__table__,
                [
                    {
                        "scan_id": sid,
                        "engine": "sast",
                        "severity": "HIGH",
                        "state": "ALL",
                        "status": "ALL",
                        "count": high,
                    }
                ],
                ["scan_id", "engine", "severity", "state", "status"],
            )
    f = FilterSpec(projects=("trend-p1", "trend-p2"))
    rows = {r["date"]: r["HIGH"] for r in c.queries.overview.trend(f, 30, now=now)}
    day = lambda ago: (now - timedelta(days=ago)).date().isoformat()  # noqa: E731
    assert rows[day(29)] == 3  # p2's older scan is carried in from before the window
    assert rows[day(11)] == 3  # p1 has no scan yet
    assert rows[day(10)] == 3 + 5
    assert rows[day(5)] == 3 + 5
    assert rows[day(4)] == 3 + 7  # a3 replaces a1 (a2 is superseded the same day)
    assert rows[day(0)] == 3 + 7
