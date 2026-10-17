"""Alert rule evaluators (spec section 13). One small class per rule kind (Open/Closed):
add a kind by registering another evaluator, no engine change needed."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Protocol

from apscheduler.triggers.cron import CronTrigger
from sqlalchemy import and_, func, select

from cxdash.container import Container
from cxdash.db import models as m
from cxdash.db.queries.base import utcnow
from cxdash.domain import SEVERITY_ORDER, is_final
from cxdash.filters import FilterSpec

SEV_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}


@dataclass(frozen=True)
class AlertCandidate:
    fingerprint: str
    title: str
    lines: list[str] = field(default_factory=list)
    severity: str = "INFO"
    template: str = "alert"
    data: Mapping[str, Any] = field(default_factory=dict)
    cooldown_hours: int | None = None  # None -> ALERT_COOLDOWN_HOURS


class RuleEvaluator(Protocol):
    kind: str

    def evaluate(self, rule: m.AlertRule, c: Container, now: datetime) -> list[AlertCandidate]: ...


def _h(*parts: object) -> str:
    return hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:20]


def _params(rule: m.AlertRule) -> dict[str, Any]:
    return dict(rule.params or {})


def _last_eval(c: Container, rule: m.AlertRule, now: datetime, default: timedelta) -> datetime:
    st = c.state.get(f"alert-rule-{rule.id}")
    return st.high_water_mark if st and st.high_water_mark else now - default


class NewSeverityRule:
    """A newly loaded latest scan has NEW findings at or above a severity."""

    kind = "new_severity"

    def evaluate(self, rule: m.AlertRule, c: Container, now: datetime) -> list[AlertCandidate]:
        p = _params(rule)
        threshold = str(p.get("severity", "HIGH")).upper()
        if threshold not in SEV_RANK:
            return []
        sevs = [s for s in SEVERITY_ORDER if SEV_RANK[s] <= SEV_RANK[threshold]]
        engines = [e.lower() for e in p.get("engines", [])] or list(c.settings.cx_engines)
        branches = p.get("branches") or None
        since = now - timedelta(hours=max(48, c.settings.alert_cooldown_hours))
        f, s = m.Finding, m.Scan
        stmt = (
            select(s.id, m.Project.name, s.branch, f.severity, f.engine, f.title)
            .select_from(f)
            .join(s, s.id == f.scan_id)
            .join(m.Project, m.Project.id == s.project_id)
            .where(s.is_latest.is_(True), s.findings_loaded.is_(True), s.created_at >= since, func.upper(f.status) == "NEW",
                   f.severity.in_(sevs), f.engine.in_(engines), c.rules.open_sql(f.state, f.status),
                   *([s.branch.in_(branches)] if branches else []))
            .order_by(f.severity)
        )  # fmt: skip
        with c.db.session() as sess:
            rows = sess.execute(stmt).all()
        by_scan: dict[str, list[Any]] = {}
        for row in rows:
            by_scan.setdefault(row[0], []).append(row)
        out = []
        for scan_id, items in by_scan.items():
            worst = min((SEV_RANK[i[3]] for i in items), default=4)
            lines = [f"{i[3]} {i[4]}: {i[5]}" for i in items[:10]]
            out.append(AlertCandidate(
                _h(rule.id, scan_id), f"{len(items)} new {threshold}+ finding(s) in {items[0][1]} ({items[0][2]})", lines,
                SEVERITY_ORDER[worst], cooldown_hours=10**6))  # fmt: skip
        return out


class SlaBreachRule:
    """A finding crossed its SLA threshold since the last evaluation."""

    kind = "sla_breach"

    def evaluate(self, rule: m.AlertRule, c: Container, now: datetime) -> list[AlertCandidate]:
        p = _params(rule)
        sevs = [str(x).upper() for x in p.get("severities", ["CRITICAL", "HIGH"])]
        last = _last_eval(c, rule, now, timedelta(days=1))
        f, s, lc = m.Finding, m.Scan, m.FindingLifecycle
        conds = []
        for sev in sevs:
            days = c.settings.sla_days(sev)
            if days is None:
                continue
            ts = func.coalesce(f.first_found_at, lc.first_seen_at)
            conds.append(
                and_(f.severity == sev, ts <= now - timedelta(days=days), ts > last - timedelta(days=days))
            )
        if not conds:
            return []
        from sqlalchemy import or_

        stmt = (
            select(m.Project.name, f.severity, f.engine, f.title)
            .select_from(f)
            .join(s, s.id == f.scan_id)
            .join(m.Project, m.Project.id == s.project_id)
            .outerjoin(
                lc,
                and_(
                    lc.project_id == f.project_id,
                    lc.branch == f.branch,
                    lc.engine == f.engine,
                    lc.similarity_id == f.similarity_id,
                ),
            )
            .where(s.is_latest.is_(True), c.rules.open_sql(f.state, f.status), or_(*conds))
        )
        with c.db.session() as sess:
            rows = sess.execute(stmt).all()
        c.state.set(f"alert-rule-{rule.id}", now)
        if not rows:
            return []
        lines = [f"{r[1]} {r[2]} in {r[0]}: {r[3]}" for r in rows[:15]]
        worst = min(SEV_RANK[r[1]] for r in rows)
        return [
            AlertCandidate(
                _h(rule.id, now.isoformat()),
                f"{len(rows)} finding(s) crossed their SLA",
                lines,
                SEVERITY_ORDER[worst],
                cooldown_hours=0,
            )
        ]


class ScanFailedRule:
    """A scan on a configured branch ended Failed, or an engine failed."""

    kind = "scan_failed"

    def evaluate(self, rule: m.AlertRule, c: Container, now: datetime) -> list[AlertCandidate]:
        engines = {e.lower() for e in _params(rule).get("engines", [])}
        since = now - timedelta(hours=48)
        rs = c.queries.ctx.resolver.resolve(FilterSpec())
        s, es = m.Scan, m.ScanEngineStatus
        with c.db.session() as sess:
            scans = sess.execute(
                select(s.id, m.Project.name, s.branch, s.status)
                .join(m.Project, m.Project.id == s.project_id)
                .where(
                    s.created_at >= since, *([s.branch.in_(rs.branches)] if rs.branches is not None else [])
                )
            ).all()
            bad_engines: dict[str, list[str]] = {}
            for sid, eng, st in sess.execute(
                select(es.scan_id, es.engine, es.status).where(es.scan_id.in_([x[0] for x in scans] or [""]))
            ):
                if (st or "").lower() == "failed" and (not engines or eng in engines):
                    bad_engines.setdefault(sid, []).append(eng)
        out = []
        for sid, name, branch, status in scans:
            failed_scan = status.upper() == "FAILED" and is_final(status)
            if failed_scan or sid in bad_engines:
                detail = "scan failed" if failed_scan else "engine(s) failed: " + ", ".join(bad_engines[sid])
                out.append(
                    AlertCandidate(
                        _h(rule.id, sid),
                        f"Scan problem in {name} ({branch})",
                        [detail],
                        "HIGH",
                        cooldown_hours=10**6,
                    )
                )
        return out


class StaleProjectRule:
    kind = "stale_project"

    def evaluate(self, rule: m.AlertRule, c: Container, now: datetime) -> list[AlertCandidate]:
        days = int(_params(rule).get("days", c.settings.stale_project_days))
        health = c.queries.projects.scan_health(FilterSpec())
        cutoff = now - timedelta(days=days)
        stale = [p for p in health["stale_projects"] if p["last_scan"] is None or p["last_scan"] < cutoff]
        if not stale:
            return []
        ids = sorted(p["project_id"] for p in stale)
        lines = [
            f"{p['project']} (last scan: {p['last_scan'].date() if p['last_scan'] else 'never'})"
            for p in stale[:20]
        ]
        return [
            AlertCandidate(
                _h(rule.id, *ids),
                f"{len(stale)} project(s) without a completed scan for {days}+ days",
                lines,
                "MEDIUM",
            )
        ]


class ThresholdRule:
    kind = "threshold"

    def evaluate(self, rule: m.AlertRule, c: Container, now: datetime) -> list[AlertCandidate]:
        p = _params(rule)
        engine = str(p.get("engine", "")).lower()
        severity = str(p.get("severity", "CRITICAL")).upper()
        limit = int(p.get("count", 0))
        f = FilterSpec(engines=(engine,) if engine else (), severities=(severity,))
        total = sum(c.queries.overview.open_by_engine_severity(f).values())
        if total <= limit:
            return []
        label = engine or "all engines"
        return [
            AlertCandidate(
                _h(rule.id, label, severity),
                f"{total} open {severity} findings in {label} (threshold {limit})",
                [f"Open: {total}", f"Threshold: {limit}"],
                severity,
            )
        ]


class WeeklyDigestRule:
    kind = "weekly_digest"

    def evaluate(self, rule: m.AlertRule, c: Container, now: datetime) -> list[AlertCandidate]:
        cron = str(_params(rule).get("cron", "0 8 * * 1"))
        trigger = CronTrigger.from_crontab(cron, timezone="UTC")
        last = _last_eval(c, rule, now, timedelta(days=7))
        due = trigger.get_next_fire_time(None, last)
        if due is None or due > now:
            return []
        c.state.set(f"alert-rule-{rule.id}", now)
        data = build_digest(c, now)
        return [
            AlertCandidate(
                _h(rule.id, due.isoformat()),
                "Checkmarx One weekly security digest",
                [],
                "INFO",
                "digest",
                data,
                cooldown_hours=0,
            )
        ]


def build_digest(c: Container, now: datetime) -> dict[str, Any]:
    f = FilterSpec()
    ov = c.queries.overview
    trend = ov.trend(f, days=8, now=now)
    today, week_ago = trend[-1], trend[0]
    deltas = {sev: today[sev] - week_ago[sev] for sev in SEVERITY_ORDER}
    return {
        "generated_at": now.strftime("%Y-%m-%d %H:%M UTC"),
        "totals": ov.kpis(f),
        "deltas": deltas,
        "top_projects": ov.top_projects(f, 10),
        "sla_breaches": ov.sla_breach_count(f),
    }


DEFAULT_EVALUATORS: tuple[RuleEvaluator, ...] = (
    NewSeverityRule(), SlaBreachRule(), ScanFailedRule(), StaleProjectRule(), ThresholdRule(), WeeklyDigestRule(),
)  # fmt: skip


def evaluators_by_kind() -> dict[str, RuleEvaluator]:
    return {e.kind: e for e in DEFAULT_EVALUATORS}


def validate_cron(expr: str) -> None:
    CronTrigger.from_crontab(expr, timezone="UTC")


__all__ = [
    "DEFAULT_EVALUATORS",
    "AlertCandidate",
    "RuleEvaluator",
    "build_digest",
    "evaluators_by_kind",
    "utcnow",
    "validate_cron",
]
