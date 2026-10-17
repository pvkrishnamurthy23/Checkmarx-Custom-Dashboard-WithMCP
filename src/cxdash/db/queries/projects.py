"""Projects inventory, scan health and lifecycle analytics queries."""

from __future__ import annotations

import statistics
from collections import defaultdict
from datetime import timedelta
from typing import Any

from sqlalchemy import func, select

from cxdash.db import models as m
from cxdash.db.queries.base import QueryContext, utcnow
from cxdash.db.queries.overview import OverviewQueries
from cxdash.domain import FAILED_SCAN_STATUSES, USABLE_SCAN_STATUSES
from cxdash.filters import FilterSpec
from cxdash.metrics.mttr import mttr_days_by_severity


class ProjectQueries:
    def __init__(self, ctx: QueryContext, overview: OverviewQueries) -> None:
        self._c, self._ov = ctx, overview

    def table(self, f: FilterSpec) -> list[dict[str, Any]]:
        """Per-project inventory row (spec 10.2 Projects)."""
        rs = self._c.resolver.resolve(f)
        c, s = m.ScanCounter, m.Scan
        from cxdash.db.queries.base import counter_source_clause, scan_scope

        stmt = (
            select(s.project_id, c.engine, func.sum(c.count))
            .join(c, c.scan_id == s.id)
            .join(m.Project, m.Project.id == s.project_id)
            .where(
                s.is_latest.is_(True),
                m.Project.active.is_(True),
                c.engine.in_(rs.engines),
                c.severity != "ALL",
                counter_source_clause(),
                self._c.rules.state_open_sql(c.state),
                *scan_scope(rs, f),
                *([c.severity.in_([x.upper() for x in f.severities])] if f.severities else []),
            )
            .group_by(s.project_id, c.engine)
        )
        per_engine: dict[str, dict[str, int]] = defaultdict(dict)
        with self._c.db.session() as sess:
            for pid, eng, n in sess.execute(stmt):
                per_engine[pid][eng] = int(n or 0)
            apps = {a.id: a.name for a in sess.scalars(select(m.Application))}
            projects = sess.execute(
                select(m.Project.id, m.Project.name, m.Project.application_ids).where(
                    m.Project.active.is_(True),
                    *([m.Project.id.in_(rs.project_ids)] if rs.project_ids is not None else []),
                )
            ).all()
            last_scan = dict(
                sess.execute(
                    select(s.project_id, func.max(s.created_at))
                    .where(
                        func.upper(s.status).in_(USABLE_SCAN_STATUSES),
                        *([s.branch.in_(rs.branches)] if rs.branches is not None else []),
                    )
                    .group_by(s.project_id)
                ).all()
            )
        risk = self._ov.risk_percentiles(f)
        coverage: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in self._ov.coverage(f):
            coverage[row["project_id"]].append(row)
        now = utcnow()
        out = []
        for pid, name, app_ids in projects:
            scanned = [r for r in coverage[pid] if r["scanned"]]
            engines_ok = {
                e: all(r["engines"].get(e) == "ok" for r in scanned) if scanned else False for e in rs.engines
            }
            last = last_scan.get(pid)
            out.append(
                {
                    "project_id": pid,
                    "project": name,
                    "application": ", ".join(sorted(apps[a] for a in (app_ids or []) if a in apps)),
                    "last_scan": last,
                    "age_days": (now - last).days if last else None,
                    "open_by_engine": per_engine.get(pid, {}),
                    "open_total": sum(per_engine.get(pid, {}).values()),
                    "risk_raw": risk.get(pid, (0.0, 0.0))[0],
                    "risk": risk.get(pid, (0.0, 0.0))[1],
                    "coverage": engines_ok,
                    "no_scan_branches": [r["branch"] for r in coverage[pid] if not r["scanned"]],
                }
            )
        out.sort(key=lambda r: (-r["risk"], -r["open_total"], r["project"].lower()))
        return out

    def project_trend(self, project_id: str, f: FilterSpec, days: int = 90) -> list[dict[str, Any]]:
        return self._ov.trend(f.with_values(projects=(project_id,)), days)

    # ------------------------------------------------------------------ scan health
    def scan_health(self, f: FilterSpec, days: int = 30) -> dict[str, Any]:
        rs = self._c.resolver.resolve(f)
        since = utcnow() - timedelta(days=days)
        s = m.Scan
        from cxdash.db.queries.base import scan_scope

        where = [m.Project.active.is_(True), *scan_scope(rs, f, use_dates=False)]
        with self._c.db.session() as sess:
            scans = sess.execute(
                select(s.id, s.project_id, s.status, s.duration_seconds, s.created_at)
                .join(m.Project, m.Project.id == s.project_id)
                .where(s.created_at >= since, *where)
            ).all()
            ids = [r[0] for r in scans]
            engine_fail: dict[str, int] = defaultdict(int)
            for i in range(0, len(ids), 500):
                for eng, st in sess.execute(
                    select(m.ScanEngineStatus.engine, m.ScanEngineStatus.status).where(
                        m.ScanEngineStatus.scan_id.in_(ids[i : i + 500])
                    )
                ):
                    if (st or "").lower() in ("failed", "canceled", "cancelled", "skipped"):
                        engine_fail[eng] += 1
            last_ok = dict(
                sess.execute(
                    select(s.project_id, func.max(s.created_at))
                    .where(
                        func.upper(s.status).in_(USABLE_SCAN_STATUSES),
                        *([s.branch.in_(rs.branches)] if rs.branches is not None else []),
                    )
                    .group_by(s.project_id)
                ).all()
            )
            projects = sess.execute(
                select(m.Project.id, m.Project.name).where(
                    m.Project.active.is_(True),
                    *([m.Project.id.in_(rs.project_ids)] if rs.project_ids is not None else []),
                )
            ).all()
        total = len(scans)
        failed = sum(1 for r in scans if r[2].upper() in FAILED_SCAN_STATUSES)
        ok = sum(1 for r in scans if r[2].upper() in USABLE_SCAN_STATUSES)
        durations = sorted(r[3] for r in scans if r[3] is not None)

        def pct(p: float) -> float | None:
            if not durations:
                return None
            idx = min(len(durations) - 1, round(p * (len(durations) - 1)))
            return float(durations[idx])

        stale_cutoff = utcnow() - timedelta(days=self._c.settings.stale_project_days)
        stale = [
            {"project_id": pid, "project": name, "last_scan": last_ok.get(pid)}
            for pid, name in projects
            if last_ok.get(pid) is None or last_ok[pid] < stale_cutoff
        ]
        missing = [r for r in self._ov.coverage(f) if r["scanned"] and r["gaps"]]
        return {
            "window_days": days,
            "total": total,
            "success": ok,
            "failed": failed,
            "success_rate": round(100 * ok / total, 1) if total else None,
            "duration_p50": pct(0.5),
            "duration_p90": pct(0.9),
            "duration_p95": pct(0.95),
            "duration_mean": round(statistics.fmean(durations), 1) if durations else None,
            "engine_failures": dict(engine_fail),
            "stale_projects": stale,
            "missing_engine": missing,
        }

    # ------------------------------------------------------------------ lifecycle analytics
    def _lifecycle_where(self, f: FilterSpec) -> list[Any]:
        rs = self._c.resolver.resolve(f)
        lc = m.FindingLifecycle
        conds: list[Any] = [lc.engine.in_(rs.engines)]
        if rs.project_ids is not None:
            conds.append(lc.project_id.in_(rs.project_ids))
        if rs.branches is not None:
            conds.append(lc.branch.in_(rs.branches))
        if f.severities:
            conds.append(lc.last_severity.in_([x.upper() for x in f.severities]))
        return conds

    def mttr(self, f: FilterSpec, days: int = 90) -> dict[str, float]:
        lc = m.FindingLifecycle
        since = utcnow() - timedelta(days=days)
        with self._c.db.session() as sess:
            rows = sess.execute(
                select(lc.last_severity, lc.first_seen_at, lc.resolved_at).where(
                    lc.resolved_at.is_not(None), lc.resolved_at >= since, *self._lifecycle_where(f)
                )
            ).all()
        return mttr_days_by_severity((sev or "INFO", a, b) for sev, a, b in rows if b is not None)

    def burndown(self, f: FilterSpec, weeks: int = 12) -> list[dict[str, Any]]:
        """Weekly opened (new lifecycle rows) vs closed (resolved lifecycle rows)."""
        lc = m.FindingLifecycle
        now = utcnow()
        monday = (now - timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
        start = monday - timedelta(weeks=weeks - 1)
        where = self._lifecycle_where(f)
        with self._c.db.session() as sess:
            opened = sess.scalars(select(lc.first_seen_at).where(lc.first_seen_at >= start, *where)).all()
            closed = sess.scalars(select(lc.resolved_at).where(lc.resolved_at >= start, *where)).all()
        buckets = {
            (start + timedelta(weeks=i)).date().isoformat(): {"opened": 0, "closed": 0} for i in range(weeks)
        }

        def key(ts: Any) -> str:
            d = ts - timedelta(days=ts.weekday())
            return str(d.date().isoformat())

        for ts in opened:
            buckets.get(key(ts), {"opened": 0})["opened"] += 1
        for ts in (t for t in closed if t is not None):
            buckets.get(key(ts), {"closed": 0})["closed"] += 1
        return [{"week": w, **v} for w, v in buckets.items()]
