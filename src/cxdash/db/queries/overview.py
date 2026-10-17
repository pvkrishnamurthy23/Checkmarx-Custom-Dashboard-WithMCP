"""Overview-page queries. These read ``scan_counter`` joined to latest scans, never ``finding``
(except the SLA count, which is a single indexed aggregate)."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import and_, func, or_, select

from cxdash.db import models as m
from cxdash.db.queries.base import QueryContext, counter_source_clause, scan_scope, start_of, utcnow
from cxdash.domain import FAILED_SCAN_STATUSES, SEVERITY_ORDER, USABLE_SCAN_STATUSES
from cxdash.filters import FilterSpec
from cxdash.metrics.risk import percentile_ranks, risk_score


class OverviewQueries:
    def __init__(self, ctx: QueryContext) -> None:
        self._c = ctx

    # ------------------------------------------------------------------ counters
    def _counter_filters(self, f: FilterSpec, engines: tuple[str, ...]) -> list[Any]:
        c = m.ScanCounter
        conds = [c.engine.in_(engines), c.severity != "ALL", counter_source_clause()]
        if f.severities:
            conds.append(c.severity.in_([s.upper() for s in f.severities]))
        if f.states:
            conds.append(func.upper(c.state).in_([s.upper() for s in f.states]))
        else:
            conds.append(self._c.rules.state_open_sql(c.state))
        return conds

    def open_by_engine_severity(self, f: FilterSpec) -> dict[tuple[str, str], int]:
        rs = self._c.resolver.resolve(f)
        c, s = m.ScanCounter, m.Scan
        stmt = (
            select(c.engine, c.severity, func.sum(c.count))
            .join(s, s.id == c.scan_id)
            .join(m.Project, m.Project.id == s.project_id)
            .where(
                s.is_latest.is_(True),
                m.Project.active.is_(True),
                *scan_scope(rs, f),
                *self._counter_filters(f, rs.engines),
            )
            .group_by(c.engine, c.severity)
        )
        with self._c.db.session() as sess:
            return {(e, sev): int(n or 0) for e, sev, n in sess.execute(stmt)}

    def kpis(self, f: FilterSpec) -> dict[str, int]:
        by: dict[str, int] = defaultdict(int)
        for (_, sev), n in self.open_by_engine_severity(f).items():
            by[sev] += n
        out = {sev: by.get(sev, 0) for sev in SEVERITY_ORDER}
        out["TOTAL"] = sum(out.values())
        return out

    # ------------------------------------------------------------------ trend
    def trend(self, f: FilterSpec, days: int = 90, now: datetime | None = None) -> list[dict[str, Any]]:
        """Open findings by severity per day: each (project, branch) carries its latest scan forward."""
        now = now or utcnow()
        rs = self._c.resolver.resolve(f)
        start = start_of((now - timedelta(days=days - 1)).date())
        s, c = m.Scan, m.ScanCounter
        usable = func.upper(s.status).in_(USABLE_SCAN_STATUSES)
        base_where = [usable, m.Project.active.is_(True), *scan_scope(rs, f, use_dates=False)]

        def counters_for(where: list[Any]) -> Any:
            return (
                select(s.id, s.project_id, s.branch, s.created_at, c.severity, func.sum(c.count))
                .join(c, c.scan_id == s.id)
                .join(m.Project, m.Project.id == s.project_id)
                .where(
                    *where,
                    c.engine.in_(rs.engines),
                    c.severity != "ALL",
                    counter_source_clause(),
                    *([c.severity.in_([x.upper() for x in f.severities])] if f.severities else []),
                    self._c.rules.state_open_sql(c.state),
                )
                .group_by(s.id, s.project_id, s.branch, s.created_at, c.severity)
            )

        ranked = (
            select(
                s.id,
                func.row_number()
                .over(partition_by=(s.project_id, s.branch), order_by=s.created_at.desc())
                .label("rn"),
            )
            .where(usable, s.created_at < start)
            .subquery()
        )
        window_stmt = counters_for([*base_where, s.created_at >= start])
        baseline_stmt = counters_for([*base_where, s.id.in_(select(ranked.c.id).where(ranked.c.rn == 1))])
        with self._c.db.session() as sess:
            rows = list(sess.execute(window_stmt)) + list(sess.execute(baseline_stmt))

        series: dict[tuple[str, str], dict[str, tuple[datetime, dict[str, int]]]] = defaultdict(dict)
        for scan_id, pid, branch, created, sev, n in rows:
            series[(pid, branch)].setdefault(scan_id, (created, defaultdict(int)))[1][sev] += int(n or 0)
        timelines = {k: sorted(v.values(), key=lambda t: t[0]) for k, v in series.items()}

        # Difference array: each scan's counts apply from its day until the next scan of the same
        # (project, branch) replaces them. O(scans + days) instead of O(series x days x scans).
        first_day = start.date()
        diff = [dict.fromkeys(SEVERITY_ORDER, 0) for _ in range(days + 1)]

        def day_index(ts: datetime) -> int:
            return max(0, (ts.date() - first_day).days)

        for timeline in timelines.values():
            for pos, (created, counts) in enumerate(timeline):
                begin = day_index(created)
                if begin >= days:
                    continue
                end = day_index(timeline[pos + 1][0]) if pos + 1 < len(timeline) else days
                if end <= begin:
                    continue  # superseded by a later scan the same day
                for sev, n in counts.items():
                    diff[begin][sev] += n
                    diff[min(end, days)][sev] -= n

        out: list[dict[str, Any]] = []
        running = dict.fromkeys(SEVERITY_ORDER, 0)
        for i in range(days):
            for sev in SEVERITY_ORDER:
                running[sev] += diff[i][sev]
            out.append({"date": (first_day + timedelta(days=i)).isoformat(), **running})
        return out

    # ------------------------------------------------------------------ projects
    def open_by_project(self, f: FilterSpec) -> dict[str, dict[str, int]]:
        rs = self._c.resolver.resolve(f)
        c, s = m.ScanCounter, m.Scan
        stmt = (
            select(s.project_id, c.severity, func.sum(c.count))
            .join(c, c.scan_id == s.id)
            .join(m.Project, m.Project.id == s.project_id)
            .where(
                s.is_latest.is_(True),
                m.Project.active.is_(True),
                *scan_scope(rs, f),
                *self._counter_filters(f, rs.engines),
            )
            .group_by(s.project_id, c.severity)
        )
        out: dict[str, dict[str, int]] = defaultdict(dict)
        with self._c.db.session() as sess:
            for pid, sev, n in sess.execute(stmt):
                out[pid][sev] = int(n or 0)
        return out

    def top_projects(self, f: FilterSpec, n: int = 10) -> list[dict[str, Any]]:
        by_project = self.open_by_project(f)
        weights = self._c.settings.risk_weights
        scored = {pid: risk_score(sev, weights) for pid, sev in by_project.items()}
        top = sorted(scored, key=lambda p: scored[p], reverse=True)[:n]
        if not top:
            return []
        with self._c.db.session() as sess:
            names = dict(
                sess.execute(select(m.Project.id, m.Project.name).where(m.Project.id.in_(top))).all()
            )
        return [
            {
                "project_id": p,
                "project": names.get(p, p),
                "risk": round(scored[p], 1),
                **{k: by_project[p].get(k, 0) for k in SEVERITY_ORDER},
            }
            for p in top
        ]

    def risk_percentiles(self, f: FilterSpec) -> dict[str, tuple[float, float]]:
        """project_id -> (raw score, 0-100 percentile rank)."""
        by_project = self.open_by_project(f)
        weights = self._c.settings.risk_weights
        ids = list(by_project)
        raw = [risk_score(by_project[p], weights) for p in ids]
        return dict(zip(ids, zip(raw, percentile_ranks(raw), strict=True), strict=True))

    # ------------------------------------------------------------------ scans / health on the overview
    def scans_last_days(self, f: FilterSpec, days: int = 7) -> list[dict[str, Any]]:
        rs = self._c.resolver.resolve(f)
        since = utcnow() - timedelta(days=days)
        s = m.Scan
        with self._c.db.session() as sess:
            rows = sess.execute(
                select(s.created_at, s.status)
                .join(m.Project, m.Project.id == s.project_id)
                .where(s.created_at >= since, m.Project.active.is_(True), *scan_scope(rs, f, use_dates=False))
            ).all()
        per_day: dict[str, dict[str, int]] = defaultdict(lambda: {"success": 0, "failed": 0, "other": 0})
        for created, status in rows:
            key = created.date().isoformat()
            up = status.upper()
            bucket = (
                "success"
                if up in USABLE_SCAN_STATUSES
                else "failed"
                if up in FAILED_SCAN_STATUSES
                else "other"
            )
            per_day[key][bucket] += 1
        return [
            {
                "date": (since + timedelta(days=i + 1)).date().isoformat(),
                **per_day.get(
                    (since + timedelta(days=i + 1)).date().isoformat(),
                    {"success": 0, "failed": 0, "other": 0},
                ),
            }
            for i in range(days)
        ]

    # ------------------------------------------------------------------ SLA
    def sla_cutoff_case(
        self, first_found: Any, first_seen: Any, severity: Any, now: datetime | None = None
    ) -> Any:
        """SQL boolean: age in days exceeds the severity's SLA (INFO excluded). Python-computed
        cutoffs keep this portable between PostgreSQL and SQLite."""
        now = now or utcnow()
        ts = func.coalesce(first_found, first_seen)
        branches = [
            and_(severity == sev, ts < now - timedelta(days=days))
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
            if (days := self._c.settings.sla_days(sev)) is not None
        ]
        return or_(*branches)

    def sla_breach_count(self, f: FilterSpec) -> int:
        rs = self._c.resolver.resolve(f)
        fd, s, lc = m.Finding, m.Scan, m.FindingLifecycle
        stmt = (
            select(func.count())
            .select_from(fd)
            .join(s, s.id == fd.scan_id)
            .join(m.Project, m.Project.id == s.project_id)
            .outerjoin(
                lc,
                and_(
                    lc.project_id == fd.project_id,
                    lc.branch == fd.branch,
                    lc.engine == fd.engine,
                    lc.similarity_id == fd.similarity_id,
                ),
            )
            .where(
                s.is_latest.is_(True),
                m.Project.active.is_(True),
                fd.engine.in_(rs.engines),
                self._c.rules.open_sql(fd.state, fd.status),
                self.sla_cutoff_case(fd.first_found_at, lc.first_seen_at, fd.severity),
                *scan_scope(rs, f, use_dates=False),
                *([fd.severity.in_([x.upper() for x in f.severities])] if f.severities else []),
            )
        )
        with self._c.db.session() as sess:
            return int(sess.scalar(stmt) or 0)

    # ------------------------------------------------------------------ coverage
    def coverage(self, f: FilterSpec) -> list[dict[str, Any]]:
        """One row per (project, configured branch): latest scan and which engines finished."""
        rs = self._c.resolver.resolve(f)
        configured = self._c.settings.cx_engines
        engines = rs.engines or configured
        branches = rs.branches if rs.branches is not None else tuple(self._c.resolver.known_branches())
        with self._c.db.session() as sess:
            projects = sess.execute(
                select(m.Project.id, m.Project.name).where(
                    m.Project.active.is_(True),
                    *([m.Project.id.in_(rs.project_ids)] if rs.project_ids is not None else []),
                )
            ).all()
            latest = {
                (sc.project_id, sc.branch): sc
                for sc in sess.scalars(select(m.Scan).where(m.Scan.is_latest.is_(True)))
            }
            statuses: dict[str, dict[str, str]] = defaultdict(dict)
            ids = [sc.id for sc in latest.values()]
            for i in range(0, len(ids), 500):
                for sid, eng, st in sess.execute(
                    select(
                        m.ScanEngineStatus.scan_id, m.ScanEngineStatus.engine, m.ScanEngineStatus.status
                    ).where(m.ScanEngineStatus.scan_id.in_(ids[i : i + 500]))
                ):
                    statuses[sid][eng] = (st or "").lower()
        rows = []
        for pid, name in projects:
            for branch in branches:
                sc = latest.get((pid, branch))
                if sc is None:
                    rows.append(
                        {
                            "project_id": pid,
                            "project": name,
                            "branch": branch,
                            "scanned": False,
                            "engines": {},
                            "gaps": list(engines),
                        }
                    )
                    continue
                present = {e.lower() for e in (sc.engines or [])}
                result = {}
                for e in engines:
                    st = statuses[sc.id].get(e)
                    result[e] = (
                        "ok"
                        if st in ("completed", "success") or (st is None and e in present)
                        else ("failed" if st else "missing")
                    )
                rows.append(
                    {
                        "project_id": pid,
                        "project": name,
                        "branch": branch,
                        "scanned": True,
                        "scan_id": sc.id,
                        "engines": result,
                        "gaps": [e for e, v in result.items() if v != "ok"],
                    }
                )
        return rows

    def coverage_gap_count(self, f: FilterSpec) -> int:
        """Number of (project, branch) pairs that scanned but miss or failed at least one engine."""
        return sum(1 for r in self.coverage(f) if r["scanned"] and r["gaps"])
