"""Finding-level queries: grid paging, detail, breakdowns, streaming export."""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from datetime import timedelta
from typing import Any

from sqlalchemy import ColumnElement, Integer, and_, case, cast, func, or_, select

from cxdash.db import models as m
from cxdash.db.queries.base import (
    QueryContext,
    end_of,
    like_escape,
    scan_scope,
    severity_rank,
    start_of,
    utcnow,
)
from cxdash.filters import FilterSpec
from cxdash.metrics.aging import BUCKET_LABELS, age_days
from cxdash.metrics.sla import days_over_sla

F = m.Finding

# Columns the grid may sort or filter on (whitelist: user input never reaches SQL as an identifier).
SORTABLE: dict[str, Any] = {
    "severity": None,  # custom rank, handled below
    "title": F.title,
    "engine": F.engine,
    "state": F.state,
    "status": F.status,
    "project_id": F.project_id,
    "branch": F.branch,
    "file_path": F.file_path,
    "line": F.line,
    "cve": F.cve,
    "cwe": F.cwe,
    "cvss": F.cvss,
    "package": F.package,
    "image": F.image,
    "first_found_at": F.first_found_at,
}
TEXT_FILTERABLE = {
    "title",
    "file_path",
    "cve",
    "cwe",
    "package",
    "image",
    "branch",
    "engine",
    "state",
    "status",
    "category",
    "language",
}

GRID_COLUMNS = [
    "scan_id", "finding_id", "project_id", "project", "branch", "engine", "severity", "state", "status", "title", "cwe", "cve",
    "cvss", "package", "package_version", "fixed_version", "image", "file_path", "line", "language", "category", "first_found_at",
]  # fmt: skip

BREAKDOWN_COLUMNS: dict[str, Any] = {
    "title": F.title, "cwe": F.cwe, "cve": F.cve, "language": F.language, "category": F.category, "package": F.package,
    "image": F.image, "file_path": F.file_path, "state": F.state, "status": F.status, "severity": F.severity,
    "project_id": F.project_id, "engine": F.engine, "fixed_version": F.fixed_version,
}  # fmt: skip


class FindingQueries:
    def __init__(self, ctx: QueryContext) -> None:
        self._c = ctx

    # ------------------------------------------------------------------ conditions
    def _where(self, f: FilterSpec, engines: Sequence[str] | None = None) -> list[ColumnElement[bool]]:
        rs = self._c.resolver.resolve(f)
        allowed = tuple(e for e in rs.engines if engines is None or e in engines)
        conds: list[ColumnElement[bool]] = [
            m.Scan.is_latest.is_(True),
            m.Project.active.is_(True),
            F.engine.in_(allowed),
        ]
        conds += scan_scope(rs, f, use_dates=False)
        if f.severities:
            conds.append(F.severity.in_([s.upper() for s in f.severities]))
        if f.states:
            conds.append(func.upper(F.state).in_([s.upper() for s in f.states]))
        if f.statuses:
            conds.append(func.upper(F.status).in_([s.upper() for s in f.statuses]))
        if not f.states and not f.statuses:
            conds.append(self._c.rules.open_sql(F.state, F.status))
        if f.date_from:
            conds.append(F.first_found_at >= start_of(f.date_from))
        if f.date_to:
            conds.append(F.first_found_at < end_of(f.date_to))
        for field, values in f.facet_values().items():
            conds.append(getattr(F, field).in_(values))
        if f.text.strip():
            pattern = f"%{like_escape(f.text.strip().lower())}%"
            conds.append(
                or_(
                    *(
                        func.lower(col).like(pattern, escape="\\")
                        for col in (F.title, F.file_path, F.cve, F.package, F.image, F.cwe)
                    )
                )
            )
        return conds

    def _from(self, stmt: Any) -> Any:
        return (
            stmt.select_from(F)
            .join(m.Scan, m.Scan.id == F.scan_id)
            .join(m.Project, m.Project.id == F.project_id)
        )

    # ------------------------------------------------------------------ grid
    def _grid_filters(self, filter_model: dict[str, Any] | None) -> list[ColumnElement[bool]]:
        conds: list[ColumnElement[bool]] = []
        for col, spec in (filter_model or {}).items():
            if col not in TEXT_FILTERABLE or not isinstance(spec, dict):
                continue
            value = str(spec.get("filter", "")).strip().lower()
            if not value:
                continue
            attr = getattr(F, col)
            esc = like_escape(value)
            kind = spec.get("type", "contains")
            pattern = {"startsWith": f"{esc}%", "endsWith": f"%{esc}"}.get(kind, f"%{esc}%")
            if kind == "equals":
                conds.append(func.lower(attr) == value)
            elif kind == "notContains":
                conds.append(or_(attr.is_(None), ~func.lower(attr).like(pattern, escape="\\")))
            else:
                conds.append(func.lower(attr).like(pattern, escape="\\"))
        return conds

    def _order(self, sort_model: list[dict[str, str]] | None) -> list[Any]:
        order: list[Any] = []
        for item in sort_model or []:
            col, direction = item.get("colId"), item.get("sort", "asc")
            if col not in SORTABLE:
                continue
            expr = severity_rank(F.severity) if col == "severity" else SORTABLE[col]
            order.append(expr.desc() if direction == "desc" else expr.asc())
        order += [
            severity_rank(F.severity).asc(),
            F.first_found_at.asc(),
            F.scan_id,
            F.finding_id,
        ]  # stable tiebreaker
        return order

    def page(
        self,
        f: FilterSpec,
        start: int,
        end: int,
        sort_model: list[dict[str, str]] | None = None,
        filter_model: dict[str, Any] | None = None,
        engines: Sequence[str] | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        conds = [*self._where(f, engines), *self._grid_filters(filter_model)]
        limit = max(0, min(end - start, 1000))
        cols = [getattr(F, c) for c in GRID_COLUMNS if c not in ("project",)]
        stmt = (
            self._from(select(*cols, m.Project.name.label("project")))
            .where(*conds)
            .order_by(*self._order(sort_model))
            .offset(max(0, start))
            .limit(limit)
        )
        count_stmt = self._from(select(func.count())).where(*conds)
        with self._c.db.session() as s:
            rows = [dict(r._mapping) for r in s.execute(stmt)]
            total = int(s.scalar(count_stmt) or 0)
        return rows, total

    def stream(
        self, f: FilterSpec, engines: Sequence[str] | None = None, cap: int | None = None, batch: int = 2000
    ) -> Iterator[dict[str, Any]]:
        """Server-side cursor for CSV/XLSX export; bounded by ``cap`` (EXPORT_ROW_CAP)."""
        cap = cap or self._c.settings.export_row_cap
        cols = [getattr(F, c) for c in GRID_COLUMNS if c != "project"]
        stmt = (
            self._from(select(*cols, m.Project.name.label("project")))
            .where(*self._where(f, engines))
            .order_by(*self._order(None))
            .limit(cap)
            .execution_options(yield_per=batch)
        )
        with self._c.db.session() as s:
            for row in s.execute(stmt):
                yield dict(row._mapping)

    def count(self, f: FilterSpec, engines: Sequence[str] | None = None) -> int:
        with self._c.db.session() as s:
            return int(s.scalar(self._from(select(func.count())).where(*self._where(f, engines))) or 0)

    # ------------------------------------------------------------------ detail
    def detail(self, scan_id: str, finding_id: str) -> dict[str, Any] | None:
        lc = m.FindingLifecycle
        stmt = (
            select(F, m.Project.name, lc.first_seen_at, lc.resolved_at)
            .join(m.Project, m.Project.id == F.project_id)
            .outerjoin(
                lc,
                and_(
                    lc.project_id == F.project_id,
                    lc.branch == F.branch,
                    lc.engine == F.engine,
                    lc.similarity_id == F.similarity_id,
                ),
            )
            .where(F.scan_id == scan_id, F.finding_id == finding_id)
        )
        with self._c.db.session() as s:
            row = s.execute(stmt).first()
        if row is None:
            return None
        finding, project_name, first_seen, resolved = row
        data = {c: getattr(finding, c) for c in GRID_COLUMNS if c not in ("project",)}
        data.update(
            project=project_name,
            description=finding.description,
            found_at=finding.found_at,
            raw_json=finding.raw_json,
            first_seen_at=first_seen,
            resolved_at=resolved,
            similarity_id=finding.similarity_id,
        )
        days = age_days(finding.first_found_at, first_seen)
        data["age_days"] = days
        data["sla_days"] = self._c.settings.sla_days(finding.severity)
        data["sla_over_days"] = days_over_sla(finding.severity, days, self._c.settings)
        data["is_open"] = self._c.rules.is_open(finding.state, finding.status)
        return data

    # ------------------------------------------------------------------ breakdowns
    def group_counts(
        self,
        f: FilterSpec,
        column: str,
        engines: Sequence[str],
        *,
        limit: int = 15,
        extra: Sequence[ColumnElement[bool]] = (),
    ) -> list[tuple[str, int]]:
        if column not in BREAKDOWN_COLUMNS:
            raise ValueError(f"column {column!r} is not groupable")
        col = BREAKDOWN_COLUMNS[column]
        n = func.count().label("n")
        stmt = (
            self._from(select(col, n))
            .where(*self._where(f, engines), col.is_not(None), *extra)
            .group_by(col)
            .order_by(n.desc(), col)
            .limit(limit)
        )
        with self._c.db.session() as s:
            return [(str(k), int(v)) for k, v in s.execute(stmt)]

    def severity_state(self, f: FilterSpec, engines: Sequence[str]) -> list[tuple[str, str, int]]:
        n = func.count()
        stmt = (
            self._from(select(F.severity, F.state, n))
            .where(*self._where(f, engines))
            .group_by(F.severity, F.state)
        )
        with self._c.db.session() as s:
            return [(a, b, int(c)) for a, b, c in s.execute(stmt)]

    def status_counts(self, f: FilterSpec, engines: Sequence[str]) -> dict[str, int]:
        stmt = (
            self._from(select(func.coalesce(F.status, "UNKNOWN"), func.count()))
            .where(*self._where(f, engines))
            .group_by(F.status)
        )
        with self._c.db.session() as s:
            return {k: int(v) for k, v in s.execute(stmt)}

    def fixed_in_window(self, f: FilterSpec, days: int = 30) -> int:
        """'Fixed' = lifecycle rows resolved in the window (spec section 9)."""
        rs = self._c.resolver.resolve(f)
        since = utcnow() - timedelta(days=days)
        lc = m.FindingLifecycle
        conds: list[Any] = [lc.resolved_at >= since, lc.engine.in_(rs.engines)]
        if rs.project_ids is not None:
            conds.append(lc.project_id.in_(rs.project_ids))
        if rs.branches is not None:
            conds.append(lc.branch.in_(rs.branches))
        with self._c.db.session() as s:
            return int(s.scalar(select(func.count()).select_from(lc).where(*conds)) or 0)

    def cvss_histogram(self, f: FilterSpec, engines: Sequence[str]) -> list[tuple[int, int]]:
        bucket = cast(F.cvss, Integer).label("b")
        stmt = (
            self._from(select(bucket, func.count()))
            .where(*self._where(f, engines), F.cvss.is_not(None))
            .group_by(bucket)
            .order_by(bucket)
        )
        with self._c.db.session() as s:
            return [(int(b), int(n)) for b, n in s.execute(stmt)]

    def fixable_split(self, f: FilterSpec, engines: Sequence[str]) -> dict[str, int]:
        fixable = case((F.fixed_version.is_not(None), "Fix available"), else_="No fix known")
        stmt = self._from(select(fixable, func.count())).where(*self._where(f, engines)).group_by(fixable)
        with self._c.db.session() as s:
            return {k: int(v) for k, v in s.execute(stmt)}

    def fix_available_pct(self, f: FilterSpec, engines: Sequence[str]) -> float | None:
        split = self.fixable_split(f, engines)
        total = sum(split.values())
        return round(100 * split.get("Fix available", 0) / total, 1) if total else None

    def distinct_projects(self, f: FilterSpec, engines: Sequence[str]) -> int:
        stmt = self._from(select(func.count(func.distinct(F.project_id)))).where(*self._where(f, engines))
        with self._c.db.session() as s:
            return int(s.scalar(stmt) or 0)

    def image_ranking(self, f: FilterSpec, limit: int = 15) -> list[dict[str, Any]]:
        crit_high = func.sum(case((F.severity.in_(["CRITICAL", "HIGH"]), 1), else_=0)).label("crit_high")
        total = func.count().label("total")
        stmt = (
            self._from(select(F.image, crit_high, total))
            .where(*self._where(f, ["containers"]), F.image.is_not(None))
            .group_by(F.image)
            .order_by(crit_high.desc(), total.desc())
            .limit(limit)
        )
        with self._c.db.session() as s:
            return [
                {"image": i, "critical_high": int(a or 0), "total": int(b)} for i, a, b in s.execute(stmt)
            ]

    def age_buckets(self, f: FilterSpec, engines: Sequence[str] | None = None) -> dict[str, int]:
        """Open findings by age bucket (spec section 9) using portable Python-computed cutoffs."""
        now = utcnow()
        lc = m.FindingLifecycle
        ts = func.coalesce(F.first_found_at, lc.first_seen_at)
        bounds = [8, 31, 91, 181]  # exclusive upper bound in days for each of the first four buckets
        whens = [
            (ts > now - timedelta(days=b), label) for b, label in zip(bounds, BUCKET_LABELS, strict=False)
        ]
        bucket = case(*whens, else_=BUCKET_LABELS[-1])
        stmt = (
            self._from(select(bucket, func.count()))
            .outerjoin(
                lc,
                and_(
                    lc.project_id == F.project_id,
                    lc.branch == F.branch,
                    lc.engine == F.engine,
                    lc.similarity_id == F.similarity_id,
                ),
            )
            .where(*self._where(f, engines), ts.is_not(None))
            .group_by(bucket)
        )
        with self._c.db.session() as s:
            found = {k: int(v) for k, v in s.execute(stmt)}
        return {label: found.get(label, 0) for label in BUCKET_LABELS}
