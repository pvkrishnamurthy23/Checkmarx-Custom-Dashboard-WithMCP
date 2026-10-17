"""Shared plumbing for the query modules."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from typing import Any

from sqlalchemy import ColumnElement, and_, or_

from cxdash.config import Settings
from cxdash.db import models as m
from cxdash.db.queries.scope import ResolvedScope, ScopeResolver
from cxdash.db.session import Database
from cxdash.domain import COUNTER_DERIVED, COUNTER_SUMMARY, SEVERITY_ORDER
from cxdash.filters import FilterSpec
from cxdash.metrics.open_rules import OpenRules


@dataclass(frozen=True)
class QueryContext:
    db: Database
    settings: Settings
    rules: OpenRules
    resolver: ScopeResolver

    @classmethod
    def build(cls, db: Database, settings: Settings) -> QueryContext:
        return cls(db, settings, OpenRules.from_settings(settings), ScopeResolver(db, settings))


def start_of(d: date) -> datetime:
    return datetime.combine(d, time.min, tzinfo=UTC)


def end_of(d: date) -> datetime:
    return datetime.combine(d, time.min, tzinfo=UTC) + timedelta(days=1)


def utcnow() -> datetime:
    return datetime.now(UTC)


def like_escape(value: str) -> str:
    """Escape LIKE wildcards so user text is matched literally (used with ``escape='\\\\'``)."""
    return value.replace("\\", "\\\\").replace("%", r"\%").replace("_", r"\_")


def scan_scope(
    rs: ResolvedScope, f: FilterSpec, scan: Any = m.Scan, *, use_dates: bool = True
) -> list[ColumnElement[bool]]:
    conds: list[ColumnElement[bool]] = []
    if rs.project_ids is not None:
        conds.append(scan.project_id.in_(rs.project_ids))
    if rs.branches is not None:
        conds.append(scan.branch.in_(rs.branches))
    if use_dates and f.date_from:
        conds.append(scan.created_at >= start_of(f.date_from))
    if use_dates and f.date_to:
        conds.append(scan.created_at < end_of(f.date_to))
    return conds


def counter_source_clause(counter: Any = m.ScanCounter, scan: Any = m.Scan) -> ColumnElement[bool]:
    """Pick exact DERIVED counters when findings were loaded, else the scan-summary severity totals."""
    return or_(
        counter.status == COUNTER_DERIVED,
        and_(counter.status == COUNTER_SUMMARY, scan.findings_loaded.is_(False)),
    )


def severity_rank(col: Any) -> ColumnElement[int]:
    """CRITICAL=0 ... INFO=4 for ordering."""
    from sqlalchemy import case

    return case({sev: i for i, sev in enumerate(SEVERITY_ORDER)}, value=col, else_=len(SEVERITY_ORDER))
