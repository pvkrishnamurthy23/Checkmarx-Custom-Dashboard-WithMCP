"""The single definition of an *open* finding (spec section 9).

``state NOT IN closed_states AND (status IS NULL OR status NOT IN closed_statuses)``
Implemented once, exposed as a Python predicate and as a SQLAlchemy fragment so
SQL and in-memory code can never drift apart.
"""

from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass
from typing import Any

from sqlalchemy import ColumnElement, and_, func, or_

from cxdash.config import Settings


@dataclass(frozen=True)
class OpenRules:
    closed_states: frozenset[str]
    closed_statuses: frozenset[str]

    @classmethod
    def from_settings(cls, settings: Settings) -> OpenRules:
        return cls(frozenset(settings.cx_closed_states), frozenset(settings.cx_closed_statuses))

    @classmethod
    def of(cls, states: Collection[str], statuses: Collection[str]) -> OpenRules:
        return cls(frozenset(s.upper() for s in states), frozenset(s.upper() for s in statuses))

    def is_open(self, state: str | None, status: str | None) -> bool:
        if (state or "").upper() in self.closed_states:
            return False
        return status is None or status.upper() not in self.closed_statuses

    def state_open_sql(self, state_col: Any) -> ColumnElement[bool]:
        """Only the state half (used for scan_counter, which has no status of the finding)."""
        return func.upper(state_col).notin_(sorted(self.closed_states)) if self.closed_states else and_(True)

    def open_sql(self, state_col: Any, status_col: Any) -> ColumnElement[bool]:
        status_ok = (
            or_(status_col.is_(None), func.upper(status_col).notin_(sorted(self.closed_statuses)))
            if self.closed_statuses
            else and_(True)
        )
        return and_(self.state_open_sql(state_col), status_ok)
