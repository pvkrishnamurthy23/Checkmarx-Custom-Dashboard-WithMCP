"""Read-side query facade (spec ``db/queries.py``, split by concern; ADR 0004)."""

from __future__ import annotations

from cxdash.config import Settings
from cxdash.db.queries.admin import AdminQueries, OptionQueries, UserStore
from cxdash.db.queries.base import QueryContext
from cxdash.db.queries.findings import FindingQueries
from cxdash.db.queries.overview import OverviewQueries
from cxdash.db.queries.projects import ProjectQueries
from cxdash.db.session import Database


class DashboardQueries:
    """Composition root for the read side; each attribute is a small, single-purpose class."""

    def __init__(self, db: Database, settings: Settings) -> None:
        self.ctx = QueryContext.build(db, settings)
        self.overview = OverviewQueries(self.ctx)
        self.findings = FindingQueries(self.ctx)
        self.projects = ProjectQueries(self.ctx, self.overview)
        self.options = OptionQueries(self.ctx)
        self.admin = AdminQueries(self.ctx)
        self.users = UserStore(self.ctx)


__all__ = ["DashboardQueries"]
