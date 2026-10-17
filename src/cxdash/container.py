"""Composition root: builds the object graph once. Everything else receives its dependencies."""

from __future__ import annotations

from dataclasses import dataclass

from cxdash.cache import QueryCache, build_backend
from cxdash.config import Settings, get_settings
from cxdash.db.queries import DashboardQueries
from cxdash.db.repositories import (
    FindingRepository,
    InventoryRepository,
    ScanRepository,
    SyncRequestRepository,
    SyncRunRepository,
    SyncStateRepository,
)
from cxdash.db.session import Database, engine_from_settings
from cxdash.metrics.open_rules import OpenRules


@dataclass
class Container:
    settings: Settings
    db: Database
    rules: OpenRules
    queries: DashboardQueries
    cache: QueryCache
    inventory: InventoryRepository
    scans: ScanRepository
    findings: FindingRepository
    state: SyncStateRepository
    runs: SyncRunRepository
    requests: SyncRequestRepository


def build_container(settings: Settings | None = None, db: Database | None = None) -> Container:
    settings = settings or get_settings()
    db = db or Database(engine_from_settings(settings))
    rules = OpenRules.from_settings(settings)
    queries = DashboardQueries(db, settings)

    def data_version() -> str:
        last = queries.admin.last_sync()
        return last.strftime("%Y%m%d%H%M%S") if last else "0"

    cache = QueryCache(
        build_backend(settings.redis_url.get_secret_value()), settings.sync_scans_minutes * 60, data_version
    )
    return Container(
        settings=settings,
        db=db,
        rules=rules,
        queries=queries,
        cache=cache,
        inventory=InventoryRepository(db),
        scans=ScanRepository(db),
        findings=FindingRepository(db, rules),
        state=SyncStateRepository(db),
        runs=SyncRunRepository(db),
        requests=SyncRequestRepository(db),
    )
