"""The same behaviour on real PostgreSQL: migration, upserts, JSONB/ARRAY, window functions,
advisory locks, queries. Run with ``pytest -m integration``."""

from __future__ import annotations

import pytest
from sqlalchemy import func, inspect, select, text

from cxdash.db import models as m
from cxdash.db.queries import DashboardQueries
from cxdash.devtools.seed import seed_demo
from cxdash.filters import FilterSpec
from cxdash.sync.jobs import JobRunner, PgAdvisoryLock, lock_for
from tests.conftest import make_settings
from tests.integration.test_sync import Env

pytestmark = pytest.mark.integration


def test_migration_creates_trigram_index_and_extension(pg_db):
    with pg_db.engine.connect() as c:
        has_ext = c.execute(text("select 1 from pg_extension where extname='pg_trgm'")).scalar() == 1
        idx = c.execute(text("select indexdef from pg_indexes where indexname='finding_title_trgm'")).scalar()
    assert idx, "title index must exist either way"
    if has_ext:
        assert "gin" in idx and "gin_trgm_ops" in idx
    assert "finding" in inspect(pg_db.engine).get_table_names()


async def test_full_sync_cycle_is_idempotent_on_postgres(pg_db):
    env = Env(pg_db)
    env.runner = JobRunner(env.runs, lock_for(pg_db))
    assert isinstance(lock_for(pg_db), PgAdvisoryLock)
    await env.full_cycle()
    first = env.snapshot()
    await env.full_cycle()
    assert env.snapshot() == first
    with pg_db.session() as s:
        assert s.scalar(select(func.count()).select_from(m.Finding)) == 8
        assert s.scalar(select(m.Scan.engines).where(m.Scan.id == "scan-1")) == [
            "containers",
            "kics",
            "sast",
            "sca",
            "sscs",
        ]


def test_advisory_lock_blocks_second_holder(pg_db):
    lock = PgAdvisoryLock(pg_db)
    with lock.acquire("job-x") as first, lock.acquire("job-x") as second:
        assert first is True and second is False
    with lock.acquire("job-x") as again:
        assert again is True


def test_queries_on_postgres(pg_db):
    settings = make_settings()
    seed_demo(pg_db, settings, projects=10)
    q = DashboardQueries(pg_db, settings)
    f = FilterSpec()
    assert q.overview.kpis(f)["TOTAL"] > 0
    assert q.overview.trend(f, 14)
    assert q.overview.sla_breach_count(f) >= 0
    rows, total = q.findings.page(f.with_values(text="sql"), 0, 20, [{"colId": "severity", "sort": "asc"}])
    assert total >= 0 and len(rows) <= 20
    assert q.findings.age_buckets(f)
    assert q.projects.table(f)
    assert q.projects.scan_health(f)["total"] > 0
    assert q.projects.mttr(f) is not None and q.projects.burndown(f)
    assert sum(1 for _ in q.findings.stream(f, cap=100)) <= 100
