"""PostgreSQL fixtures for ``-m integration``.

Uses CXDASH_TEST_PG_URL when set (CI service container); otherwise an embedded server from the
optional ``pgserver`` package; otherwise the tests are skipped.
"""

from __future__ import annotations

import os
import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from cxdash.db.session import Database, build_engine


def _base_url(tmp_path_factory) -> str | None:
    if url := os.environ.get("CXDASH_TEST_PG_URL"):
        return url
    try:
        import pgserver
    except ImportError:
        return None
    server = pgserver.get_server(tmp_path_factory.mktemp("pgdata"), cleanup_mode="stop")
    uri = server.get_uri()
    return uri.replace("postgresql://", "postgresql+psycopg://", 1)


@pytest.fixture(scope="session")
def pg_base_url(tmp_path_factory):
    url = _base_url(tmp_path_factory)
    if not url:
        pytest.skip("no PostgreSQL available (set CXDASH_TEST_PG_URL or install pgserver)")
    return url


@pytest.fixture
def pg_url(pg_base_url):
    """A fresh, empty database per test."""
    name = f"cxtest_{uuid.uuid4().hex[:10]}"
    admin = create_engine(pg_base_url, isolation_level="AUTOCOMMIT")
    with admin.connect() as c:
        c.execute(text(f'CREATE DATABASE "{name}"'))
    url = make_url(pg_base_url).set(database=name).render_as_string(hide_password=False)
    yield url
    with admin.connect() as c:
        c.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
    admin.dispose()


@pytest.fixture
def pg_db(pg_url) -> Database:
    from pathlib import Path

    from alembic import command
    from alembic.config import Config

    root = Path(__file__).resolve().parents[2]
    cfg = Config(str(root / "alembic.ini"))
    cfg.set_main_option("script_location", str(root / "migrations"))
    cfg.set_main_option("sqlalchemy.url", pg_url)
    command.upgrade(cfg, "head")
    return Database(build_engine(pg_url))
