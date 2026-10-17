"""Engine / session factory."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker

from cxdash.config import Settings


def build_engine(url: str, *, pool_size: int = 10) -> Engine:
    parsed = make_url(url)
    if parsed.get_backend_name() == "sqlite":
        engine = create_engine(url, connect_args={"check_same_thread": False, "timeout": 30})

        @event.listens_for(engine, "connect")
        def _pragmas(dbapi_conn: Any, _: Any) -> None:
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.execute("PRAGMA busy_timeout=30000")  # concurrent sync workers wait instead of failing
            cur.execute("PRAGMA journal_mode=WAL")  # readers (web) never block the writer (worker)
            cur.close()

        return engine
    return create_engine(url, pool_size=pool_size, max_overflow=10, pool_pre_ping=True)


def engine_from_settings(settings: Settings) -> Engine:
    return build_engine(settings.database_url.get_secret_value())


class Database:
    """Owns the engine and hands out short-lived sessions (one per unit of work)."""

    def __init__(self, engine: Engine) -> None:
        self.engine = engine
        self._factory = sessionmaker(engine, expire_on_commit=False)

    @property
    def dialect(self) -> str:
        return self.engine.dialect.name

    @contextmanager
    def session(self) -> Iterator[Session]:
        with self._factory() as s:
            try:
                yield s
                s.commit()
            except Exception:
                s.rollback()
                raise
