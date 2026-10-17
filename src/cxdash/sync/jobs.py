"""Job abstractions: the ``Job`` protocol, overlap locks and the ``JobRunner``.

Every job writes a ``sync_run`` row, is idempotent and is guarded by a lock so two
instances of the same job never overlap (spec section 8).
"""

from __future__ import annotations

import logging
import threading
import zlib
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from typing import Protocol

from prometheus_client import Counter, Gauge
from sqlalchemy import text

from cxdash.cx_client.http import track_api_calls
from cxdash.db.repositories import SyncRunRepository
from cxdash.db.session import Database

log = logging.getLogger(__name__)

JOB_RUNS = Counter("cxdash_sync_runs_total", "Sync job runs", ["job", "status"])
JOB_RECORDS = Counter("cxdash_sync_records_total", "Records processed by sync jobs", ["job"])
SYNC_LAG = Gauge("cxdash_sync_lag_seconds", "Seconds since the last successful scans cycle")


class JobError(RuntimeError):
    """A job finished with partial failures; completed work is kept."""


class Job(Protocol):
    name: str

    async def run(self) -> int:
        """Do the work; return the number of records processed."""
        ...


class JobLock(Protocol):
    def acquire(self, name: str) -> AbstractContextManager[bool]: ...


class LocalLock:
    """In-process lock (SQLite / tests)."""

    def __init__(self) -> None:
        self._held: set[str] = set()
        self._guard = threading.Lock()

    @contextmanager
    def acquire(self, name: str) -> Iterator[bool]:
        with self._guard:
            got = name not in self._held
            if got:
                self._held.add(name)
        try:
            yield got
        finally:
            if got:
                with self._guard:
                    self._held.discard(name)


class PgAdvisoryLock:
    """Session-level Postgres advisory lock held on a dedicated connection."""

    def __init__(self, db: Database) -> None:
        self._db = db

    @contextmanager
    def acquire(self, name: str) -> Iterator[bool]:
        key = zlib.crc32(f"cxdash:{name}".encode())
        with self._db.engine.connect() as conn:
            got = bool(conn.execute(text("SELECT pg_try_advisory_lock(:k)"), {"k": key}).scalar())
            try:
                yield got
            finally:
                if got:
                    conn.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": key})
                conn.commit()


def lock_for(db: Database) -> JobLock:
    return PgAdvisoryLock(db) if db.dialect == "postgresql" else LocalLock()


@dataclass
class RunOutcome:
    job: str
    status: str  # success | failed | skipped
    records: int = 0
    error: str | None = None
    api_calls: int = 0


class JobRunner:
    def __init__(self, runs: SyncRunRepository, lock: JobLock, max_api_calls: int = 0) -> None:
        self._runs = runs
        self._lock = lock
        self._max_calls = max_api_calls

    async def run(self, job: Job) -> RunOutcome:
        with self._lock.acquire(job.name) as got:
            if not got:
                log.info("job already running elsewhere, skipping", extra={"job": job.name})
                JOB_RUNS.labels(job.name, "skipped").inc()
                return RunOutcome(job.name, "skipped")
            run_id = self._runs.start(job.name)
            counter = track_api_calls(self._max_calls)
            records, error, status = 0, None, "success"
            try:
                records = await job.run()
            except Exception as exc:
                status = "failed"
                # message only: exceptions from the HTTP layer never carry credentials
                error = f"{type(exc).__name__}: {exc}"[:2000]
                log.error("job failed", extra={"job": job.name, "error": error})
            self._runs.finish(run_id, status, records, counter.calls, error)
            JOB_RUNS.labels(job.name, status).inc()
            JOB_RECORDS.labels(job.name).inc(records)
            log.info("job finished", extra={"job": job.name, "status": status, "records": records})
            return RunOutcome(job.name, status, records, error, counter.calls)
