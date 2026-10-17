"""Backfill job (spec 8.1): scans + summaries for the last SYNC_BACKFILL_DAYS; no findings."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from cxdash.config import Settings
from cxdash.db.repositories import SyncStateRepository
from cxdash.sync.scans import ScansJob
from cxdash.sync.summaries import SummariesJob

BACKFILL_KEY = "backfill"


class BackfillJob:
    name = "backfill"

    def __init__(
        self,
        scans_job_factory: Callable[[datetime], ScansJob],
        summaries: SummariesJob,
        state: SyncStateRepository,
        settings: Settings,
    ) -> None:
        self._make_scans = scans_job_factory
        self._summaries = summaries
        self._state = state
        self._settings = settings

    async def run(self) -> int:
        since = datetime.now(UTC) - timedelta(days=self._settings.sync_backfill_days)
        scans_job = self._make_scans(since)
        n = await scans_job.run()
        n += await self._summaries.run()
        self._state.set(BACKFILL_KEY, datetime.now(UTC), {"days": self._settings.sync_backfill_days})
        return n

    def done_before(self) -> bool:
        return self._state.get(BACKFILL_KEY) is not None
