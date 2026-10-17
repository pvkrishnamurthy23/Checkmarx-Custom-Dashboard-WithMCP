"""Summaries job (spec 8.1/8.2): batch /api/scan-summary into ``scan_counter``."""

from __future__ import annotations

import logging

from cxdash.cx_client.endpoints import SUMMARY_BATCH, CheckmarxReader
from cxdash.cx_client.normalize import summary_counter_rows
from cxdash.db.repositories import ScanRepository

log = logging.getLogger(__name__)


class SummariesJob:
    name = "summaries"

    def __init__(self, api: CheckmarxReader, scans: ScanRepository) -> None:
        self._api, self._scans = api, scans

    async def run(self) -> int:
        pending = self._scans.ids_needing_summary()
        loaded = 0
        for i in range(0, len(pending), SUMMARY_BATCH):
            batch = pending[i : i + SUMMARY_BATCH]
            summaries = await self._api.scan_summaries(batch)
            returned = {str(s.get("scanId") or s.get("scanID")) for s in summaries}
            rows = [r for s in summaries for r in summary_counter_rows(s)]
            done = [sid for sid in batch if sid in returned]
            if done:
                self._scans.save_summary_counters(done, [r for r in rows if r.scan_id in set(done)])
                loaded += len(done)
            missing = len(batch) - len(done)
            if missing:
                log.warning("scan-summary returned no data for some scans", extra={"missing": missing})
        self._scans.recompute_latest()
        return loaded
