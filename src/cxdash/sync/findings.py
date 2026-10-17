"""Findings + purge jobs (spec 8.1, 8.4)."""

from __future__ import annotations

import asyncio
import logging

from cxdash.config import Settings
from cxdash.cx_client.endpoints import CheckmarxReader
from cxdash.cx_client.models import NormalizedFinding
from cxdash.cx_client.normalize import NormalizerRegistry, default_registry
from cxdash.db import models as m
from cxdash.db.repositories import FindingRepository, ScanRepository
from cxdash.sync.jobs import JobError

log = logging.getLogger(__name__)

CHUNK = 1000
_OK_ENGINE_STATUSES = {"completed", "success", "succeeded"}


class FindingsJob:
    name = "findings"

    def __init__(
        self,
        api: CheckmarxReader,
        scans: ScanRepository,
        findings: FindingRepository,
        settings: Settings,
        registry: NormalizerRegistry | None = None,
        *,
        full_refresh: bool = False,
    ) -> None:
        self._api, self._scans, self._findings, self._settings = api, scans, findings, settings
        self._registry = registry or default_registry()
        self._full_refresh = full_refresh

    async def run(self) -> int:
        if not self._settings.sync_load_findings:
            return 0  # counters-only mode: scan-summary totals are used, no per-finding API calls
        if self._full_refresh:
            self._scans.reset_findings_loaded()
        targets = self._scans.latest_scans_needing_findings(self._settings.cx_branches)
        sem = asyncio.Semaphore(self._settings.cx_max_concurrency)

        async def one(scan: m.Scan) -> int:
            async with sem:
                return await self._load_scan(scan)

        results = await asyncio.gather(*(one(s) for s in targets), return_exceptions=True)
        errors = [r for r in results if isinstance(r, BaseException)]
        total = sum(r for r in results if isinstance(r, int))
        if errors:
            raise JobError(
                f"{len(errors)}/{len(targets)} scans failed; first: {type(errors[0]).__name__}: {errors[0]}"
            )
        return total

    async def _load_scan(self, scan: m.Scan) -> int:
        wanted = set(self._settings.cx_engines)
        await asyncio.to_thread(self._findings.delete_scan_findings, scan.id)
        buffer: list[NormalizedFinding] = []
        total = 0
        async for raw in self._api.results(scan.id):
            nf = self._registry.normalize(raw, scan.id, scan.project_id, scan.branch)
            if nf is None or nf.engine not in wanted:
                continue
            buffer.append(nf)
            if len(buffer) >= CHUNK:
                total += await asyncio.to_thread(self._findings.upsert_findings, buffer)
                buffer = []
        if buffer:
            total += await asyncio.to_thread(self._findings.upsert_findings, buffer)

        statuses = await asyncio.to_thread(self._scans.engine_statuses, scan.id)
        engines_ok = [e for e, st in statuses.items() if st.lower() in _OK_ENGINE_STATUSES and e in wanted]
        await asyncio.to_thread(self._findings.derive_counters, scan.id)
        await asyncio.to_thread(self._findings.update_lifecycle, scan, engines_ok)
        await asyncio.to_thread(self._scans.mark_findings_loaded, scan.id)
        log.info("findings loaded", extra={"scan_id": scan.id, "findings": total})
        return total


class PurgeJob:
    name = "purge"

    def __init__(self, findings: FindingRepository, settings: Settings) -> None:
        self._findings, self._settings = findings, settings

    async def run(self) -> int:
        removed = await asyncio.to_thread(
            self._findings.purge, self._settings.findings_keep_scans_per_branch, self._settings.cx_branches
        )
        await asyncio.to_thread(self._findings.purge_old_run_logs)
        if not self._settings.sync_keep_scan_history:
            removed["scans"] += await asyncio.to_thread(self._findings.purge_non_latest_scans)
        log.info("purge finished", extra=removed)
        return removed["findings"] + removed["scans"]
