"""Scans job (spec 8.1) with two interchangeable scan-selection strategies (ADR 0013).

* ``LastScanSelection`` (default): only the newest full scan per project and branch, found with one
  ``/api/projects/last-scan`` call per ``SYNC_LAST_SCAN_BATCH`` projects. Cheapest in API calls.
* ``HighWaterMarkSelection``: every scan since a high-water mark (the original spec 8.1 behaviour); needed for
  glob / all-branch scope.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Protocol

from cxdash.config import Settings
from cxdash.cx_client.endpoints import CheckmarxReader
from cxdash.cx_client.models import ScanModel
from cxdash.db.repositories import InventoryRepository, ScanRepository, SyncStateRepository
from cxdash.scope import branch_matches, has_glob

log = logging.getLogger(__name__)

OVERLAP = timedelta(minutes=5)
JOB_KEY = "scans"


def _chunks(items: Sequence[str], size: int) -> list[Sequence[str]]:
    return [items[i : i + size] for i in range(0, len(items), size)]


class ScanSelection(Protocol):
    async def collect(self) -> list[ScanModel]:
        """Scans (with statusDetails/metadata) that should be stored this cycle."""
        ...

    def after_persist(self) -> None:
        """Bookkeeping that must only happen once the scans are safely stored."""
        ...


class HighWaterMarkSelection:
    def __init__(
        self,
        api: CheckmarxReader,
        scans: ScanRepository,
        inventory: InventoryRepository,
        state: SyncStateRepository,
        settings: Settings,
        force_since: datetime | None = None,
    ) -> None:
        self._api, self._scans, self._inventory, self._state = api, scans, inventory, state
        self._settings, self._force_since = settings, force_since
        self._fetched_newest: datetime | None = None
        self._since_used = datetime.now(UTC)

    def _since(self) -> datetime:
        """High-water mark, or a backfill window on first run / when CX_BRANCHES changed (spec 8.3)."""
        if self._force_since:
            return self._force_since
        saved = self._state.get(JOB_KEY)
        branches_now = sorted(self._settings.cx_branches)
        if saved and saved.high_water_mark and (saved.details or {}).get("branches") == branches_now:
            return saved.high_water_mark
        return datetime.now(UTC) - timedelta(days=self._settings.sync_backfill_days)

    async def collect(self) -> list[ScanModel]:
        patterns = self._settings.cx_branches
        since = self._since()
        self._since_used = since
        sources: list[str | None] = [None] if (not patterns or has_glob(patterns)) else list(patterns)
        found: dict[str, ScanModel] = {}
        for branch in sources:
            async for scan in self._api.scans(branch=branch, from_date=since - OVERLAP):
                found[scan.id] = scan
        self._fetched_newest = max((s.createdAt for s in found.values()), default=None)
        known = self._inventory.active_project_ids()
        return [s for s in found.values() if s.projectId in known and branch_matches(s.branch, patterns)]

    def after_persist(self) -> None:
        newest = self._fetched_newest or self._since_used
        unfinished = self._scans.oldest_unfinished_created_at()
        mark = min(newest, unfinished) if unfinished else newest
        self._state.set(JOB_KEY, mark - OVERLAP, {"branches": sorted(self._settings.cx_branches)})


class LastScanSelection:
    """Newest full scan per (project, branch); remembers incremental scans it has already looked past."""

    def __init__(
        self,
        api: CheckmarxReader,
        scans: ScanRepository,
        inventory: InventoryRepository,
        state: SyncStateRepository,
        settings: Settings,
    ) -> None:
        self._api, self._scans, self._inventory, self._state = api, scans, inventory, state
        self._s = settings
        saved = self._state.get(JOB_KEY)
        remembered = ((saved.details if saved else None) or {}).get("skipped") or {}
        # remembered look-pasts only apply while the option is on (toggling it off must re-evaluate those scans)
        self._skipped: dict[str, str | None] = dict(remembered) if settings.sync_full_scans_only else {}
        self._current: set[str] = set()

    async def collect(self) -> list[ScanModel]:
        s = self._s
        project_ids = sorted(self._inventory.active_project_ids())
        wanted: dict[str, tuple[str, str]] = {}  # last scan id -> (project id, branch)
        for branch in s.cx_branches:
            for chunk in _chunks(project_ids, s.sync_last_scan_batch):
                latest = await self._api.last_scans(chunk, branch=branch, status=s.sync_last_scan_status)
                for pid, entry in latest.items():
                    wanted[entry["id"]] = (pid, branch)
        self._current = set(wanted)

        known = self._scans.existing_ids(wanted)
        to_fetch = [sid for sid in wanted if sid not in known and sid not in self._skipped]
        details: list[ScanModel] = []
        for chunk in _chunks(to_fetch, s.sync_last_scan_batch):
            async for scan in self._api.scans_by_ids(chunk):
                details.append(scan)

        keep: list[ScanModel] = []
        for scan in details:
            pid, branch = wanted.get(scan.id, (scan.projectId, scan.branch))
            if s.sync_full_scans_only and scan.is_incremental:
                chosen = await self._previous_full_scan(pid, branch)
                self._skipped[scan.id] = chosen.id if chosen else None
                if chosen and chosen.id not in known:
                    keep.append(chosen)
                continue
            keep.append(scan)
        log.info(
            "last-scan selection",
            extra={
                "projects": len(project_ids),
                "latest": len(wanted),
                "new": len(to_fetch),
                "stored": len(keep),
            },
        )
        return keep

    async def _previous_full_scan(self, project_id: str, branch: str) -> ScanModel | None:
        s = self._s
        page = await self._api.recent_scans(
            project_id, branch=branch, status=s.sync_last_scan_status, limit=s.sync_full_scan_lookback
        )
        for scan in sorted(page, key=lambda x: x.createdAt, reverse=True):
            if not scan.is_incremental:
                return scan
        log.warning("no full scan within lookback", extra={"project": project_id, "branch": branch})
        return None

    def after_persist(self) -> None:
        pruned = {k: v for k, v in self._skipped.items() if k in self._current}
        self._state.set(
            JOB_KEY, datetime.now(UTC), {"branches": sorted(self._s.cx_branches), "skipped": pruned}
        )


class ScansJob:
    name = "scans"

    def __init__(
        self,
        api: CheckmarxReader,
        scans: ScanRepository,
        inventory: InventoryRepository,
        state: SyncStateRepository,
        settings: Settings,
        *,
        force_since: datetime | None = None,
    ) -> None:
        self._scans = scans
        self._settings = settings
        self._selection: ScanSelection
        if settings.sync_scan_selection == "last_scan" and force_since is None:
            self._selection = LastScanSelection(api, scans, inventory, state, settings)
        else:
            # forced (backfill with an explicit window) or "all": walk scans since a point in time
            self._selection = HighWaterMarkSelection(api, scans, inventory, state, settings, force_since)

    async def run(self) -> int:
        collected = await self._selection.collect()
        n = self._scans.upsert_scans(collected)
        self._scans.recompute_latest()
        self._selection.after_persist()
        log.info("scans synced", extra={"stored": n})
        return n
