"""Sync worker process: ``python -m cxdash.sync.scheduler`` (spec section 8).

Exactly one worker should run; Postgres advisory locks make an accidental second one harmless.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from prometheus_client import start_http_server

from cxdash.alerts.engine import AlertEngine
from cxdash.config import Settings, get_settings
from cxdash.container import Container, build_container
from cxdash.cx_client.auth import TokenManager, strategy_from_settings
from cxdash.cx_client.endpoints import CheckmarxApi, CheckmarxReader
from cxdash.cx_client.http import CheckmarxHttpClient
from cxdash.logging import configure_logging
from cxdash.sync.backfill import BackfillJob
from cxdash.sync.findings import FindingsJob, PurgeJob
from cxdash.sync.inventory import InventoryJob
from cxdash.sync.jobs import SYNC_LAG, Job, JobRunner, RunOutcome, lock_for
from cxdash.sync.scans import ScansJob
from cxdash.sync.summaries import SummariesJob

log = logging.getLogger(__name__)


class AlertsJob:
    name = "alerts"

    def __init__(self, container: Container) -> None:
        self._engine = AlertEngine(container)

    async def run(self) -> int:
        return await asyncio.to_thread(self._engine.run)


@asynccontextmanager
async def open_api(settings: Settings) -> AsyncIterator[CheckmarxApi]:
    tokens = TokenManager(
        settings.token_url, strategy_from_settings(settings), timeout=settings.cx_http_timeout_seconds
    )
    http = CheckmarxHttpClient(
        settings.base_url,
        tokens,
        max_concurrency=settings.cx_max_concurrency,
        timeout=settings.cx_http_timeout_seconds,
        max_retries=settings.cx_max_retries,
        page_size=settings.cx_page_size,
    )
    try:
        yield CheckmarxApi(http, settings.cx_results_page_size)
    finally:
        await http.aclose()


class SyncService:
    """Builds and runs jobs. Used by the scheduler, the CLI and tests (same code path)."""

    def __init__(self, container: Container, api: CheckmarxReader) -> None:
        self.c, self.api = container, api
        self.runner = JobRunner(
            container.runs, lock_for(container.db), container.settings.sync_max_api_calls_per_run
        )

    # -- job factories (dependencies injected; no job builds its own collaborators)
    def inventory(self) -> InventoryJob:
        return InventoryJob(self.api, self.c.inventory, self.c.settings)

    def scans(self, force_since: datetime | None = None) -> ScansJob:
        return ScansJob(
            self.api, self.c.scans, self.c.inventory, self.c.state, self.c.settings, force_since=force_since
        )

    def summaries(self) -> SummariesJob:
        return SummariesJob(self.api, self.c.scans)

    def findings(self, full_refresh: bool = False) -> FindingsJob:
        return FindingsJob(
            self.api, self.c.scans, self.c.findings, self.c.settings, full_refresh=full_refresh
        )

    def backfill(self) -> BackfillJob:
        return BackfillJob(
            lambda since: self.scans(force_since=since), self.summaries(), self.c.state, self.c.settings
        )

    async def _run(self, job: Job) -> RunOutcome:
        return await self.runner.run(job)

    # -- composite flows
    async def run_inventory(self) -> RunOutcome:
        return await self._run(self.inventory())

    async def run_scans_cycle(self) -> list[RunOutcome]:
        """scans -> summaries -> findings (new latest scans) -> alerts (spec 8.1)."""
        outcomes = [await self._run(self.scans())]
        if outcomes[-1].status == "failed":
            return outcomes  # no point chaining on a failed discovery step
        outcomes.append(await self._run(self.summaries()))
        outcomes.append(await self._run(self.findings()))
        outcomes.append(await self._run(AlertsJob(self.c)))
        if all(o.status != "failed" for o in outcomes[:2]):
            SYNC_LAG.set(0)
        return outcomes

    async def run_nightly(self, force_refresh: bool = False) -> list[RunOutcome]:
        refresh = force_refresh or self.c.settings.sync_nightly_findings_refresh
        out = [await self._run(self.findings(full_refresh=refresh))]
        out.append(await self._run(PurgeJob(self.c.findings, self.c.settings)))
        return out

    async def run_backfill(self) -> list[RunOutcome]:
        out = [await self.run_inventory(), await self._run(self.backfill())]
        out += await self.run_scans_cycle()
        return out

    async def process_requests(self) -> None:
        """Drain on-demand refresh requests queued by the web app (ADR 0006)."""
        pending = await asyncio.to_thread(self.c.requests.claim_pending)
        if not pending:
            return
        jobs = {job for _, job, _ in pending}
        log.info("processing on-demand sync requests", extra={"count": len(pending), "jobs": sorted(jobs)})
        if "inventory" in jobs or "full" in jobs:
            await self.run_inventory()
        if "full" in jobs:
            await self.run_nightly(force_refresh=True)
        await self.run_scans_cycle()

    async def first_start(self) -> None:
        orphans = await asyncio.to_thread(self.c.runs.mark_orphans_failed)
        if orphans:
            log.warning("closed orphaned sync runs", extra={"count": orphans})
        if not self.backfill().done_before():
            log.info("first start: running inventory + backfill")
            await self.run_backfill()


def update_lag(c: Container) -> None:
    last = c.runs.last_success("scans")
    if last:
        SYNC_LAG.set((datetime.now(UTC) - last).total_seconds())


def build_scheduler(svc: SyncService) -> AsyncIOScheduler:
    s = svc.c.settings
    sched = AsyncIOScheduler(
        timezone="UTC", job_defaults={"max_instances": 1, "coalesce": True, "misfire_grace_time": 300}
    )
    sched.add_job(svc.run_inventory, "interval", minutes=s.sync_inventory_minutes, id="inventory")
    sched.add_job(svc.run_scans_cycle, "interval", minutes=s.sync_scans_minutes, id="scans-cycle")
    sched.add_job(
        svc.run_nightly, CronTrigger.from_crontab(s.sync_findings_cron, timezone="UTC"), id="nightly"
    )
    sched.add_job(svc.process_requests, "interval", seconds=s.sync_request_poll_seconds, id="requests")
    sched.add_job(lambda: update_lag(svc.c), "interval", seconds=30, id="lag")
    return sched


async def amain() -> None:
    settings = get_settings()
    configure_logging(settings.log_level, settings.secret_values())
    container = build_container(settings)
    if settings.worker_metrics_port:
        start_http_server(settings.worker_metrics_port, addr=settings.worker_metrics_host)
    async with open_api(settings) as api:
        svc = SyncService(container, api)
        await svc.first_start()
        sched = build_scheduler(svc)
        sched.start()
        log.info("sync worker started")
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            with contextlib.suppress(NotImplementedError):  # Windows event loops cannot add signal handlers
                loop.add_signal_handler(sig, stop.set)
        try:
            await stop.wait()
        finally:
            sched.shutdown(wait=False)


def main() -> None:
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(amain())


if __name__ == "__main__":
    main()
