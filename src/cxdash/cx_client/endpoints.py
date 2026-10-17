"""Checkmarx One endpoints (spec 6.4). Every path lives in this one module so API
drift is a one-file change. Sync code depends on ``CheckmarxReader`` (DIP), so
tests and the demo seeder can substitute a fake.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from datetime import datetime
from typing import Any, Protocol

from cxdash.cx_client.http import CheckmarxHttpClient
from cxdash.cx_client.models import ApplicationModel, ProjectModel, ScanModel

SUMMARY_BATCH = 20


class CheckmarxReader(Protocol):
    def projects(self) -> AsyncIterator[ProjectModel]: ...
    def applications(self) -> AsyncIterator[ApplicationModel]: ...
    def scans(
        self,
        *,
        branch: str | None = None,
        from_date: datetime | None = None,
        statuses: Sequence[str] | None = None,
    ) -> AsyncIterator[ScanModel]: ...
    async def scan_summaries(self, scan_ids: Sequence[str]) -> list[dict[str, Any]]: ...
    def results(self, scan_id: str) -> AsyncIterator[dict[str, Any]]: ...
    async def last_scans(
        self, project_ids: Sequence[str], *, branch: str, status: str = "Completed"
    ) -> dict[str, dict[str, Any]]: ...
    def scans_by_ids(self, scan_ids: Sequence[str]) -> AsyncIterator[ScanModel]: ...
    async def recent_scans(
        self, project_id: str, *, branch: str, status: str, limit: int
    ) -> list[ScanModel]: ...


class CheckmarxApi:
    """GET-only implementation backed by ``CheckmarxHttpClient``."""

    def __init__(self, http: CheckmarxHttpClient, results_page_size: int = 500) -> None:
        self._http = http
        self._results_page_size = results_page_size

    async def projects(self) -> AsyncIterator[ProjectModel]:
        async for raw in self._http.paged("/api/projects", "projects"):
            yield ProjectModel.model_validate(raw)

    async def applications(self) -> AsyncIterator[ApplicationModel]:
        async for raw in self._http.paged("/api/applications", "applications"):
            yield ApplicationModel.model_validate(raw)

    async def scans(
        self,
        *,
        branch: str | None = None,
        from_date: datetime | None = None,
        statuses: Sequence[str] | None = None,
        project_id: str | None = None,
    ) -> AsyncIterator[ScanModel]:
        params: dict[str, Any] = {}
        if project_id:
            params["project-id"] = project_id
        if branch:
            params["branch"] = branch
        if from_date:
            params["from-date"] = from_date.strftime("%Y-%m-%dT%H:%M:%SZ")
        if statuses:
            params["statuses"] = ",".join(statuses)
        async for raw in self._http.paged("/api/scans", "scans", **params):
            yield ScanModel.model_validate(raw)

    async def scan_summaries(self, scan_ids: Sequence[str]) -> list[dict[str, Any]]:
        """One call for up to ~20 ids; callers batch with ``SUMMARY_BATCH``."""
        body = await self._http.get("/api/scan-summary", **{"scan-ids": ",".join(scan_ids)})
        return list((body or {}).get("scansSummaries") or [])

    async def results(self, scan_id: str) -> AsyncIterator[dict[str, Any]]:
        params: dict[str, Any] = {"scan-id": scan_id}
        async for raw in self._http.paged("/api/results", "results", limit=self._results_page_size, **params):
            yield raw

    async def last_scans(
        self, project_ids: Sequence[str], *, branch: str, status: str = "Completed"
    ) -> dict[str, dict[str, Any]]:
        """Newest scan per project on ``branch`` in ONE call (verified: 50 ids accepted; keyed by project id)."""
        params: dict[str, Any] = {
            "project-ids": ",".join(project_ids),
            "branch": branch,
            "scan-status": status,
            "limit": len(project_ids),
            "offset": 0,
        }
        body = await self._http.get("/api/projects/last-scan", **params)
        return {k: v for k, v in (body or {}).items() if isinstance(v, dict) and v.get("id")}

    async def scans_by_ids(self, scan_ids: Sequence[str]) -> AsyncIterator[ScanModel]:
        """Full scan records (statusDetails, metadata) for known ids; one call per ~50 ids (verified)."""
        params: dict[str, Any] = {"scan-ids": ",".join(scan_ids)}
        async for raw in self._http.paged("/api/scans", "scans", limit=max(len(scan_ids), 1), **params):
            yield ScanModel.model_validate(raw)

    async def recent_scans(self, project_id: str, *, branch: str, status: str, limit: int) -> list[ScanModel]:
        """ONE page of a project's scans on a branch (never walks the full history)."""
        params: dict[str, Any] = {
            "project-id": project_id,
            "branch": branch,
            "statuses": status,
            "limit": limit,
            "offset": 0,
            "sort": "-created_at",
        }
        body = await self._http.get("/api/scans", **params)
        return [ScanModel.model_validate(raw) for raw in (body or {}).get("scans") or []]
