"""A fake ``CheckmarxReader`` backed by fixtures (DIP: sync code never needs the network)."""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from datetime import datetime
from typing import Any

from cxdash.cx_client.models import ApplicationModel, ProjectModel, ScanModel
from tests.conftest import load_fixture


class FakeReader:
    def __init__(self) -> None:
        self.project_items = load_fixture("projects.json")["projects"]
        self.application_items = load_fixture("applications.json")["applications"]
        self.scan_items = load_fixture("scans.json")["scans"]
        self.summary_items = load_fixture("scan_summary.json")["scansSummaries"]
        self.results_by_scan: dict[str, list[dict[str, Any]]] = {
            "scan-1": load_fixture("results_s1.json")["results"]
        }
        self.calls: list[str] = []

    async def projects(self) -> AsyncIterator[ProjectModel]:
        self.calls.append("projects")
        for p in self.project_items:
            yield ProjectModel.model_validate(p)

    async def applications(self) -> AsyncIterator[ApplicationModel]:
        self.calls.append("applications")
        for a in self.application_items:
            yield ApplicationModel.model_validate(a)

    async def scans(
        self,
        *,
        branch: str | None = None,
        from_date: datetime | None = None,
        statuses: Sequence[str] | None = None,
        project_id: str | None = None,
    ) -> AsyncIterator[ScanModel]:
        self.calls.append(f"scans:{branch}")
        for raw in self.scan_items:
            if branch and raw.get("branch") != branch:
                continue
            scan = ScanModel.model_validate(raw)
            if from_date and scan.createdAt < from_date:
                continue
            yield scan

    async def scan_summaries(self, scan_ids: Sequence[str]) -> list[dict[str, Any]]:
        self.calls.append("summary:" + ",".join(scan_ids))
        return [s for s in self.summary_items if s["scanId"] in scan_ids]

    async def results(self, scan_id: str) -> AsyncIterator[dict[str, Any]]:
        self.calls.append(f"results:{scan_id}")
        for r in self.results_by_scan.get(scan_id, []):
            yield r

    # --- last-scan strategy (ADR 0013)
    @staticmethod
    def _is_inc(raw: dict[str, Any]) -> bool:
        for cfg in (raw.get("metadata") or {}).get("configs", []):
            if cfg.get("type") == "sast":
                return str((cfg.get("value") or {}).get("incremental")).lower() == "true"
        return False

    async def last_scans(
        self, project_ids: Sequence[str], *, branch: str, status: str = "Completed"
    ) -> dict[str, dict[str, Any]]:
        self.calls.append(f"last_scans:{branch}:{len(project_ids)}")
        out: dict[str, dict[str, Any]] = {}
        for pid in project_ids:
            mine = [
                r
                for r in self.scan_items
                if r["projectId"] == pid and r.get("branch") == branch and r["status"] == status
            ]
            if mine:
                newest = max(mine, key=lambda r: r["createdAt"])
                out[pid] = {
                    "id": newest["id"],
                    "createdAt": newest["createdAt"],
                    "status": newest["status"],
                    "branch": branch,
                }
        return out

    async def scans_by_ids(self, scan_ids: Sequence[str]) -> AsyncIterator[ScanModel]:
        self.calls.append(f"scans_by_ids:{len(scan_ids)}")
        for raw in self.scan_items:
            if raw["id"] in scan_ids:
                yield ScanModel.model_validate(raw)

    async def recent_scans(self, project_id: str, *, branch: str, status: str, limit: int) -> list[ScanModel]:
        self.calls.append(f"recent_scans:{project_id}")
        mine = [
            r
            for r in self.scan_items
            if r["projectId"] == project_id and r.get("branch") == branch and r["status"] == status
        ]
        mine.sort(key=lambda r: r["createdAt"], reverse=True)
        return [ScanModel.model_validate(r) for r in mine[:limit]]
