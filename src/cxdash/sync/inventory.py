"""Inventory job: projects + applications with scope filters (spec 8.1)."""

from __future__ import annotations

import logging

from cxdash.config import Settings
from cxdash.cx_client.endpoints import CheckmarxReader
from cxdash.db.repositories import InventoryRepository
from cxdash.scope import compile_name_regex, tags_match

log = logging.getLogger(__name__)


class InventoryJob:
    name = "inventory"

    def __init__(self, api: CheckmarxReader, repo: InventoryRepository, settings: Settings) -> None:
        self._api, self._repo, self._settings = api, repo, settings

    async def run(self) -> int:
        cfg = self._settings
        wanted_apps = {a.lower() for a in cfg.cx_applications}
        apps = [a async for a in self._api.applications()]
        selected_apps = [a for a in apps if not wanted_apps or a.name.lower() in wanted_apps]
        selected_app_ids = {a.id for a in selected_apps}

        regex = compile_name_regex(cfg.cx_project_name_regex)
        projects = []
        async for p in self._api.projects():
            if regex and not regex.search(p.name):
                continue
            if cfg.cx_project_tags and not tags_match(p.tags, cfg.cx_project_tags):
                continue
            if wanted_apps and not (selected_app_ids & set(p.applicationIds)):
                continue
            projects.append(p)

        n_apps = self._repo.upsert_applications(selected_apps)
        n_projects = self._repo.upsert_projects(projects)
        inactive = self._repo.mark_inactive_except(p.id for p in projects)
        log.info(
            "inventory synced",
            extra={"projects": n_projects, "applications": n_apps, "flagged_inactive": inactive},
        )
        return n_projects + n_apps
