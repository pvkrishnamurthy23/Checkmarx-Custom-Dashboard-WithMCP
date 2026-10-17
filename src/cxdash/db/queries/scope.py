"""Turns a ``FilterSpec`` into concrete SQL constraints (project ids, branches, engines).

Single place that knows how application / tag / branch-glob filters resolve, so every
query module applies scope identically (DRY) and row-level scoping cannot be bypassed.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from sqlalchemy import select

from cxdash.config import Settings
from cxdash.db import models as m
from cxdash.db.session import Database
from cxdash.filters import FilterSpec
from cxdash.scope import branch_matches, tags_match


@dataclass(frozen=True)
class ResolvedScope:
    project_ids: tuple[str, ...] | None  # None = no project restriction
    branches: tuple[str, ...] | None  # None = no branch restriction
    engines: tuple[str, ...]


class ScopeResolver:
    _BRANCH_TTL = 60.0

    def __init__(self, db: Database, settings: Settings) -> None:
        self._db, self._settings = db, settings
        self._branch_cache: tuple[float, list[str]] = (0.0, [])

    def known_branches(self) -> list[str]:
        ts, cached = self._branch_cache
        if time.monotonic() - ts < self._BRANCH_TTL and cached:
            return cached
        with self._db.session() as s:
            branches = sorted(s.scalars(select(m.Scan.branch).distinct()))
        self._branch_cache = (time.monotonic(), branches)
        return branches

    def effective_branches(self, f: FilterSpec) -> tuple[str, ...] | None:
        configured = self._settings.cx_branches
        if not configured and not f.branches:
            return None
        pool = [b for b in self.known_branches() if branch_matches(b, configured)]
        if f.branches:
            pool = [b for b in pool if b in f.branches]
        return tuple(pool)

    def engines(self, f: FilterSpec) -> tuple[str, ...]:
        allowed = self._settings.cx_engines
        return tuple(e for e in allowed if not f.engines or e in f.engines)

    def project_ids(self, f: FilterSpec) -> tuple[str, ...] | None:
        needs_projects = bool(f.applications or f.projects or f.tags or f.scope_applications is not None)
        if not needs_projects:
            return None
        with self._db.session() as s:
            apps = {a.name: a.id for a in s.scalars(select(m.Application))}
            projects = s.execute(
                select(m.Project.id, m.Project.tags, m.Project.application_ids).where(
                    m.Project.active.is_(True)
                )
            ).all()
        wanted_ids = {apps[n] for n in f.applications if n in apps} if f.applications else None
        scope_ids = (
            {apps[n] for n in f.scope_applications if n in apps} if f.scope_applications is not None else None
        )
        result: list[str] = []
        for pid, tags, app_ids in projects:
            app_set = set(app_ids or [])
            if wanted_ids is not None and not (wanted_ids & app_set):
                continue
            if scope_ids is not None and not (scope_ids & app_set):
                continue
            if f.projects and pid not in f.projects:
                continue
            if f.tags and not tags_match(tags or {}, f.tags):
                continue
            result.append(pid)
        return tuple(result)

    def resolve(self, f: FilterSpec) -> ResolvedScope:
        return ResolvedScope(self.project_ids(f), self.effective_branches(f), self.engines(f))
