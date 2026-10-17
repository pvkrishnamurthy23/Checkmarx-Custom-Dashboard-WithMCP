"""Filter options, Admin page data and small per-user stores (saved views, audit log)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import delete, func, select

from cxdash.db import models as m
from cxdash.db.queries.base import QueryContext, utcnow
from cxdash.domain import ENGINE_LABELS, SEVERITY_ORDER

COMMON_STATES = ["TO_VERIFY", "NOT_EXPLOITABLE", "PROPOSED_NOT_EXPLOITABLE", "CONFIRMED", "URGENT"]
MAX_SAVED_VIEWS_PER_USER = 50


class OptionQueries:
    def __init__(self, ctx: QueryContext) -> None:
        self._c = ctx

    def project_names(self, ids: tuple[str, ...] | list[str]) -> dict[str, str]:
        """id -> name for a handful of projects (labels for active-filter chips)."""
        if not ids:
            return {}
        with self._c.db.session() as s:
            return dict(
                s.execute(select(m.Project.id, m.Project.name).where(m.Project.id.in_(list(ids)[:200]))).all()
            )

    def filter_options(self, scope_applications: tuple[str, ...] | None = None) -> dict[str, list[Any]]:
        with self._c.db.session() as s:
            apps = sorted(s.scalars(select(m.Application.name)))
            projects = s.execute(
                select(m.Project.id, m.Project.name, m.Project.tags)
                .where(m.Project.active.is_(True))
                .order_by(m.Project.name)
            ).all()
            states = set(COMMON_STATES) | set(
                s.scalars(select(m.ScanCounter.state).where(m.ScanCounter.state != "ALL").distinct())
            )
        tags: set[str] = set()
        for _, _, t in projects:
            for k, v in (t or {}).items():
                tags.add(k)
                if v:
                    tags.add(f"{k}:{v}")
        if scope_applications is not None:
            apps = [a for a in apps if a in scope_applications]
        configured = self._c.settings.cx_branches
        branches = (
            list(configured)
            if configured and not any("*" in b for b in configured)
            else self._c.resolver.known_branches()
        )
        return {
            "applications": apps,
            "projects": [{"label": n, "value": i} for i, n, _ in projects],
            "tags": sorted(tags),
            "branches": branches,
            "engines": [{"label": ENGINE_LABELS[e], "value": e} for e in self._c.settings.cx_engines],
            "severities": list(SEVERITY_ORDER),
            "states": sorted(states),
            "statuses": ["NEW", "RECURRENT", "FIXED"],
        }


class AdminQueries:
    def __init__(self, ctx: QueryContext) -> None:
        self._c = ctx

    def sync_runs(self, limit: int = 50) -> list[dict[str, Any]]:
        r = m.SyncRun
        with self._c.db.session() as s:
            rows = s.scalars(select(r).order_by(r.id.desc()).limit(limit)).all()
        return [
            {"id": x.id, "job": x.job, "started_at": x.started_at, "ended_at": x.ended_at, "status": x.status,
             "records": x.records, "api_calls": x.api_calls, "error": x.error}
            for x in rows
        ]  # fmt: skip

    def api_call_totals(self, hours: int = 24) -> dict[str, int]:
        from datetime import timedelta

        since = utcnow() - timedelta(hours=hours)
        with self._c.db.session() as s:
            rows = s.execute(
                select(m.SyncRun.job, func.sum(m.SyncRun.api_calls))
                .where(m.SyncRun.started_at >= since)
                .group_by(m.SyncRun.job)
            ).all()
        return {job: int(n or 0) for job, n in rows}

    def freshness(self) -> dict[str, datetime | None]:
        with self._c.db.session() as s:
            rows = s.execute(
                select(m.SyncRun.job, func.max(m.SyncRun.ended_at))
                .where(m.SyncRun.status == "success")
                .group_by(m.SyncRun.job)
            ).all()
        return dict(rows)

    def last_sync(self) -> datetime | None:
        """Newest successful scans cycle (drives the 'Last synced' header and /healthz)."""
        return self.freshness().get("scans")

    def users(self) -> list[dict[str, Any]]:
        with self._c.db.session() as s:
            return [
                {"id": u.id, "email": u.email, "role": u.role, "last_login": u.last_login}
                for u in s.scalars(select(m.AppUser).order_by(m.AppUser.last_login.desc()))
            ]

    def record_login(self, user_id: str, email: str | None, role: str) -> None:
        from cxdash.db.upsert import upsert

        with self._c.db.session() as s:
            upsert(
                s,
                m.AppUser.__table__,
                [{"id": user_id, "email": email, "role": role, "last_login": utcnow()}],
                ["id"],
            )


class UserStore:
    """Saved views and the export/audit log (per-user data, kept apart from analytics queries)."""

    def __init__(self, ctx: QueryContext) -> None:
        self._c = ctx

    def saved_views(self, user_id: str) -> list[dict[str, Any]]:
        v = m.SavedView
        with self._c.db.session() as s:
            return [
                {"id": x.id, "name": x.name, "filters": x.filters}
                for x in s.scalars(select(v).where(v.user_id == user_id).order_by(v.name))
            ]

    def save_view(self, user_id: str, name: str, filters: dict[str, Any]) -> int:
        name = name.strip()[:80]
        if not name:
            raise ValueError("view name required")
        with self._c.db.session() as s:
            count = (
                s.scalar(select(func.count()).select_from(m.SavedView).where(m.SavedView.user_id == user_id))
                or 0
            )
            if count >= MAX_SAVED_VIEWS_PER_USER:
                raise ValueError("saved view limit reached")
            row = m.SavedView(user_id=user_id, name=name, filters=filters)
            s.add(row)
            s.flush()
            return row.id

    def delete_view(self, user_id: str, view_id: int) -> None:
        with self._c.db.session() as s:
            s.execute(delete(m.SavedView).where(m.SavedView.id == view_id, m.SavedView.user_id == user_id))

    def audit(self, user_id: str, action: str, detail: dict[str, Any]) -> None:
        with self._c.db.session() as s:
            s.add(m.AuditLog(user_id=user_id, action=action, detail=detail))

    def audit_rows(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._c.db.session() as s:
            rows = s.scalars(select(m.AuditLog).order_by(m.AuditLog.id.desc()).limit(limit)).all()
        return [{"at": r.at, "user": r.user_id, "action": r.action, "detail": r.detail} for r in rows]
