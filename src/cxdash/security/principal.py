"""Who is calling, what role they hold, and which applications they may see."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

import yaml

from cxdash.config import Settings
from cxdash.domain import ROLE_ADMIN, ROLE_ANALYST, ROLE_RANK, ROLE_VIEWER


@dataclass(frozen=True)
class Principal:
    user_id: str
    email: str | None
    role: str
    scope_applications: tuple[str, ...] | None = None  # None = unrestricted

    def has_role(self, required: str) -> bool:
        return ROLE_RANK.get(self.role, -1) >= ROLE_RANK[required]


ANONYMOUS_DEV = Principal("anonymous-dev", None, ROLE_ADMIN)


class RoleMapper:
    """IdP groups -> role (ROLE_ADMIN_GROUPS / ROLE_ANALYST_GROUPS); everyone else is a viewer."""

    def __init__(self, admin_groups: Iterable[str], analyst_groups: Iterable[str]) -> None:
        self._admin = {g.lower() for g in admin_groups}
        self._analyst = {g.lower() for g in analyst_groups}

    @classmethod
    def from_settings(cls, s: Settings) -> RoleMapper:
        return cls(s.role_admin_groups, s.role_analyst_groups)

    def role_for(self, groups: Iterable[str]) -> str:
        g = {x.lower() for x in groups}
        if g & self._admin:
            return ROLE_ADMIN
        if g & self._analyst:
            return ROLE_ANALYST
        return ROLE_VIEWER


class ScopeMap:
    """Optional row-level scoping (``scope_map.yaml``: ``{group: [application name, ...]}``)."""

    def __init__(self, mapping: dict[str, list[str]] | None) -> None:
        self._mapping = {k.lower(): tuple(v) for k, v in (mapping or {}).items()}

    @property
    def enabled(self) -> bool:
        return bool(self._mapping)

    @classmethod
    def load(cls, path: str) -> ScopeMap:
        if not path:
            return cls(None)
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict) or not all(isinstance(v, list) for v in data.values()):
            raise ValueError("scope_map.yaml must map group -> list of application names")
        return cls({str(k): [str(a) for a in v] for k, v in data.items()})

    def applications_for(self, groups: Iterable[str], role: str) -> tuple[str, ...] | None:
        """None means unrestricted (feature off, or admin). An empty tuple means "sees nothing"."""
        if not self.enabled or role == ROLE_ADMIN:
            return None
        apps: dict[str, None] = {}
        for g in groups:
            for a in self._mapping.get(g.lower(), ()):
                apps.setdefault(a, None)
        return tuple(apps)
