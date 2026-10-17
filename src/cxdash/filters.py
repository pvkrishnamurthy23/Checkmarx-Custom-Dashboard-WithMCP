"""The global filter model shared by UI, exports, alerts and SQL queries."""

from __future__ import annotations

import hashlib
import json
from datetime import date

from pydantic import BaseModel, ConfigDict, Field

MAX_TEXT_LENGTH = 200
FACET_FIELDS = frozenset({"title", "category", "cwe", "language", "package", "cve", "image", "file_path"})


class FilterSpec(BaseModel):
    """Immutable description of the active global filters (spec 2.1 #4)."""

    model_config = ConfigDict(frozen=True)

    applications: tuple[str, ...] = ()
    projects: tuple[str, ...] = ()  # project ids
    tags: tuple[str, ...] = ()  # key or key:value
    branches: tuple[str, ...] = ()
    engines: tuple[str, ...] = ()
    severities: tuple[str, ...] = ()
    states: tuple[str, ...] = ()
    statuses: tuple[str, ...] = ()
    date_from: date | None = None
    date_to: date | None = None
    text: str = Field(default="", max_length=MAX_TEXT_LENGTH)
    # Cross-filter facets from chart clicks, as "field:value" (field must be in FACET_FIELDS).
    facets: tuple[str, ...] = ()
    # Row-level scoping injected server-side from the user's groups (never from the URL).
    scope_applications: tuple[str, ...] | None = Field(default=None, exclude=True)

    def with_values(self, **changes: object) -> FilterSpec:
        return self.model_copy(update=changes)

    def fingerprint(self) -> str:
        """Stable hash used as cache key and audit-log reference."""
        payload = self.model_dump(mode="json")
        payload["scope"] = list(self.scope_applications) if self.scope_applications is not None else None
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:16]

    @property
    def is_empty(self) -> bool:
        return self == FilterSpec(scope_applications=self.scope_applications)

    def facet_values(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for item in self.facets:
            field, _, value = item.partition(":")
            if field in FACET_FIELDS and value:
                out.setdefault(field, []).append(value)
        return out
