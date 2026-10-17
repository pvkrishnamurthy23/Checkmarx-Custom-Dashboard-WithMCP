"""Pydantic models for Checkmarx One payloads.

Parsing is tolerant (``extra="allow"``): unknown fields are kept, never fatal.
Field names follow the public API; verify against fixtures (docs/API_NOTES.md).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from cxdash.domain import Severity


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


class CxModel(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)


class ProjectModel(CxModel):
    id: str
    name: str
    createdAt: datetime | None = None
    updatedAt: datetime | None = None
    groups: list[str] = Field(default_factory=list)
    tags: dict[str, str] = Field(default_factory=dict)
    repoUrl: str | None = None
    mainBranch: str | None = None
    applicationIds: list[str] = Field(default_factory=list)

    @field_validator("groups", "applicationIds", mode="before")
    @classmethod
    def _none_list(cls, v: Any) -> Any:
        return v or []

    @field_validator("tags", mode="before")
    @classmethod
    def _none_dict(cls, v: Any) -> Any:
        return {str(k): "" if val is None else str(val) for k, val in (v or {}).items()}

    _tz = field_validator("createdAt", "updatedAt")(_utc)


class ApplicationModel(CxModel):
    id: str
    name: str
    criticality: int | None = None
    tags: dict[str, str] = Field(default_factory=dict)
    projectIds: list[str] = Field(default_factory=list)

    @field_validator("tags", mode="before")
    @classmethod
    def _none_dict(cls, v: Any) -> Any:
        return {str(k): "" if val is None else str(val) for k, val in (v or {}).items()}

    @field_validator("projectIds", mode="before")
    @classmethod
    def _none_list(cls, v: Any) -> Any:
        return v or []


class ScanStatusDetail(CxModel):
    name: str
    status: str = ""
    details: str | None = None


class ScanModel(CxModel):
    id: str
    status: str
    branch: str = ""
    projectId: str
    createdAt: datetime
    updatedAt: datetime | None = None
    engines: list[str] = Field(default_factory=list)
    statusDetails: list[ScanStatusDetail] = Field(default_factory=list)
    initiator: str | None = None
    sourceType: str | None = None
    sourceOrigin: str | None = None
    metadata: dict[str, Any] | None = None

    def _config(self, name: str) -> dict[str, Any]:
        for cfg in (self.metadata or {}).get("configs") or []:
            if isinstance(cfg, dict) and cfg.get("type") == name:
                value = cfg.get("value")
                return value if isinstance(value, dict) else {}
        return {}

    @property
    def is_incremental(self) -> bool:
        """SAST incremental flag from the scan configuration (verified on a real tenant: ``"true"``/``"false"``)."""
        return str(self._config("sast").get("incremental", "")).lower() == "true"

    def engine_keys(self, name: str) -> list[str]:
        """Dashboard engine(s) a scan engine name stands for.

        ``microengines`` bundles secret detection (2ms) and the SSCS scorecard; the scan configuration says which ran.
        """
        lowered = name.lower()
        if lowered == "microengines":
            cfg = self._config("microengines")
            keys = ["secrets"] if str(cfg.get("2ms", "true")).lower() != "false" else []
            if str(cfg.get("scorecard", "")).lower() == "true":
                keys.append("sscs")
            return keys
        if lowered == "general":
            return []
        return [lowered]

    @field_validator("engines", "statusDetails", mode="before")
    @classmethod
    def _none_list(cls, v: Any) -> Any:
        return v or []

    @field_validator("branch", mode="before")
    @classmethod
    def _branch(cls, v: Any) -> Any:
        return v or ""

    _tz = field_validator("createdAt", "updatedAt")(_utc)


class CounterRow(BaseModel):
    """One flattened row destined for ``scan_counter``."""

    scan_id: str
    engine: str
    severity: str
    state: str
    status: str
    count: int


class NormalizedFinding(BaseModel):
    """Engine-independent finding (spec 6.6). ``raw_json`` is always retained."""

    finding_id: str
    similarity_id: str
    scan_id: str
    project_id: str
    branch: str
    engine: Literal["sast", "sca", "containers", "kics", "secrets", "apisec", "sscs"]
    severity: Severity
    state: str
    status: Literal["NEW", "RECURRENT", "FIXED"] | None = None
    title: str
    description: str | None = None
    cwe: str | None = None
    cve: str | None = None
    cvss: float | None = None
    package: str | None = None
    package_version: str | None = None
    fixed_version: str | None = None
    image: str | None = None
    file_path: str | None = None
    line: int | None = None
    language: str | None = None
    category: str | None = None
    first_found_at: datetime | None = None
    found_at: datetime | None = None
    raw_json: dict[str, Any]
