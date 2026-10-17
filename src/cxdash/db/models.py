"""ORM models mirroring spec section 7 (+ documented additions, see ADR 0003)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, Boolean, ForeignKey, Index, Integer, Numeric, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from cxdash.db.base import Base, JSONType, TextArray, UTCDateTime

_NOW = func.now()
BigPk = BigInteger().with_variant(Integer(), "sqlite")  # SQLite only autoincrements INTEGER PKs


class Application(Base):
    __tablename__ = "application"
    id: Mapped[str] = mapped_column(Text, primary_key=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    criticality: Mapped[int | None] = mapped_column(Integer)
    tags: Mapped[dict[str, Any] | None] = mapped_column(JSONType, default=dict, server_default="{}")
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, server_default=_NOW, nullable=False)


class Project(Base):
    __tablename__ = "project"
    id: Mapped[str] = mapped_column(Text, primary_key=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    repo_url: Mapped[str | None] = mapped_column(Text)
    main_branch: Mapped[str | None] = mapped_column(Text)
    groups: Mapped[list[Any] | None] = mapped_column(JSONType, default=list, server_default="[]")
    tags: Mapped[dict[str, Any] | None] = mapped_column(JSONType, default=dict, server_default="{}")
    application_ids: Mapped[list[Any] | None] = mapped_column(JSONType, default=list, server_default="[]")
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="1")
    created_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, server_default=_NOW, nullable=False)


class Scan(Base):
    __tablename__ = "scan"
    id: Mapped[str] = mapped_column(Text, primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"), nullable=False)
    branch: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    initiator: Mapped[str | None] = mapped_column(Text)
    source_type: Mapped[str | None] = mapped_column(Text)
    source_origin: Mapped[str | None] = mapped_column(Text)
    engines: Mapped[list[Any]] = mapped_column(TextArray, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    duration_seconds: Mapped[int | None] = mapped_column(Integer)
    summary_loaded: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="0")
    findings_loaded: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="0")
    is_latest: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="0")

    __table_args__ = (
        Index("scan_proj_branch_created", "project_id", "branch", "created_at"),
        Index("scan_latest", "is_latest"),
    )


class ScanEngineStatus(Base):
    __tablename__ = "scan_engine_status"
    scan_id: Mapped[str] = mapped_column(ForeignKey("scan.id", ondelete="CASCADE"), primary_key=True)
    engine: Mapped[str] = mapped_column(Text, primary_key=True)
    status: Mapped[str | None] = mapped_column(Text)
    details: Mapped[str | None] = mapped_column(Text)


class ScanCounter(Base):
    __tablename__ = "scan_counter"
    scan_id: Mapped[str] = mapped_column(ForeignKey("scan.id", ondelete="CASCADE"), primary_key=True)
    engine: Mapped[str] = mapped_column(Text, primary_key=True)
    severity: Mapped[str] = mapped_column(Text, primary_key=True)
    state: Mapped[str] = mapped_column(Text, primary_key=True)
    status: Mapped[str] = mapped_column(Text, primary_key=True, default="ALL", server_default="ALL")
    count: Mapped[int] = mapped_column(Integer, nullable=False)


class Finding(Base):
    __tablename__ = "finding"
    scan_id: Mapped[str] = mapped_column(ForeignKey("scan.id", ondelete="CASCADE"), primary_key=True)
    finding_id: Mapped[str] = mapped_column(Text, primary_key=True)
    similarity_id: Mapped[str | None] = mapped_column(Text)
    project_id: Mapped[str] = mapped_column(Text, nullable=False)
    branch: Mapped[str] = mapped_column(Text, nullable=False)
    engine: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(Text, nullable=False)
    state: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str | None] = mapped_column(Text)
    title: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)
    cwe: Mapped[str | None] = mapped_column(Text)
    cve: Mapped[str | None] = mapped_column(Text)
    cvss: Mapped[float | None] = mapped_column(Numeric(3, 1, asdecimal=False))
    package: Mapped[str | None] = mapped_column(Text)
    package_version: Mapped[str | None] = mapped_column(Text)
    fixed_version: Mapped[str | None] = mapped_column(Text)
    image: Mapped[str | None] = mapped_column(Text)
    file_path: Mapped[str | None] = mapped_column(Text)
    line: Mapped[int | None] = mapped_column(Integer)
    language: Mapped[str | None] = mapped_column(Text)
    category: Mapped[str | None] = mapped_column(Text)
    first_found_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    found_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    raw_json: Mapped[dict[str, Any] | None] = mapped_column(JSONType)

    __table_args__ = (
        Index("finding_filter", "project_id", "branch", "engine", "severity", "state"),
        Index("finding_scan_engine", "scan_id", "engine"),
        Index("finding_lifecycle_key", "project_id", "branch", "engine", "similarity_id"),
        Index(
            "finding_title_trgm", "title", postgresql_using="gin", postgresql_ops={"title": "gin_trgm_ops"}
        ),
    )


class FindingLifecycle(Base):
    __tablename__ = "finding_lifecycle"
    project_id: Mapped[str] = mapped_column(Text, primary_key=True)
    branch: Mapped[str] = mapped_column(Text, primary_key=True)
    engine: Mapped[str] = mapped_column(Text, primary_key=True)
    similarity_id: Mapped[str] = mapped_column(Text, primary_key=True)
    first_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_severity: Mapped[str | None] = mapped_column(Text)
    last_state: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        Index("lifecycle_resolved", "resolved_at"),
        Index("lifecycle_first_seen", "first_seen_at"),
    )


class SyncRun(Base):
    __tablename__ = "sync_run"
    id: Mapped[int] = mapped_column(BigPk, primary_key=True, autoincrement=True)
    job: Mapped[str] = mapped_column(Text, nullable=False)
    started_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    ended_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    records: Mapped[int | None] = mapped_column(Integer, default=0, server_default="0")
    api_calls: Mapped[int | None] = mapped_column(Integer, default=0, server_default="0")
    error: Mapped[str | None] = mapped_column(Text)


class SyncState(Base):
    __tablename__ = "sync_state"
    job: Mapped[str] = mapped_column(Text, primary_key=True)
    high_water_mark: Mapped[datetime | None] = mapped_column(UTCDateTime)
    details: Mapped[dict[str, Any] | None] = mapped_column(JSONType)


class SyncRequest(Base):
    """On-demand refresh queue written by the web app, drained by the worker (ADR 0006)."""

    __tablename__ = "sync_request"
    id: Mapped[int] = mapped_column(BigPk, primary_key=True, autoincrement=True)
    requested_by: Mapped[str | None] = mapped_column(Text)
    requested_at: Mapped[datetime] = mapped_column(UTCDateTime, server_default=_NOW, nullable=False)
    job: Mapped[str] = mapped_column(Text, nullable=False, default="scans")
    params: Mapped[dict[str, Any] | None] = mapped_column(JSONType)
    picked_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


class AppUser(Base):
    __tablename__ = "app_user"
    id: Mapped[str] = mapped_column(Text, primary_key=True)
    email: Mapped[str | None] = mapped_column(Text)
    role: Mapped[str] = mapped_column(Text, nullable=False)
    last_login: Mapped[datetime | None] = mapped_column(UTCDateTime)


class SavedView(Base):
    __tablename__ = "saved_view"
    id: Mapped[int] = mapped_column(BigPk, primary_key=True, autoincrement=True)
    user_id: Mapped[str | None] = mapped_column(Text)
    name: Mapped[str | None] = mapped_column(Text)
    filters: Mapped[dict[str, Any] | None] = mapped_column(JSONType)
    created_at: Mapped[datetime | None] = mapped_column(UTCDateTime, server_default=_NOW)


class AlertRule(Base):
    __tablename__ = "alert_rule"
    id: Mapped[int] = mapped_column(BigPk, primary_key=True, autoincrement=True)
    name: Mapped[str | None] = mapped_column(Text)
    kind: Mapped[str | None] = mapped_column(Text)
    params: Mapped[dict[str, Any] | None] = mapped_column(JSONType)
    channel: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool | None] = mapped_column(Boolean, default=True, server_default="1")


class AlertEvent(Base):
    __tablename__ = "alert_event"
    id: Mapped[int] = mapped_column(BigPk, primary_key=True, autoincrement=True)
    rule_id: Mapped[int | None] = mapped_column(BigInteger)
    fired_at: Mapped[datetime | None] = mapped_column(UTCDateTime, server_default=_NOW)
    payload: Mapped[dict[str, Any] | None] = mapped_column(JSONType)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(BigPk, primary_key=True, autoincrement=True)
    at: Mapped[datetime | None] = mapped_column(UTCDateTime, server_default=_NOW)
    user_id: Mapped[str | None] = mapped_column(Text)
    action: Mapped[str | None] = mapped_column(Text)
    detail: Mapped[dict[str, Any] | None] = mapped_column(JSONType)
