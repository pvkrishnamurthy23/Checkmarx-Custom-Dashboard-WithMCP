"""initial schema (spec section 7 + ADR 0003 additions)

Revision ID: 0001_init
Revises:
Create Date: 2026-10-16
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001_init"
down_revision = None
branch_labels = None
depends_on = None

JSONT = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
TEXT_ARRAY = postgresql.ARRAY(sa.Text()).with_variant(sa.JSON(), "sqlite")
TS = sa.DateTime(timezone=True)
NOW = sa.func.now()
BIGPK = sa.BigInteger().with_variant(sa.Integer(), "sqlite")


def upgrade() -> None:
    bind = op.get_bind()
    trgm = False
    if bind.dialect.name == "postgresql":
        try:  # contrib module; present in the official postgres image, absent on some minimal builds
            with bind.begin_nested():
                op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
            trgm = True
        except Exception:
            print("WARNING: pg_trgm unavailable; text search falls back to a plain btree index")

    op.create_table(
        "application",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("name", sa.Text, nullable=False),
        sa.Column("criticality", sa.Integer),
        sa.Column("tags", JSONT, server_default=sa.text("'{}'")),
        sa.Column("updated_at", TS, server_default=NOW, nullable=False),
    )
    op.create_table(
        "project",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("name", sa.Text, nullable=False),
        sa.Column("repo_url", sa.Text),
        sa.Column("main_branch", sa.Text),
        sa.Column("groups", JSONT, server_default=sa.text("'[]'")),
        sa.Column("tags", JSONT, server_default=sa.text("'{}'")),
        sa.Column("application_ids", JSONT, server_default=sa.text("'[]'")),
        sa.Column("active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("created_at", TS),
        sa.Column("updated_at", TS, server_default=NOW, nullable=False),
    )
    op.create_table(
        "scan",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("project_id", sa.Text, sa.ForeignKey("project.id"), nullable=False),
        sa.Column("branch", sa.Text, nullable=False),
        sa.Column("status", sa.Text, nullable=False),
        sa.Column("initiator", sa.Text),
        sa.Column("source_type", sa.Text),
        sa.Column("source_origin", sa.Text),
        sa.Column("engines", TEXT_ARRAY, nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("completed_at", TS),
        sa.Column("duration_seconds", sa.Integer),
        sa.Column("summary_loaded", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("findings_loaded", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("is_latest", sa.Boolean, nullable=False, server_default=sa.false()),
    )
    op.create_index("scan_proj_branch_created", "scan", ["project_id", "branch", "created_at"])
    op.create_index("scan_latest", "scan", ["is_latest"])

    op.create_table(
        "scan_engine_status",
        sa.Column("scan_id", sa.Text, sa.ForeignKey("scan.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("engine", sa.Text, primary_key=True),
        sa.Column("status", sa.Text),
        sa.Column("details", sa.Text),
    )
    op.create_table(
        "scan_counter",
        sa.Column("scan_id", sa.Text, sa.ForeignKey("scan.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("engine", sa.Text, primary_key=True),
        sa.Column("severity", sa.Text, primary_key=True),
        sa.Column("state", sa.Text, primary_key=True),
        sa.Column("status", sa.Text, primary_key=True, server_default="ALL"),
        sa.Column("count", sa.Integer, nullable=False),
    )
    op.create_table(
        "finding",
        sa.Column("scan_id", sa.Text, sa.ForeignKey("scan.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("finding_id", sa.Text, primary_key=True),
        sa.Column("similarity_id", sa.Text),
        sa.Column("project_id", sa.Text, nullable=False),
        sa.Column("branch", sa.Text, nullable=False),
        sa.Column("engine", sa.Text, nullable=False),
        sa.Column("severity", sa.Text, nullable=False),
        sa.Column("state", sa.Text, nullable=False),
        sa.Column("status", sa.Text),
        sa.Column("title", sa.Text),
        sa.Column("description", sa.Text),
        sa.Column("cwe", sa.Text),
        sa.Column("cve", sa.Text),
        sa.Column("cvss", sa.Numeric(3, 1)),
        sa.Column("package", sa.Text),
        sa.Column("package_version", sa.Text),
        sa.Column("fixed_version", sa.Text),
        sa.Column("image", sa.Text),
        sa.Column("file_path", sa.Text),
        sa.Column("line", sa.Integer),
        sa.Column("language", sa.Text),
        sa.Column("category", sa.Text),
        sa.Column("first_found_at", TS),
        sa.Column("found_at", TS),
        sa.Column("raw_json", JSONT),
    )
    op.create_index("finding_filter", "finding", ["project_id", "branch", "engine", "severity", "state"])
    op.create_index("finding_scan_engine", "finding", ["scan_id", "engine"])
    op.create_index("finding_lifecycle_key", "finding", ["project_id", "branch", "engine", "similarity_id"])
    if trgm:
        op.execute("CREATE INDEX finding_title_trgm ON finding USING gin (title gin_trgm_ops)")
    else:
        op.create_index("finding_title_trgm", "finding", ["title"])

    op.create_table(
        "finding_lifecycle",
        sa.Column("project_id", sa.Text, primary_key=True),
        sa.Column("branch", sa.Text, primary_key=True),
        sa.Column("engine", sa.Text, primary_key=True),
        sa.Column("similarity_id", sa.Text, primary_key=True),
        sa.Column("first_seen_at", TS, nullable=False),
        sa.Column("last_seen_at", TS, nullable=False),
        sa.Column("resolved_at", TS),
        sa.Column("last_severity", sa.Text),
        sa.Column("last_state", sa.Text),
    )
    op.create_index("lifecycle_resolved", "finding_lifecycle", ["resolved_at"])
    op.create_index("lifecycle_first_seen", "finding_lifecycle", ["first_seen_at"])

    op.create_table(
        "sync_run",
        sa.Column("id", BIGPK, primary_key=True, autoincrement=True),
        sa.Column("job", sa.Text, nullable=False),
        sa.Column("started_at", TS, nullable=False),
        sa.Column("ended_at", TS),
        sa.Column("status", sa.Text, nullable=False),
        sa.Column("records", sa.Integer, server_default="0"),
        sa.Column("api_calls", sa.Integer, server_default="0"),
        sa.Column("error", sa.Text),
    )
    op.create_table(
        "sync_state",
        sa.Column("job", sa.Text, primary_key=True),
        sa.Column("high_water_mark", TS),
        sa.Column("details", JSONT),
    )
    op.create_table(
        "sync_request",
        sa.Column("id", BIGPK, primary_key=True, autoincrement=True),
        sa.Column("requested_by", sa.Text),
        sa.Column("requested_at", TS, server_default=NOW, nullable=False),
        sa.Column("job", sa.Text, nullable=False, server_default="scans"),
        sa.Column("params", JSONT),
        sa.Column("picked_at", TS),
    )
    op.create_table(
        "app_user",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("email", sa.Text),
        sa.Column("role", sa.Text, nullable=False),
        sa.Column("last_login", TS),
    )
    op.create_table(
        "saved_view",
        sa.Column("id", BIGPK, primary_key=True, autoincrement=True),
        sa.Column("user_id", sa.Text),
        sa.Column("name", sa.Text),
        sa.Column("filters", JSONT),
        sa.Column("created_at", TS, server_default=NOW),
    )
    op.create_table(
        "alert_rule",
        sa.Column("id", BIGPK, primary_key=True, autoincrement=True),
        sa.Column("name", sa.Text),
        sa.Column("kind", sa.Text),
        sa.Column("params", JSONT),
        sa.Column("channel", sa.Text),
        sa.Column("enabled", sa.Boolean, server_default=sa.true()),
    )
    op.create_table(
        "alert_event",
        sa.Column("id", BIGPK, primary_key=True, autoincrement=True),
        sa.Column("rule_id", sa.BigInteger),
        sa.Column("fired_at", TS, server_default=NOW),
        sa.Column("payload", JSONT),
    )
    op.create_table(
        "audit_log",
        sa.Column("id", BIGPK, primary_key=True, autoincrement=True),
        sa.Column("at", TS, server_default=NOW),
        sa.Column("user_id", sa.Text),
        sa.Column("action", sa.Text),
        sa.Column("detail", JSONT),
    )


def downgrade() -> None:
    for table in (
        "audit_log", "alert_event", "alert_rule", "saved_view", "app_user", "sync_request", "sync_state",
        "sync_run", "finding_lifecycle", "finding", "scan_counter", "scan_engine_status", "scan", "project",
        "application",
    ):  # fmt: skip
        op.drop_table(table)
