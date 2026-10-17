# 0003. Schema additions beyond the spec; portable types

- **Status:** Accepted
- **Date:** 2026-10-16
- **Spec reference:** 7, 8.1 (inactive projects), 10.1 (refresh)

## Context
Section 7 gives the DDL, but other sections require data the DDL cannot hold ("projects that disappear are flagged inactive",
an on-demand refresh button, SQLite in dev through the same SQLAlchemy layer).

## Decision
Added, all in `0001_init`:
* `project.active boolean` - soft-delete flag set by the inventory job; every dashboard query joins `project` and filters `active`.
* `sync_request` - queue written by the web app, drained by the worker (ADR 0006).
* Indexes: `scan(is_latest)`, `finding(scan_id, engine)`, `finding(project_id, branch, engine, similarity_id)` (lifecycle join),
  `finding_lifecycle(resolved_at)`, `finding_lifecycle(first_seen_at)`.
* Portable types: `JSON` with a `JSONB` variant on PostgreSQL; `text[]` with a JSON variant on SQLite; `UTCDateTime`
  (a `TypeDecorator`) so SQLite round-trips aware UTC datetimes like `timestamptz`.
* `pg_trgm` is created when available; if the extension cannot be created the migration falls back to a plain btree index on
  `finding.title` and prints a warning (the official `postgres:16` image has the extension).
* Models use `Mapped[X | None]` where the spec DDL has `DEFAULT` but no `NOT NULL`, so `alembic compare_metadata` stays empty
  (`tests/integration/test_migrations.py` enforces model/migration parity).

## Consequences
The same code and migration run on PostgreSQL (production) and SQLite (dev/tests); both are exercised in tests.
