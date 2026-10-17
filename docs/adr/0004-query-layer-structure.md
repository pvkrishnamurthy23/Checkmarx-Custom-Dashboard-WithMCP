# 0004. Read-side query package, scope resolver, facade

- **Status:** Accepted
- **Date:** 2026-10-16
- **Spec reference:** 4 (`db/queries.py`), 9, 10.4, 12 (row-level scoping)

## Context
The spec names a single `db/queries.py`. Page needs grew to overview, findings, projects, health, analytics, options and
admin queries, and every one of them must apply the same scope rules (applications, tags, branch globs, engines, row-level scope).

## Decision
* `db/queries/` is a package: `scope.py` (`ScopeResolver`), `base.py` (shared helpers), `overview.py`, `findings.py`,
  `projects.py` (+ health/lifecycle analytics), `admin.py` (options, admin, per-user store). `DashboardQueries` is a thin facade.
* `ScopeResolver` is the **only** place that turns a `FilterSpec` into project ids / branches / engines. The row-level scope
  (`scope_applications`) is intersected there, so no query can forget it. It is injected server-side
  (`FilterSpec.scope_applications` is `exclude=True` and ignored when decoding client state).
* "Open" is defined once (`metrics/open_rules.py`) as a Python predicate **and** a SQL fragment.
* Portable SQL: age/SLA cutoffs are computed in Python and bound as parameters (no `EXTRACT`/`julianday`).
* User-controlled identifiers never reach SQL: sort and filter columns, breakdown columns and facet fields are whitelists;
  text search escapes `%`, `_` and `\` and uses bound parameters.
* Findings grids show *open* findings unless the user picks explicit states/statuses.

## Consequences
Adding a query means adding a method, not a new scope implementation. Counter-based pages (overview, scanner KPIs) honour
application/project/tag/branch/engine/severity/state/date filters; `status` and free text only apply to finding-level views.
