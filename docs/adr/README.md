# Architecture Decision Records

One file per decision, numbered, never deleted. To change a decision, add a new ADR that **supersedes** the old one
and set the old one's status to `Superseded by NNNN`. Keep this index and `CLAUDE.md` in step with every change.

Template: copy [0000-template.md](0000-template.md).

| # | Title | Status |
|---|-------|--------|
| [0001](0001-dash-multipage-ui-and-vendored-assets.md) | Dash multi-page UI on a Flask server; self-hosted Bootstrap | Accepted |
| [0002](0002-read-only-checkmarx-client.md) | Read-only Checkmarx client (GET-only guard) | Accepted |
| [0003](0003-schema-additions-and-portable-types.md) | Schema additions beyond the spec; portable types | Accepted |
| [0004](0004-query-layer-structure.md) | Read-side query package, scope resolver, facade | Accepted |
| [0005](0005-counter-sourcing.md) | How scan_counter is sourced (summary vs derived) | Accepted |
| [0006](0006-on-demand-refresh-queue.md) | On-demand refresh through a database queue | Accepted |
| [0007](0007-lifecycle-and-sync-semantics.md) | Lifecycle, resolution and high-water-mark semantics | Accepted |
| [0008](0008-security-architecture.md) | Dashboard security architecture | Accepted |
| [0009](0009-caching.md) | Query cache keyed by data version | Accepted |
| [0010](0010-filter-state-flow.md) | Filter state flow and grid refresh | Accepted |
| [0011](0011-testing-strategy-and-synthetic-fixtures.md) | Testing strategy; synthetic fixtures until real payloads exist | Accepted |
| [0012](0012-deferred-scope-and-assumptions.md) | Deferred scope and API assumptions | Accepted |
| [0013](0013-api-call-economy-and-last-scan-selection.md) | API-call economy and last-scan selection | Accepted |
| [0014](0014-ui-design-system-and-component-library.md) | UI design system and reusable component library | Accepted |
