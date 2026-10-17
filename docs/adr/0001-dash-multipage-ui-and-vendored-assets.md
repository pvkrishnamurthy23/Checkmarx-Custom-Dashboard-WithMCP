# 0001. Dash multi-page UI on a Flask server; self-hosted Bootstrap

- **Status:** Accepted (page layout superseded by ADR 0014)
- **Date:** 2026-10-16
- **Spec reference:** 3 (stack), 4 (layout), 10 (UI)

## Context
The spec fixes Dash/Plotly with `dash.register_page`, dash-bootstrap-components and AG Grid. We still had to decide how the
Flask server is created, where Bootstrap CSS comes from, and how the app is wired so it can be tested.

## Decision
* `create_app()` builds an explicit `Flask` server, installs security (ADR 0008), health/metrics and export routes on it, and
  passes it to `dash.Dash(use_pages=True)`. `cxdash.ui.app:server` is resolved lazily (module `__getattr__`) so importing
  the module never needs a valid `.env`.
* `app.layout` is a **function**, evaluated per page load, so the navigation (Admin link) and the filter options reflect
  the calling user's role and row-level scope.
* Bootstrap 5.3.3 CSS is **vendored** into `ui/assets/10-bootstrap.min.css` (MIT, sha256 recorded in `docs/RUNBOOK.md`).
  No third-party CDN is contacted at runtime, so the CSP can stay `'self'` and the app works air-gapped.
* AG Grid uses the default (Theming API) theme; light/dark follows `data-bs-theme` via `data-ag-theme-mode`.
* Scanner pages are declarative (`ScannerPageSpec`): a page lists its charts, one factory wires layout, callbacks, grid and
  cross-filtering (Open/Closed).

## Consequences
* One Dash app per process (Dash's global callback registry); tests create a single session-scoped app.
* Upgrading Bootstrap means replacing one file and re-recording its hash.

## Alternatives considered
* `dbc.themes.BOOTSTRAP` CDN link: simpler, but needs CDN egress and widens the CSP.
* Custom router instead of `register_page`: more control, but the spec asks for `register_page`.
