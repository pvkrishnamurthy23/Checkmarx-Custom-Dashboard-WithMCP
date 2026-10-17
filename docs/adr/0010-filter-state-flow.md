# 0010. Filter state flow and grid refresh

- **Status:** Accepted
- **Date:** 2026-10-16
- **Spec reference:** 10.1, 10.3

## Decision
`dcc.Store('filters')` is the single source of truth. Four callbacks keep it, the controls and the URL in step, each comparing
before writing (`no_update` when equal) so the loop terminates: URL -> store+controls (C, also the initial load), controls -> store (A),
store -> controls (D), store -> URL (B). Chart/KPI clicks write to the store (`allow_duplicate`); clicking the same value clears it.

Lessons baked in (found with a real browser test, `tests/ui/test_e2e.py`):
* Dropdown **options are rendered in the layout**, not loaded by a callback; otherwise a value restored from the URL is discarded
  as "not in options" and the filter silently clears.
* Dash re-fires callbacks when a page's components first render; click handlers ignore falsy trigger values (`n_clicks == 0`, no `clickData`).
* The infinite-row-model grid cannot be refreshed in place from Dash, so its container is rebuilt whenever the filters change.

Everything decoded from the URL is validated and length-capped (`ui/state.py`); malformed or absurd URLs degrade to "no filters".
