# 0011. Testing strategy; synthetic fixtures until real payloads exist

- **Status:** Accepted
- **Date:** 2026-10-16
- **Spec reference:** 1, 15, 16

## Context
The spec requires sanitised **real** payload fixtures. No tenant access existed when this was built, so real payloads could not be captured.

## Decision
* `tests/fixtures/*.json` are **synthetic**, written from the public API reference, and labelled as such (`tests/fixtures/README.md`).
  Replacing them with sanitised real payloads is Milestone-1 follow-up work (`docs/API_NOTES.md` has the checklist). Contract tests fail
  loudly on any field that no longer maps.
* Layers: unit (config, metrics, normalisers, codec, security), client (respx), integration (full sync on SQLite and, with
  `-m integration`, on real PostgreSQL via `CXDASH_TEST_PG_URL` or the optional embedded `pgserver`), UI (Dash callbacks through the real
  `/_dash-update-component` endpoint), e2e (`-m e2e`, Playwright/Chromium with the CSP active).
* `make test` runs everything except `integration` and `e2e`; CI runs both against a PostgreSQL service.
* `devtools/seed.py` generates a fake dataset for demos, UI tests and the load test (`devtools/loadtest.py`).

## Consequences
Until real fixtures replace the synthetic ones, the field mappings in `normalize.py` are **assumptions**; reconciliation against the
Checkmarx One UI (`docs/RECONCILE.md`) is mandatory before the numbers are trusted.
