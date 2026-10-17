# Test fixtures

> **These payloads are SYNTHETIC** (their shapes were later checked against a real tenant: see `docs/API_NOTES.md`, section VERIFIED). They follow the public Checkmarx One API reference
> but were not captured from a real tenant (no tenant access was available when they were written).

Spec section 1 requires sanitised *real* payloads. To replace them:

1. Call each endpoint once with real credentials (see `docs/API_NOTES.md` for the checklist).
2. Remove names, URLs, hashes, file paths and any snippet content.
3. Overwrite the matching file here, keep the file name, and run `make test`.
   Failing contract tests (`tests/unit/test_contract_fixtures.py`) show exactly which field mapping to adjust.

| File | Endpoint |
|------|----------|
| `projects.json` | `GET /api/projects` |
| `applications.json` | `GET /api/applications` |
| `scans.json` | `GET /api/scans` |
| `scan_summary.json` | `GET /api/scan-summary` |
| `results_s1.json` | `GET /api/results?scan-id=scan-1` (one result per engine, plus an unknown type) |
| `token.json` | IAM token response |
