# 0012. Deferred scope and API assumptions

- **Status:** Accepted
- **Date:** 2026-10-16
- **Spec reference:** 6.4, 6.6, 8.2, 10.2, 16, 17

## Deferred (not in this build)
| Item | Why | To do |
|------|-----|-------|
| SCA "direct vs transitive" chart and "exploitable (network vector)" toggle | Spec says "if present in payload"; the field location is unknown without a real payload | Add columns in `normalize.py` + a migration once a real SCA result is captured |
| Optional Helm chart | Marked optional | Derive from `docker-compose.yml` |
| Delete saved views from the UI | Not specified; storage and API (`UserStore.delete_view`) exist | Add a small menu action |
| "Branch not scanned" message on every scanner page | Coverage is shown on Projects/Overview ("no scan on branch") | Add an empty-state variant when `effective_branches` has no scan |
| Server-side PNG endpoint | Plotly's modebar already downloads PNG client-side; `exporting.figure_to_png` (kaleido) is used for the PDF | Expose if a headless consumer needs it |
| Per-filter refresh | See ADR 0006 | n/a |
| Load test at 5,000 projects / 10M findings | Needs a dedicated PostgreSQL host; tool is provided and was run at 128k findings (p95 < 0.9 s) | Run `devtools/loadtest.py` at scale, tune indexes |

## API assumptions to verify (also in `docs/API_NOTES.md`)
1. `/api/scan-summary` block names and the secrets/SSCS blocks (`microEnginesCounters`, `sscsCounters` are guesses).
2. Result `type` strings for secrets, SSCS and how API Security results are distinguished from SAST (`TYPE_RULES` is the mapping table).
3. `similarityId` presence per engine (a stable hash fallback exists).
4. IAM host per region (`CX_IAM_URL` override).
5. Portal deep-link pattern (`CX_DEEPLINK_TEMPLATE`).
6. Scan `statusDetails[].name` values (`sca-container` etc. are normalised through `TYPE_RULES`).
