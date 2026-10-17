# 0005. How scan_counter is sourced (summary vs derived)

- **Status:** Accepted
- **Date:** 2026-10-16
- **Spec reference:** 7.1, 8.2, 9, 10.4

## Context
`/api/scan-summary` returns a severity counter list and a separate state counter list per engine; it does **not** give
severity x state. The "open" definition excludes closed states (default `NOT_EXPLOITABLE`), so severity-only totals over-count.
Section 8.2 says to derive severity x state from findings for latest scans and "mark the rows status accordingly".

## Decision
`scan_counter.status` is a source marker (`domain.py`):
* `ALL`     - severity totals from the summary (`state='ALL'`).
* `STATE`   - state totals from the summary (`severity='ALL'`); informational, never summed.
* `DERIVED` - severity x state computed from `finding` rows when a latest scan's findings are loaded
  (finding rows already in a closed *status* such as FIXED are excluded at derivation time).

Queries use `counter_source_clause()`: a scan contributes its `DERIVED` rows once `findings_loaded` is true, otherwise its `ALL` rows.
The overview therefore never touches the `finding` table, is exact for latest scans, and still has history (trend) from summaries.
Trend points for historical scans are labelled "from scan summaries" because those cannot exclude closed states.

## Consequences
* Between a scan appearing and its findings loading, that scan's numbers are the (slightly high) summary totals.
* Changing `CX_CLOSED_STATUSES` takes effect after the next nightly full refresh (which re-derives counters).
