# Reconciliation checklist (dashboard vs Checkmarx One)

Run this before trusting the numbers, and again after any change to scope settings (`CX_BRANCHES`, `CX_CLOSED_STATES`, `CX_ENGINES`),
normalisers or counters. Spec acceptance: Overview counts equal the Checkmarx One UI for 10 sampled projects (same branch, same states).

## Procedure (per sampled project and branch)
1. Pick 10 projects: a mix of busy/quiet, with and without Secrets/SSCS/API Security, one with a failed engine, one on a glob branch if used.
2. In the dashboard: Projects page -> filter by the project and branch -> note open counts per scanner and per severity (Overview KPIs / scanner pages).
3. In Checkmarx One: open the project -> the same branch -> latest scan -> Results, apply the **same state filter** the dashboard uses
   (all states except `CX_CLOSED_STATES`, status not `FIXED`) -> note counts per scanner and severity.
4. Compare. They must match exactly for latest scans whose findings are loaded (counters are `DERIVED` from the findings).
5. If they differ, check in order:
   * Is the scan's `findings_loaded` true (Admin -> Sync runs: a `findings` run succeeded after the scan)? Otherwise the dashboard shows summary totals.
   * Same branch? (exact, case-sensitive; globs via `*`).
   * Same open definition? (`PROPOSED_NOT_EXPLOITABLE` is open by default; custom states are open.)
   * Same engines? (`CX_ENGINES`; unknown result types are skipped and logged: search logs for `unknown result type ignored`).
   * Mapping assumptions in `docs/API_NOTES.md` (type strings for secrets/SSCS/API Security).
6. Record the outcome below.

## Also verify once
* SLA/aging: pick a finding, compare `first found` in the drawer with the portal; confirm the SLA badge against `SLA_DAYS_*`.
* Scan health: success rate for the last 30 days against the portal's scan list.
* Deep link: "Open in Checkmarx One" lands on the right result (otherwise fix `CX_DEEPLINK_TEMPLATE`).
* Purge: `finding` rows exist only for the newest `FINDINGS_KEEP_SCANS_PER_BRANCH` scans per branch.

## Results log
| Date | Project | Branch | Engine | Dashboard (C/H/M/L) | Checkmarx One (C/H/M/L) | Match | Notes |
|------|---------|--------|--------|---------------------|-------------------------|-------|-------|
| | | | | | | | |
