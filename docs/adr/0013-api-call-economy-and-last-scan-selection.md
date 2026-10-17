# 0013. API-call economy and last-scan selection

- **Status:** Accepted (refines ADR 0007 for the default mode)
- **Date:** 2026-10-17
- **Spec reference:** 8.1 (scans job), 6.3, 16 #7 (rate limits)

## Context
The spec walks every scan in `CX_BRANCHES` since a high-water mark and backfills 90 days. On the real tenant (396 projects, 8,778
scans, ~1,000 on the two configured branches) that is thousands of calls for history the dashboard does not need. The product owner
wants **only the last full scan per project** and as few API calls as possible.

## Verified API facts (real tenant, 2026-10-16)
* `GET /api/projects/last-scan?project-ids=<50 ids>&branch=B&scan-status=Completed&limit=N` returns the newest scan per project on a branch
  in one call, keyed by project id (the entry has `id`, `createdAt`, `status`, `branch`, `engines`, but no `statusDetails`/`metadata`).
* `GET /api/scans?scan-ids=<ids>` returns full scan records (incl. `statusDetails` and `metadata.configs`) for up to 50 ids in one call.
* `GET /api/results?...&limit=500` is accepted: a typical scan's results arrive in one call (was 2+ at 100).
* Scan `metadata.configs[type=sast].value.incremental` is `"true"`/`"false"`. It is the *configured* mode; a project's first scan cannot be
  incremental, so it is not proof that results are partial. Sampled: 3 of 20 latest master scans flagged, 7 of 7 in one webhook-driven repo.

## Decision
* `SYNC_SCAN_SELECTION=last_scan` (default). `ScansJob` composes a selection strategy: `LastScanSelection` (this ADR) or
  `HighWaterMarkSelection` (`all`, the original behaviour; required for glob or all-branch scope, and used for an explicit backfill window).
  `last_scan` needs exact branch names (validated at startup).
* Per cycle: one `last-scan` call per 50 projects per branch; scan details only for scan ids not already stored (one call per 50); summaries
  and results only for new latest scans. Steady state for N projects and B branches = `ceil(N/50) * B` calls plus the delta.
* "Full" = status `SYNC_LAST_SCAN_STATUS` (default `Completed`; Partial/Failed/Canceled never count). `SYNC_FULL_SCANS_ONLY` is **opt-in**: when on,
  a latest scan flagged incremental is looked past (one `scans` page of `SYNC_FULL_SCAN_LOOKBACK` per project, remembered in `sync_state` so it is
  not repeated), and a project with no other scan stores nothing. Default off because the flag is not proof and would blank webhook-only projects.
* Findings: `CX_RESULTS_PAGE_SIZE=500`; the nightly full re-pull is off by default (`SYNC_NIGHTLY_FINDINGS_REFRESH`); `SYNC_LOAD_FINDINGS=false`
  gives a counters-only mode (overview works from scan-summary totals).
* History: stored scans accumulate over time at zero extra cost, which builds the trend. `SYNC_KEEP_SCAN_HISTORY=false` makes the nightly purge keep only
  the latest scan per project/branch.
* Safety net: `SYNC_MAX_API_CALLS_PER_RUN` (default 2500) stops a job with `ApiBudgetExceeded` before the call is made; work is idempotent and
  resumes next cycle. Every `sync_run` row and CLI line shows `api_calls`.

## Consequences
* The trend chart starts with the first sync and fills as new scans appear (no backfill in `last_scan` mode).
* Counts are as of each project's last scan, not a point-in-time snapshot.
* Result ids are not unique per engine (SCA/Containers reuse the CVE), so findings are keyed on `alternateId` (verified unique) and the lifecycle key adds
  package/image; duplicate keys inside an upsert batch are logged instead of silently dropped.
