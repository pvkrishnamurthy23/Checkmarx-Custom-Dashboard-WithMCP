# 0007. Lifecycle, resolution and high-water-mark semantics

- **Status:** Accepted
- **Date:** 2026-10-16
- **Spec reference:** 7.1, 8.1, 8.3, 9

## Decision
**Lifecycle (`finding_lifecycle`)**, updated after each findings load of a latest scan:
* seen finding -> `last_seen_at = scan time`, `first_seen_at = min(existing, first_found_at, scan time)`; reopened if previously resolved and open again.
* a finding in a **closed state/status** counts as resolved (burndown "closed", MTTR) even though it is still listed by the API.
* a finding missing from the newest scan is resolved **only if its engine provably ran** (engine status Completed in `scan_engine_status`,
  or the engine produced findings in that scan). A failed/skipped engine never creates false "fixes".
* Idempotent: re-running the same scan yields identical rows.

**Scans high-water mark** (only when `SYNC_SCAN_SELECTION=all`; the default `last_scan` mode is ADR 0013): `max(createdAt)` minus a 5-minute overlap, but never later than the oldest **unfinished** scan, so a long
running scan is re-polled until it reaches a final status (the spec's formula alone would skip it). When `CX_BRANCHES` changes the
stored branch list no longer matches and the next run backfills `SYNC_BACKFILL_DAYS` (catch-up for newly included branches).

**Branches:** exact, case-sensitive; `fnmatch` when the pattern contains `*`. With globs or no branch list, scans are fetched
unfiltered and matched locally; with exact names the API filters per branch.

**Findings reload:** the nightly job sets `findings_loaded=false` on latest scans; a reload deletes that scan's rows first, so findings
that disappeared do not linger. A failure mid-way leaves the scan unloaded and it is retried next cycle (errors are isolated per scan).

**Purge:** keep finding detail for the newest `FINDINGS_KEEP_SCANS_PER_BRANCH` final scans per (project, branch); counters are kept
indefinitely; scans/lifecycle of branches no longer configured are deleted.
