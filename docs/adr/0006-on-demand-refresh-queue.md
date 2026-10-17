# 0006. On-demand refresh through a database queue

- **Status:** Accepted
- **Date:** 2026-10-16
- **Spec reference:** 10.1 (Refresh button), 8 (worker is a separate process), 14.2

## Context
The header Refresh button must "queue an on-demand scans+summaries run (rate-limited to once per minute per user)". The web
app and the worker are separate processes and the web app must never call Checkmarx One itself.

## Decision
The web app inserts a row into `sync_request` (job `scans`, or `inventory`/`full` from the Admin page). The worker polls every
`SYNC_REQUEST_POLL_SECONDS`, claims pending rows (`picked_at`), and runs the normal scans cycle once for all of them. The rate
limit is enforced per user from `sync_request.requested_at`. Every request is audit-logged. Redis/Celery is not required.

## Consequences
* A refresh is global (the whole configured scope), not per filter: scans are discovered per branch/project, not per UI filter.
  Running the same idempotent cycle is cheaper and simpler than a filtered partial sync.
* Latency is bounded by the poll interval (default 30 s) plus sync time.
