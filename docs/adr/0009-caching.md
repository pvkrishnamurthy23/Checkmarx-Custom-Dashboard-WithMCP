# 0009. Query cache keyed by data version

- **Status:** Accepted
- **Date:** 2026-10-16
- **Spec reference:** 10.3 (Performance), 3 (Redis optional)

## Decision
`QueryCache` keys entries by `(query id, filter fingerprint, data version)`. The data version is the end time of the last successful
`scans` run, so every sync invalidates by construction (no purge job, no pub/sub). Backend is Redis when `REDIS_URL` is set, otherwise an
in-process TTL cache; TTL equals the scan sync interval. Values are JSON (never pickle: a compromised Redis must not become code
execution), so only JSON-safe aggregates are cached (overview bundle, trend, top projects). The filter fingerprint includes the
caller's row-level scope so users never share entries across scopes. Redis failures degrade to uncached.

## Consequences
Datetime-bearing results (grids, project table) are not cached; they are paged/indexed SQL. The version lookup is itself cached for 10 s.
