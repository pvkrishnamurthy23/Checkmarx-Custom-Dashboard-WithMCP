# 0002. Read-only Checkmarx client (GET-only guard)

- **Status:** Accepted
- **Date:** 2026-10-16
- **Spec reference:** 1, 2.2 (write-back), 6.2, 6.3

## Context
The dashboard must never change anything in Checkmarx One. The only non-GET request the process may make is the OAuth
token request to the IAM host.

## Decision
* `CheckmarxHttpClient` exposes `get()` and `paged()` only. Its `httpx.AsyncClient` has a request event hook that raises
  `ReadOnlyViolation` for any method other than GET, so a future bug (or a direct use of the private client) still cannot write.
* The token POST lives in `TokenManager`, which uses a **separate** client bound to the IAM URL. It is strategy-driven
  (`ApiKeyStrategy`, `ClientCredentialsStrategy`) so adding an auth method does not touch the manager.
* One shared `asyncio.Lock` serialises refreshes; a 401 invalidates only the token that was rejected, refreshes once, retries once.
* Retry (tenacity): connection errors, 429, 500/502/503/504, exponential backoff with jitter 1-30 s, `Retry-After` honoured (capped at 120 s).
* `ENABLE_WRITEBACK=true` is a startup error in v1.
* Sync jobs depend on the `CheckmarxReader` protocol, never on the HTTP client.

## Consequences
Tests assert every verb that reaches `CX_BASE_URL` is GET (`tests/unit/test_cx_client.py`). Any future triage feature needs a new ADR
and a separate, explicitly named write client.

## Alternatives considered
A single client with a verb allow-list: rejected because the token POST would then need an exception inside the guard.
