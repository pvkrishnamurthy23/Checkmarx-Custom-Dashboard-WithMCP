# Runbook

## Components
| Process | Command | Notes |
|---------|---------|-------|
| migrate | `python -m cxdash.cli migrate` | run before web/worker on every release |
| web | `gunicorn -w 4 -b 0.0.0.0:8050 cxdash.ui.app:server` (Linux) / `waitress-serve --port 8050 cxdash.ui.app:server` (Windows) | stateless, scale horizontally |
| worker | `python -m cxdash.sync.scheduler` | exactly one; advisory locks make an accidental second one skip jobs |
| PostgreSQL 16 | | back up daily; data is reproducible from Checkmarx One, RPO not critical |
| Redis (optional) | | shared query cache; failures degrade to uncached |

## Health and monitoring
* `GET /healthz` -> `{"status": "ok|degraded|error", "db": "up|down", "last_sync_age_seconds": n, "sync_stale": bool}`.
  `degraded` = last successful scans cycle older than 3 x `SYNC_SCANS_MINUTES` -> **alert**. `error` (HTTP 503) = database unreachable.
* `GET /metrics` (web; `METRICS_TOKEN` bearer or admin role) and the worker's `WORKER_METRICS_HOST:WORKER_METRICS_PORT`:
  `cx_api_requests_total{endpoint,status}`, `cx_api_latency_seconds`, `cxdash_sync_runs_total{job,status}`, `cxdash_sync_records_total`,
  `cxdash_sync_lag_seconds`. Suggested alerts: `cxdash_sync_lag_seconds > 3 * scan interval`, rising `status="failed"` runs, 429/5xx bursts.
* Logs are JSON on stdout; secrets and bearer tokens are redacted; raw findings are never logged at INFO.
* Admin page: sync runs, errors, API calls, freshness, masked config.

## Routine operations
| Task | How |
|------|-----|
| Force a refresh | Header **Refresh** (analyst) or Admin -> *Sync scans now* / *Full refresh*; or `python -m cxdash.cli scans` |
| First load / re-backfill | `python -m cxdash.cli backfill` |
| Add a branch | Edit `CX_BRANCHES`, restart worker: the next scans run backfills `SYNC_BACKFILL_DAYS` for the new set |
| Remove a branch | Edit `CX_BRANCHES`; hidden immediately by query filters, deleted by the nightly purge |
| Change what is "open" | Edit `CX_CLOSED_STATES` / `CX_CLOSED_STATUSES`, restart; counters re-derive at the next nightly full refresh (or Admin -> Full refresh) |
| Rotate the API key | Update the secret, restart the worker (token cache is in memory) |
| Upgrade | pull, `pip install -e .` / rebuild image, `migrate`, restart web then worker |
| Reset the dev database | delete `cxdash-dev.db`, `migrate`, `seed-demo` |

## Troubleshooting sync
| Run error | Meaning / action |
|-----------|------------------|
| `AuthError: token request failed with HTTP 400/401` | wrong tenant/API key/client; confirm `CX_TENANT`, region and `CX_IAM_URL` |
| `AuthError: token endpoint unreachable` | network/proxy to the IAM host |
| `ApiError: ... HTTP 403` | service account lacks a read role (see docs/API_NOTES.md) |
| `ApiError: ... HTTP 429/5xx` after retries | Checkmarx throttling/outage: lower `CX_MAX_CONCURRENCY`, raise `SYNC_*` intervals; retried automatically next cycle |
| `JobError: n/m scans failed` | per-scan isolation: good scans are kept, failed ones retried next cycle; see the first error text |
| Job status `skipped` | another instance holds the lock (normal during overlap) |
| Worker logs `closed orphaned sync runs` | the worker crashed or was killed mid-run; benign |

## Security operations
* `AUTH_MODE=none` is for local development only (logs a warning on every start). Never expose it.
* Review `audit_log` (Admin page) for exports and manual syncs. Rotate `SESSION_SECRET`/`METRICS_TOKEN` by editing the environment and restarting.
* Scheduled hygiene: `pip-audit` and `bandit` (CI runs them), gitleaks pre-commit hook, rebuild the image regularly for base-image patches.

## Vendored asset provenance
`src/cxdash/ui/assets/10-bootstrap.min.css` = Bootstrap 5.3.3 (MIT) from `cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css`,
sha256 `3c8f27e6009ccfd710a905e6dcf12d0ee3c6f2ac7da05b0572d3e0d12e736fc8`.

## Load test
`python -m cxdash.devtools.loadtest --projects 500 --findings-per-engine 35 --runs 10` on a throw-away PostgreSQL (URL must contain `demo` or `load`).
Seeding is single-threaded Python and slow (about 2.5 minutes for 128k findings); for 5,000 projects / 10M findings generate with several processes or
bulk-copy. Measured at 128k findings on PostgreSQL 16: all page queries p95 < 0.9 s (budget 2 s). Re-run at full scale and tune indexes before go-live.
