# Spec traceability

Maps the build spec (v1.0, 16 Oct 2026) to code, tests and ADRs. Status: Done / Partial / Deferred. Keep in step with the code.

## 2.1 Functional requirements
| # | Requirement | Status | Where | Tests |
|---|-------------|--------|-------|-------|
| 1 | Landing page: open by scanner x severity, totals, trend, top risky projects, scan health | Done | `ui/pages/overview.py`, `db/queries/overview.py` | `tests/ui/test_app.py`, e2e |
| 2 | Page per scanner (SAST, SCA, Containers, IaC, Secrets/API Security/SSCS) with breakdowns + grid | Done (SCA direct/transitive + network-vector toggle deferred, ADR 0012) | `ui/pages/*`, `components/scanner_page.py` | `test_scanner_pages_update` |
| 3 | Projects inventory: per-scanner counts, risk, last scan age, coverage | Done | `ui/pages/projects.py`, `queries/projects.py` | `test_projects_health_admin` |
| 4 | Global filters (application, project, tag, branch, scanner, severity, state, status, date, text) in URL | Done | `components/filter_bar.py`, `ui/state.py`, ADR 0010 | `test_ui_state.py`, e2e |
| 5 | Drill-down: KPI/chart click -> filtered grid -> drawer -> deep link | Done (deep-link pattern is an assumption) | `cross_filter.py`, `findings_grid.py`, `drawer.py`, `cx_client/deeplink.py` | e2e, `test_drawer_shows_detail_and_deeplink` |
| 6 | Aging, SLA breach, MTTR, burndown, new/recurring/fixed, coverage gaps | Done | `metrics/*`, `queries/findings.py`, `queries/projects.py` | `test_metrics.py`, `test_sync.py` lifecycle tests |
| 7 | Export tables CSV/XLSX, charts PNG, executive PDF | Done (PNG via Plotly modebar; PDF needs `pdf` extra) | `exporting.py`, `ui/exporters.py`, `executive.py` | `test_features.py` |
| 8 | Alerts and weekly digest (email/webhook) | Done | `alerts/*` | `test_features.py` |
| 9 | Admin page: sync runs, API errors, freshness, effective config (masked) | Done | `ui/pages/admin.py` | `test_projects_health_admin` |

## 2.2 Scope rules
| Topic | Status | Where |
|-------|--------|-------|
| Region/tenant/overrides in `.env` | Done | `config.py` (`CX_REGION`, `CX_TENANT`, `CX_BASE_URL`, `CX_IAM_URL`) |
| Auth method api_key / oauth_client | Done | `cx_client/auth.py` |
| Branches list (default master, dis-devinteg; empty = all; globs) | Done | `scope.py`, `sync/scans.py` |
| Open definition (closed states/statuses) | Done | `metrics/open_rules.py` |
| Read-only, `ENABLE_WRITEBACK` rejected | Done | `cx_client/http.py`, `config.py`, ADR 0002 |
| Secrets/SSCS licensed, toggled by `CX_ENGINES` | Done | `config.py`, normalisers, pages |

## 2.3 Non-functional
| Area | Status | Notes |
|------|--------|-------|
| Page p95 < 2 s up to 100k findings | Verified at 128k findings on PostgreSQL (all queries p95 < 0.9 s before the trend rewrite; trend is now O(scans+days)) | `devtools/loadtest.py`; re-run at 5,000 projects / 10M findings before go-live |
| Freshness 15 min | Configurable (`SYNC_SCANS_MINUTES`, default 10) | |
| Resilience | Done: UI reads local DB; client retries with backoff | |
| Security: SSO, secrets from env, audit log for exports | Done (OIDC/proxy); audit in `audit_log` | `docs/SECURITY_REVIEW.md` |
| Observability: JSON logs, `/healthz`, `/metrics`, sync lag | Done | `logging.py`, `ui/app.py`, `sync/jobs.py` |

## Sections 3-17
| Spec section | Status | Notes / deviations |
|--------------|--------|--------------------|
| 3 Stack | Done | Dash 4 (>=3 supported), SQLAlchemy 2, psycopg 3, APScheduler 3, Authlib; Redis optional; waitress added for Windows |
| 4 Layout | Done with deviations | `db/queries.py` -> package (ADR 0004); extra modules `container.py`, `cache.py`, `exporting.py`, `executive.py`, `cli.py`, `security/`, `devtools/` |
| 5 Configuration + validation | Done | All spec variables + additions (`CX_DEEPLINK_TEMPLATE`, `TRUSTED_PROXY_IPS`, `SESSION_*`, `METRICS_TOKEN`, `SCOPE_MAP_PATH`, `EXPORT_ROW_CAP`, `WORKER_METRICS_*`, `SYNC_REQUEST_POLL_SECONDS`, `ALERT_COOLDOWN_HOURS`, `REFRESH_RATE_LIMIT_SECONDS`, `WEB_*`) |
| 6 API client | Done | auth, retry, Retry-After, paging, GET-only guard, metrics, API-call counting |
| 7 Schema | Done + additions (ADR 0003) | `project.active`, `sync_request`, extra indexes |
| 8 Sync | Done; **default changed to last-scan selection** (ADR 0013) | jobs, advisory locks, purge, alerts chain; ADR 0005/0006/0007/0013. `backfill` only matters with `SYNC_SCAN_SELECTION=all` |
| 9 Metrics | Done | one open definition; risk percentile; SLA; MTTR; burndown; coverage; stale; fix-available % |
| 10 UI | Done (see 2.1 #2 for deferred widgets); redesigned with a reusable component library (ADR 0014) | sidebar shell, filter chips, stat cards with sparklines/deltas, dark mode, responsive; `dcc.Loading` placeholders; Redis cache keyed by version (ADR 0009) |
| 11 Exports | Done | formula-injection safe; audit log |
| 12 Security | Done; review in `docs/SECURITY_REVIEW.md` | minimum Checkmarx role set to be documented after testing (API_NOTES) |
| 13 Alerts | Done | all five rule kinds + digest; de-duplication via `alert_event` |
| 14 Deployment | Dockerfile + compose written; **not executed** (no Docker daemon on build machine) | `/healthz`, runbook |
| 15 Testing | Done; contract tests use synthetic fixtures (ADR 0011) | testcontainers replaced by `CXDASH_TEST_PG_URL`/`pgserver` |
| 16 Risks | Tracked in `docs/API_NOTES.md` | |
| 17 Milestones | All four implemented in one pass | Acceptance items needing a real tenant (reconciliation, real fixtures, 5,000-project load test) are open: `docs/RECONCILE.md` |
