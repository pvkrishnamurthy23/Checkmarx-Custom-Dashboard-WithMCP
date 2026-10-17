# Checkmarx One Security Dashboard

A read-only dashboard that consolidates **SAST, SCA, Containers, IaC (KICS), Secrets, API Security and SSCS** findings from
Checkmarx One in one place: open findings by scanner x severity, 90-day trend, risky projects, scan health, SLA breaches, coverage
gaps, drill-down to individual findings with a deep link back to Checkmarx One, exports, alerts and a weekly digest.

* It only ever **reads** from Checkmarx One (HTTP GET, plus the OAuth token request to the IAM host).
* A background worker copies data into PostgreSQL; the UI reads only the local database, so it stays usable if Checkmarx One is down.
* Every setting (region, tenant, credentials, branches, SLA days, ...) comes from `.env`. No secret is in the code.

> **Status:** feature-complete against the spec, tested on SQLite and PostgreSQL and in a real browser. The Checkmarx field mappings
> are based on the public API reference and **must be confirmed against your tenant** before you rely on the numbers
> ([docs/API_NOTES.md](docs/API_NOTES.md), [docs/RECONCILE.md](docs/RECONCILE.md)).

---

## 1. Quick start (demo data, no Checkmarx account needed) - Windows PowerShell

```powershell
cd D:\Project_Current\Checkmarx-Custom-Dashboard
python -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev]"

# .env already exists with placeholders and a local SQLite database (it is git-ignored)
.venv\Scripts\python -m cxdash.cli migrate
.venv\Scripts\python -m cxdash.cli seed-demo --projects 40     # SYNTHETIC data
.venv\Scripts\python -m cxdash.ui.app
```
Open <http://127.0.0.1:8050>. Linux/macOS: use `.venv/bin/python`, or `make install migrate seed-demo run`.

## 2. Connect to your Checkmarx One tenant

1. **Create credentials** in Checkmarx One: either an **API key** (Settings -> Identity and Access Management -> API keys) or an
   **OAuth client**. Give the service account read-only access (projects, applications, scans, scan summary, results). Document the
   minimum role set you end up with (spec section 12).
2. **Edit `.env`** (copy `.env.example` for the full list):
   ```ini
   CX_REGION=eu                  # us | us2 | eu | eu2 | deu | anz | ind | sng | mea
   CX_TENANT=your-tenant-name    # the tenant/realm in your Checkmarx One URL
   CX_AUTH_METHOD=api_key        # or oauth_client (then set CX_CLIENT_ID / CX_CLIENT_SECRET)
   CX_API_KEY=...                # never commit this file
   CX_BRANCHES=master,dis-devinteg
   DATABASE_URL=postgresql+psycopg://cx:<password>@localhost:5432/cxdash
   ```
   If your region is not listed, set both `CX_BASE_URL` and `CX_IAM_URL`.
3. **Check it:** `python -m cxdash.cli check-config` prints the effective configuration with secrets masked. Typos in `.env` fail at startup.
4. **Create the schema and load the latest scans:**
   ```powershell
   .venv\Scripts\python -m cxdash.cli migrate
   .venv\Scripts\python -m cxdash.cli backfill      # inventory, newest scan per project/branch, summaries, findings
   ```
   Re-running changes nothing (idempotent).
5. **Run continuously** (two processes):
   ```powershell
   .venv\Scripts\python -m cxdash.sync.scheduler    # the worker - run exactly one
   .venv\Scripts\python -m cxdash.ui.app            # the web UI (use gunicorn/waitress + a TLS proxy in production)
   ```
6. **Verify:** compare Overview counts with the Checkmarx One UI for ~10 projects ([docs/RECONCILE.md](docs/RECONCILE.md)).

## Keeping API calls low

By default the dashboard fetches **only the newest `Completed` scan per project and branch** (never the scan history):

| What | Calls |
|------|-------|
| Inventory (projects + applications), every `SYNC_INVENTORY_MINUTES` | `ceil(projects/100) + 1` (about 5 for 396 projects) |
| Newest scan per project, every `SYNC_SCANS_MINUTES` | `ceil(projects/50)` per branch (8 per branch for 396 projects) |
| Details, summary, findings for a *new* scan | about 1/50 + 1/20 + 1 per scan (one `results` call of up to 500 findings) |
| Unchanged scans | **0** |

Measured on the real tenant: 7 projects, first load = 17 calls; each later cycle = 2 calls. Rule of thumb for your 396 projects and two
branches: first load is about 80 calls plus roughly one call per project/branch that has a scan; steady state is 16 calls per cycle.

To go lower, in `.env`:
* `SYNC_SCANS_MINUTES=60` and `SYNC_INVENTORY_MINUTES=240` (about 400 calls/day at steady state).
* `SYNC_LOAD_FINDINGS=false` for **counters only**: no per-finding calls at all. Overview and scanner KPIs work from scan summaries; grids, SLA and aging are empty.
* `SYNC_MAX_API_CALLS_PER_RUN=500` (hard cap; the job stops and resumes next cycle). Keep `SYNC_NIGHTLY_FINDINGS_REFRESH=false`.
* `SYNC_KEEP_SCAN_HISTORY=false` if you do not want older scans stored (no trend).

Every sync prints its call count (`python -m cxdash.cli scans` shows `api_calls=`) and the Admin page lists calls per job.

"Full scan" here means status `Completed` (Partial, Failed and Canceled are ignored). Optionally `SYNC_FULL_SCANS_ONLY=true` also skips scans whose SAST
config says *incremental* and looks back for another one (extra calls; that flag is the configured mode, so projects scanned only by webhooks may end up with no scan).
Details and verified API behaviour: [ADR 0013](docs/adr/0013-api-call-economy-and-last-scan-selection.md), [docs/API_NOTES.md](docs/API_NOTES.md).

## 3. Using the dashboard

| Page | What you get |
|------|--------------|
| **Overview** | Critical/High/Medium/Low/total open, SLA breaches, coverage gaps, scanner x severity heatmap, scanner donut, 90-day trend, top-10 risky projects, scans in the last 7 days |
| **SAST / SCA / Containers / IaC / Secrets & API Security** | Scanner-specific breakdowns (top queries, CWE, OWASP, packages, CVEs, CVSS, fixable, images, platforms, secret types...) and a findings grid |
| **Projects** | Per-project open counts per scanner, risk score (0-100), last scan age, coverage; click a row for trend + top findings |
| **Scan Health** | Success rate, duration percentiles, engine failures, stale projects, projects missing an engine |
| **Executive** | One-page summary; **Export PDF** (needs the `pdf` extra) or printable HTML |
| **Admin** (admin role) | Sync runs, data freshness, API calls, effective config (masked), manual sync, users, alert rules, audit log |

* **Navigation:** left sidebar (Overview, scanners, Projects, Scan Health, Executive, Admin); it collapses to an icon rail on narrow screens. The sun/moon switch at the
  bottom toggles dark mode. The top bar shows the last sync time, a Refresh button and who you are.
* **Filters** (sticky bar): search plus application, project, branch, scanner and severity are always visible; **More** reveals tag, state, status and date range (a badge counts
  what is applied there). Every active filter also appears as a **chip** under the bar: click a chip to remove it. Filters apply to every chart and table and live in the URL, so a
  view can be bookmarked or shared. **Click** a KPI card, chart bar/slice or heatmap cell to filter; click again to clear.
* **KPI cards** on the Overview show a 30-day sparkline and the change versus 7 days ago (red = more findings).
* **Findings grid:** server-side paging/sorting/column filters, column chooser, click a row for the **detail drawer** (all fields, age/SLA badge, raw JSON,
  *Open in Checkmarx One* link). By default it lists *open* findings; pick states/statuses to include closed ones.
* **Exports** (analyst or admin; every export is audit-logged): CSV (streamed, UTF-8 BOM), XLSX (summary + data sheets), chart PNG (camera icon on each chart),
  selection export, executive PDF. Spreadsheet formulas in data are neutralised.
* **Saved views** and a **Refresh** button (queues a sync; once a minute per user). Light/dark theme switch in the header.
* **What counts as open:** every state except `CX_CLOSED_STATES` (default `NOT_EXPLOITABLE`) and status `FIXED`. `PROPOSED_NOT_EXPLOITABLE` is open unless you add it.

## 4. Configuration reference (most used)

| Variable | Meaning |
|----------|---------|
| `CX_BRANCHES` | Branches to sync and show; comma list, globs (`release/*`) allowed; empty = all branches |
| `CX_ENGINES` | Engines to include (`sast,sca,containers,kics,secrets,apisec,sscs`) |
| `CX_CLOSED_STATES` / `CX_CLOSED_STATUSES` | What does **not** count as open |
| `CX_PROJECT_NAME_REGEX`, `CX_PROJECT_TAGS`, `CX_APPLICATIONS` | Limit which projects are in scope |
| `SYNC_*`, `CX_PAGE_SIZE`, `CX_MAX_CONCURRENCY`, `CX_MAX_RETRIES` | Sync cadence and API politeness |
| `SLA_DAYS_*`, `RISK_WEIGHT_*`, `STALE_PROJECT_DAYS` | Metric definitions |
| `AUTH_MODE` | `none` (local dev only), `oidc`, `proxy_headers` (see section 6) |
| `REDIS_URL` | Optional shared query cache |
| `CX_DEEPLINK_TEMPLATE` | Portal link pattern; confirm in your portal and adjust without code changes |

All variables, with comments, are in [.env.example](.env.example).

## 5. Alerts and weekly digest

Create rules with the CLI (they run after every scans cycle; duplicates are suppressed for `ALERT_COOLDOWN_HOURS`). Use `--param KEY=VALUE`
(repeatable, PowerShell-friendly; commas make a list) or `--params '<json>'`:
```powershell
python -m cxdash.cli alert-add --name "New high+" --kind new_severity --param severity=HIGH --channel webhook
python -m cxdash.cli alert-add --name "Crit threshold" --kind threshold --param engine=sast --param severity=CRITICAL --param count=20
python -m cxdash.cli alert-add --name "Weekly" --kind weekly_digest --param "cron=0 8 * * 1" --param recipients=a@example.com,b@example.com --channel both
```
Kinds: `new_severity`, `sla_breach`, `scan_failed`, `stale_project`, `threshold`, `weekly_digest`. Channels: `email` (set `SMTP_*`, `ALERT_EMAIL_FROM`),
`webhook` (set `ALERT_WEBHOOK_URL`; Slack/Teams compatible), `both`. Rules are listed read-only on the Admin page.

## 6. Production

```powershell
$env:POSTGRES_PASSWORD = "<generated>"      # also use it inside DATABASE_URL in .env
docker compose up -d --build                # db, redis, migrate, web, worker
```
* Put the web service behind a TLS-terminating reverse proxy. Choose an auth mode:
  * `proxy_headers` - your proxy does SSO and sets `X-Forwarded-User` / `X-Forwarded-Groups`; set `TRUSTED_PROXY_IPS` to the proxy.
  * `oidc` - set `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `SESSION_SECRET` (>= 32 random chars), `ROLE_ADMIN_GROUPS`, `ROLE_ANALYST_GROUPS`.
* Roles: **viewer** (all pages but Admin), **analyst** (+ exports, saved views, refresh), **admin** (+ Admin page, `/metrics`).
* Optional row-level scoping: set `SCOPE_MAP_PATH` to a `scope_map.yaml` (`group: [Application name, ...]`).
* Run **exactly one** worker. `/healthz` reports DB connectivity and sync age (alert if older than 3 x the scan interval); `/metrics` is Prometheus text
  (needs `METRICS_TOKEN` or the admin role). The worker exposes its own metrics on `WORKER_METRICS_PORT`.
* Operations guide: [docs/RUNBOOK.md](docs/RUNBOOK.md).

## 7. Development

```powershell
.venv\Scripts\python -m pytest                      # unit, client, integration (SQLite), UI callbacks
.venv\Scripts\python -m pytest -m integration       # PostgreSQL (CXDASH_TEST_PG_URL, or `pip install -e ".[pg-embedded]"` for an embedded server)
.venv\Scripts\python -m pip install -e ".[e2e]" ; .venv\Scripts\python -m playwright install chromium
.venv\Scripts\python -m pytest -m e2e               # real-browser tests
.venv\Scripts\python -m ruff check src tests ; .venv\Scripts\python -m mypy src/cxdash ; .venv\Scripts\python -m bandit -q -r src -c pyproject.toml
```
Project conventions, architecture and decisions: `CLAUDE.md` (local), [docs/adr/](docs/adr/), [docs/TRACEABILITY.md](docs/TRACEABILITY.md),
[docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md), [docs/PROMPTS.md](docs/PROMPTS.md).

## 8. Troubleshooting

| Symptom | Likely cause / fix |
|---------|--------------------|
| Startup error naming a variable | `.env` validation (typo, missing key, bad region). `check-config` shows the details |
| Sync runs `failed` with `token request failed with HTTP 4xx` | Wrong tenant/region/API key; set `CX_IAM_URL` if your IAM host differs |
| Overview empty | Worker not running or `CX_BRANCHES` matches no scans; see Admin -> Sync runs |
| Counts differ from the Checkmarx UI | Follow docs/RECONCILE.md; check `CX_CLOSED_STATES`, branches, and the API-field assumptions in docs/API_NOTES.md |
| "Open in Checkmarx One" link 404s | Adjust `CX_DEEPLINK_TEMPLATE` to your portal's URL pattern |
| PDF export returns 501 | `pip install -e ".[pdf]"` (WeasyPrint needs pango) or use the printable HTML |
| `.env` rejected with an unknown key | Remove variables not in `.env.example` (e.g. `POSTGRES_*`) |
