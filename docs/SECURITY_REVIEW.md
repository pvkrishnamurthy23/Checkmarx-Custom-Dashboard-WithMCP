# Security review

- **Date:** 2026-10-16 - **Scope:** all code in `src/`, `migrations/`, Dockerfile, compose, CI, pre-commit - **Version:** 1.0.0
- **Method:** manual code review against the checklist below + automated tools. Update this file whenever security-relevant code changes.

## Tooling results
| Tool | Result |
|------|--------|
| `bandit -r src` | 0 issues (one `# nosec B311` on the synthetic-data RNG in `devtools/seed.py`, not security-relevant) |
| `pip-audit` | No known vulnerabilities in installed dependencies |
| `ruff` security rules (`S`) | clean (tests exempt only for fake credentials) |
| Secret scan (grep for literals, keys, JWTs, AWS keys) | none in code, tests, docs, compose, CI. `gitleaks` is wired as a pre-commit hook (not executed locally) |
| `.gitignore` check | `.env*` (except `.env.example`), `CLAUDE.md`, `CLAUDE.local.md`, `.claude/`, `.mcp.json`, `scope_map.yaml`, `*.db` are ignored |

## Findings fixed during review
| # | Severity | Finding | Fix | Regression test |
|---|----------|---------|-----|-----------------|
| 1 | Medium | `REDIS_URL` (may embed a password) was shown unmasked on the Admin page | now `SecretStr`, masked | `test_redis_url_is_masked_in_effective_config` |
| 2 | Medium | Worker Prometheus endpoint bound to all interfaces | `WORKER_METRICS_HOST` defaults to `127.0.0.1` | config default; documented |
| 3 | Medium | No CSRF defence-in-depth for state-changing requests behind header-SSO | Origin must match Host on every non-GET request | `test_cross_origin_posts_are_rejected` |
| 4 | Low | A URL with > 100 query fields raised an unhandled `ValueError` (500 per page load) | codec treats it as "no filters" | `test_value_count_is_capped` |
| 5 | Low | PDF renderers could fetch external resources / run JS | WeasyPrint `url_fetcher` denies everything; Playwright context has JS disabled | n/a (no PDF engine in CI) - review only |
| 6 | Low | OIDC session had no server-side lifetime | `iat` + 12 h max age enforced | `test_oidc_session_principal_and_expiry` |
| 7 | Functional | Chart/KPI click handlers fired on first render and applied a filter | ignore falsy trigger values | browser test `test_kpi_click_filters_and_round_trips_through_url` |

## Checklist
| Area | Result | Evidence |
|------|--------|----------|
| **Secrets in code/logs** | OK | `SecretStr` everywhere; `RedactingFilter` masks configured values, bearer tokens and `key=value` secrets; `httpx` logs silenced; exceptions from the client carry status only; token errors never echo bodies (`test_token_failure_raises_auth_error_without_credentials`, `test_logging_redacts_secrets_and_tokens`); CLI failure run printed no secret |
| **Write access to Checkmarx** | OK | GET-only wrapper + request hook; test asserts verbs; token POST goes to IAM host only |
| **SQL injection** | OK | SQLAlchemy expressions with bound parameters; sort/filter/breakdown/facet columns are whitelists; `LIKE` input escaped; grid filter model validated per column; `test_grid_inputs_cannot_inject_sql` |
| **Formula (CSV/XLSX) injection** | OK | `sanitize_cell` prefixes `'` for `= + - @ TAB CR LF`; tested for CSV, XLSX and selection export |
| **XSS** | OK | React renders all strings as text; no `dangerously_allow_html`/Markdown of finding data; alert HTML is autoescaped (tested); CSP present |
| **Authentication** | OK (see limits) | none/proxy/oidc strategies; proxy identity only from trusted peers, spoofing tested; OIDC auth-code + PKCE (Authlib validates state, nonce, signature, issuer/audience); session reset on login; Secure/HttpOnly/SameSite=Lax cookies |
| **Authorisation** | OK | role checks server-side in routes and callbacks; exports analyst+, Admin/metrics admin; viewer cannot export (tested) |
| **Row-level scoping** | OK | injected server-side, never from client state; admins unrestricted; scoped user without mapping sees nothing; client-chosen application cannot widen scope (tested incl. exports) |
| **Open redirect** | OK | `safe_next` allows only same-site relative paths (tested with 8 hostile inputs) |
| **CSRF** | OK | SameSite=Lax + JSON-only Dash POSTs without CORS + Origin check |
| **Session handling** | OK | signed cookie holds id/role/scope only; 12 h server-enforced lifetime; `SESSION_SECRET` >= 32 chars enforced |
| **SSRF** | OK | server only calls operator-configured URLs (Checkmarx base/IAM, SMTP, webhook); redirects disabled on API and webhook clients; PDF renderer fetching denied |
| **Deserialisation** | OK | no pickle; cache is JSON; YAML via `safe_load` (tested against a `!!python/object` payload) |
| **Header injection** | OK | email subject CR/LF stripped, recipients regex-validated (tested) |
| **DoS / resource use** | Acceptable | request body capped at 2 MB; page size capped at 1000; export row cap; filter values/lists length-capped; exports are role-gated but not rate-limited |
| **Transport** | By deployment | TLS terminates at the reverse proxy; HSTS emitted when cookies are Secure |
| **Container/deploy** | OK | non-root user, read-only root FS, `no-new-privileges`, port bound to loopback, Postgres password required (no default) |
| **Dependencies** | OK | `pip-audit` clean today; CI runs it on every push; pin/refresh regularly |
| **Logging of findings** | OK | no raw payloads logged; unknown types logged by type name only |

## Accepted residual risks
1. **CSP allows `'unsafe-inline'` and `'unsafe-eval'` for scripts.** Dash's renderer bootstrap requires them. Mitigated by no third-party origins, no HTML injection paths and `object-src 'none'`. Revisit when Dash supports nonces.
2. **`CX_PROJECT_NAME_REGEX` is an operator-supplied regular expression** run against project names from the tenant (trusted data, config is trusted). A pathological pattern could be slow.
3. **`AUTH_MODE=none` makes every visitor an admin.** Intended for local development only; logs a warning at startup; never expose it.
4. **Exports are not rate-limited** beyond role + row cap + audit log.
5. **CI uses a throw-away literal Postgres password** (`ci-only-password`) for the ephemeral service container; it protects nothing.
6. **Proxy mode trusts the proxy**: anyone who can reach the web port directly from a trusted IP can assert any identity. Keep the web port reachable only through the proxy.

## Not verified in this review (do before go-live)
* The OIDC callback against a real identity provider (claims mapping is unit-tested; the redirect/token exchange is Authlib's).
* TLS, HSTS and cookie `Secure` behaviour behind your real reverse proxy.
* `docker compose up` (Docker was unavailable on the build machine) and the hardened container settings.
* WeasyPrint/Playwright PDF path (hardening is by code review only).
* Penetration test / DAST of a deployed instance.
