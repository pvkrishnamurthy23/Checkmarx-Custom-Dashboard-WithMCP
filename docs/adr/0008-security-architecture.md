# 0008. Dashboard security architecture

- **Status:** Accepted
- **Date:** 2026-10-16
- **Spec reference:** 5.2, 12; see `docs/SECURITY_REVIEW.md` for the review itself

## Decision
* **No secret in code or repo.** All credentials come from the environment/`.env` (git-ignored) into `SecretStr` fields; the Admin
  page and logs mask them; `.env.example` has no values; pre-commit runs gitleaks and `detect-private-key`.
* **Auth modes (strategy pattern):** `none` (dev only, warns, everyone is admin), `proxy_headers` (identity headers honoured only when the
  TCP peer is in `TRUSTED_PROXY_IPS`; never `X-Forwarded-For`), `oidc` (Authlib, auth-code + PKCE S256, signed cookie, 12 h server-enforced
  lifetime, session reset on login, `next` restricted to same-site paths).
* **Roles:** viewer < analyst (exports, saved views, refresh) < admin (Admin page, manual sync, `/metrics`). Enforced server-side in
  Flask routes and in callbacks; UI hiding is cosmetic only.
* **Row-level scoping:** optional `scope_map.yaml` (group -> application names, `yaml.safe_load`); admins unrestricted; a scoped user
  with no mapped group sees nothing. Applied in `ScopeResolver`, exports and the drawer queries.
* **CSRF:** SameSite=Lax cookies, JSON-only Dash POSTs (no CORS), plus an Origin check on every non-GET request.
* **Headers:** CSP (`default-src 'self'`, `frame-ancestors 'none'`, `object-src 'none'`), nosniff, DENY framing, Referrer-Policy,
  Permissions-Policy, HSTS (when cookies are Secure). CSP keeps `'unsafe-inline'`/`'unsafe-eval'` for scripts because Dash's renderer bootstrap
  needs them; everything else is locked down and no third-party origin is allowed.
* **Output safety:** CSV/XLSX cells that start with `= + - @ TAB CR` are prefixed with `'`; alert HTML is Jinja-autoescaped; the drawer
  renders finding text through React (never `dangerously_allow_html`); email headers are CR/LF-stripped; PDF rendering denies external fetches
  and (Playwright fallback) disables JS.
* **Ops endpoints:** `/healthz` is public and minimal; `/metrics` needs `METRICS_TOKEN` or the admin role (open only in `none` mode).
* **Container:** non-root user, read-only root FS, `no-new-privileges`, Postgres password required from the environment.

## Consequences
Accepted residual risks (CSP script relaxations, exports are not rate-limited beyond role + row cap, `CX_PROJECT_NAME_REGEX` is an
operator-supplied regex) are listed in `docs/SECURITY_REVIEW.md`.
