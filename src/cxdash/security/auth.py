"""Dashboard authentication (spec section 12): AUTH_MODE = none | oidc | proxy_headers.

Strategy pattern: each mode is an ``Authenticator``; ``install_security`` wires the chosen
one into Flask. Nothing here touches Checkmarx One credentials.
"""

from __future__ import annotations

import hmac
import ipaddress
import logging
import time
from typing import Any, Protocol, cast
from urllib.parse import urlsplit

from flask import Flask, Request, abort, g, jsonify, redirect, request, session, url_for
from werkzeug.wrappers import Response

from cxdash.config import Settings
from cxdash.security.principal import ANONYMOUS_DEV, Principal, RoleMapper, ScopeMap

log = logging.getLogger(__name__)

PUBLIC_PATHS = ("/healthz", "/login", "/auth/callback", "/assets/", "/_favicon.ico")
MAX_GROUPS = 200
SESSION_MAX_AGE_SECONDS = 12 * 3600


class Authenticator(Protocol):
    def authenticate(self, req: Request) -> Principal | None: ...


class NoAuth:
    def authenticate(self, req: Request) -> Principal | None:
        return ANONYMOUS_DEV


class ProxyHeaderAuth:
    """Trusts X-Forwarded-User/-Groups ONLY when the TCP peer is a configured trusted proxy."""

    def __init__(self, settings: Settings, roles: RoleMapper, scope: ScopeMap) -> None:
        self._nets = [ipaddress.ip_network(x, strict=False) for x in settings.trusted_proxy_ips]
        self._roles, self._scope = roles, scope

    def _trusted(self, peer: str | None) -> bool:
        try:
            ip = ipaddress.ip_address(peer or "")
        except ValueError:
            return False
        return any(ip in n for n in self._nets)

    def authenticate(self, req: Request) -> Principal | None:
        if not self._trusted(req.remote_addr):
            log.warning("forwarded identity rejected: untrusted peer", extra={"peer": req.remote_addr})
            return None
        user = (req.headers.get("X-Forwarded-User") or "").strip()
        if not user or len(user) > 256:
            return None
        groups = [x.strip() for x in (req.headers.get("X-Forwarded-Groups") or "").split(",") if x.strip()][
            :MAX_GROUPS
        ]
        role = self._roles.role_for(groups)
        return Principal(
            user,
            (req.headers.get("X-Forwarded-Email") or "").strip() or None,
            role,
            self._scope.applications_for(groups, role),
        )


class SessionAuth:
    """OIDC: identity is established at /auth/callback and kept in the signed session cookie."""

    def authenticate(self, req: Request) -> Principal | None:
        data = session.get("principal")
        if not isinstance(data, dict):
            return None
        if time.time() - float(data.get("iat", 0)) > SESSION_MAX_AGE_SECONDS:
            session.clear()  # server-enforced lifetime: a stolen cookie cannot live forever
            return None
        scope = data.get("scope")
        return Principal(
            str(data["user_id"]),
            data.get("email"),
            str(data["role"]),
            tuple(scope) if scope is not None else None,
        )


def safe_next(target: str | None) -> str:
    """Only same-site relative paths are accepted (prevents open redirects)."""
    if not target:
        return "/"
    parts = urlsplit(target)
    if (
        parts.scheme
        or parts.netloc
        or not target.startswith("/")
        or target.startswith("//")
        or "\\" in target
    ):
        return "/"
    return target


def principal_session_data(
    claims: dict[str, Any], group_claim: str, roles: RoleMapper, scope: ScopeMap
) -> dict[str, Any] | None:
    """Map verified ID-token claims to what is stored in the session; ``None`` if there is no subject."""
    sub = str(claims.get("sub") or "")
    if not sub:
        return None
    raw_groups = claims.get(group_claim) or []
    groups = [str(x) for x in (raw_groups if isinstance(raw_groups, list) else [raw_groups])][:MAX_GROUPS]
    role = roles.role_for(groups)
    apps = scope.applications_for(groups, role)
    return {
        "user_id": sub, "email": claims.get("email"), "role": role, "iat": int(time.time()),
        "scope": list(apps) if apps is not None else None,
    }  # fmt: skip


def _same_origin(req: Request) -> bool:
    """Defence in depth against CSRF: a browser always sends Origin on cross-site POSTs."""
    origin = req.headers.get("Origin")
    if not origin:
        return True  # non-browser clients (curl, Prometheus) and same-origin form posts in older browsers
    return urlsplit(origin).netloc == req.host


def current_principal() -> Principal:
    p = getattr(g, "principal", None)
    if not isinstance(p, Principal):
        abort(401)
    return p


def require_role(required: str) -> Principal:
    p = current_principal()
    if not p.has_role(required):
        abort(403)
    return p


def build_authenticator(settings: Settings) -> Authenticator:
    roles = RoleMapper.from_settings(settings)
    scope = ScopeMap.load(settings.scope_map_path)
    if settings.auth_mode == "proxy_headers":
        return ProxyHeaderAuth(settings, roles, scope)
    if settings.auth_mode == "oidc":
        return SessionAuth()
    return NoAuth()


def _security_headers(settings: Settings, resp: Response) -> Response:
    # Dash's renderer needs inline bootstrap script + eval; everything else stays locked down (ADR 0008).
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
        "base-uri 'self'; form-action 'self'; object-src 'none'",
    )
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    resp.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    resp.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    if settings.session_cookie_secure and settings.auth_mode != "none":
        resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    if request.path.startswith(("/export", "/login", "/auth", "/_dash-update-component")):
        resp.headers["Cache-Control"] = "no-store"
    return resp


def install_security(
    server: Flask, settings: Settings, authenticator: Authenticator, record_login=None
) -> None:
    """Attach cookies config, auth gate, security headers and (for oidc) the login routes."""
    server.config.update(
        SECRET_KEY=settings.session_secret.get_secret_value() or None,
        SESSION_COOKIE_SECURE=settings.session_cookie_secure and settings.auth_mode != "none",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        MAX_CONTENT_LENGTH=2 * 1024 * 1024,
    )

    @server.before_request
    def _gate() -> Response | None:
        if request.method not in ("GET", "HEAD", "OPTIONS") and not _same_origin(request):
            return Response("cross-origin request rejected", 403)
        if request.path.startswith(PUBLIC_PATHS):
            g.principal = ANONYMOUS_DEV if settings.auth_mode == "none" else None
            return None
        if request.path == "/metrics" and settings.metrics_token.get_secret_value():
            return None  # the route verifies its own bearer token (Prometheus cannot do SSO)
        principal = authenticator.authenticate(request)
        if principal is None:
            if (
                settings.auth_mode == "oidc"
                and request.method == "GET"
                and not request.path.startswith("/_dash")
            ):
                return redirect(url_for("login", next=request.full_path.rstrip("?")))
            return Response("authentication required", 401)
        g.principal = principal
        return None

    @server.after_request
    def _headers(resp: Response) -> Response:
        return _security_headers(settings, resp)

    if settings.auth_mode == "oidc":
        _install_oidc(server, settings, record_login)

    if settings.auth_mode == "none":
        log.warning("AUTH_MODE=none: every visitor is an admin. Do not expose this instance.")


def _install_oidc(server: Flask, settings: Settings, record_login) -> None:
    from authlib.integrations.flask_client import OAuth

    roles = RoleMapper.from_settings(settings)
    scope = ScopeMap.load(settings.scope_map_path)
    oauth = OAuth(server)
    oauth.register(
        "idp",
        server_metadata_url=f"{settings.oidc_issuer.rstrip('/')}/.well-known/openid-configuration",
        client_id=settings.oidc_client_id,
        client_secret=settings.oidc_client_secret.get_secret_value(),
        client_kwargs={"scope": "openid email profile", "code_challenge_method": "S256"},
    )

    @server.route("/login")
    def login() -> Response:
        session["next"] = safe_next(request.args.get("next"))
        return cast(Response, oauth.idp.authorize_redirect(url_for("auth_callback", _external=True)))

    @server.route("/auth/callback")
    def auth_callback() -> Response:
        token = oauth.idp.authorize_access_token()
        claims = token.get("userinfo") or {}
        data = principal_session_data(claims, settings.oidc_group_claim, roles, scope)
        if data is None:
            abort(401)
        target = safe_next(session.pop("next", "/"))
        session.clear()  # new session on login (fixation defence)
        session["principal"] = data
        session.permanent = False
        if record_login:
            record_login(data["user_id"], data["email"], data["role"])
        return redirect(target)

    @server.post("/logout")
    def logout() -> Response:
        session.clear()
        return redirect("/")


def install_ops_routes(server: Flask, settings: Settings, health, metrics_render) -> None:
    """/healthz (public, minimal) and /metrics (token or admin only)."""

    @server.get("/healthz")
    def healthz() -> tuple[Response, int]:
        body = health()
        return jsonify(body), 503 if body.get("status") == "error" else 200

    @server.get("/metrics")
    def metrics() -> Response:
        token = settings.metrics_token.get_secret_value()
        if token:
            supplied = (request.headers.get("Authorization") or "").removeprefix("Bearer ").strip()
            if not hmac.compare_digest(supplied, token):
                abort(401)
        elif settings.auth_mode != "none":
            require_role("admin")
        body, content_type = metrics_render()
        return Response(body, mimetype=content_type.split(";")[0])
