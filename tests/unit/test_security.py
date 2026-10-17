from __future__ import annotations

import time

import pytest
from flask import Flask, g, jsonify

from cxdash.security.auth import (
    SESSION_MAX_AGE_SECONDS,
    build_authenticator,
    install_ops_routes,
    install_security,
    principal_session_data,
    require_role,
    safe_next,
)
from cxdash.security.principal import RoleMapper, ScopeMap
from tests.conftest import make_settings


def make_app(**settings_kw):
    s = make_settings(**settings_kw)
    app = Flask(__name__)
    install_security(app, s, build_authenticator(s))
    install_ops_routes(app, s, lambda: {"status": "ok"}, lambda: (b"m 1\n", "text/plain; version=0.0.4"))

    @app.get("/who")
    def who():
        p = g.principal
        return jsonify(user=p.user_id, role=p.role, scope=p.scope_applications)

    @app.get("/admin-only")
    def admin_only():
        require_role("admin")
        return "ok"

    return app


PROXY = {
    "auth_mode": "proxy_headers",
    "trusted_proxy_ips": "10.0.0.0/8, 192.168.1.5",
    "role_admin_groups": "sec-admins",
    "role_analyst_groups": "sec-analysts",
}


def hdrs(user="alice", groups="", **extra):
    h = {"X-Forwarded-User": user, "X-Forwarded-Groups": groups}
    h.update(extra)
    return h


def test_none_mode_is_admin_dev_user():
    r = make_app().test_client().get("/who")
    assert r.json["role"] == "admin" and r.json["user"] == "anonymous-dev"


def test_proxy_mode_trusts_headers_only_from_trusted_peer():
    c = make_app(**PROXY).test_client()
    ok = c.get("/who", headers=hdrs(groups="sec-analysts"), environ_overrides={"REMOTE_ADDR": "10.2.3.4"})
    assert ok.status_code == 200 and ok.json["role"] == "analyst"
    exact = c.get("/who", headers=hdrs(), environ_overrides={"REMOTE_ADDR": "192.168.1.5"})
    assert exact.status_code == 200 and exact.json["role"] == "viewer"


def test_proxy_mode_rejects_spoofed_headers_from_untrusted_peer():
    c = make_app(**PROXY).test_client()
    r = c.get("/who", headers=hdrs(groups="sec-admins"), environ_overrides={"REMOTE_ADDR": "203.0.113.9"})
    assert r.status_code == 401


def test_proxy_mode_requires_user_header():
    c = make_app(**PROXY).test_client()
    assert c.get("/who", environ_overrides={"REMOTE_ADDR": "10.2.3.4"}).status_code == 401
    assert (
        c.get("/who", headers=hdrs(user="x" * 400), environ_overrides={"REMOTE_ADDR": "10.2.3.4"}).status_code
        == 401
    )


def test_role_enforcement():
    c = make_app(**PROXY).test_client()
    env = {"REMOTE_ADDR": "10.2.3.4"}
    assert c.get("/admin-only", headers=hdrs(groups="sec-analysts"), environ_overrides=env).status_code == 403
    assert (
        c.get("/admin-only", headers=hdrs(groups="SEC-ADMINS"), environ_overrides=env).status_code == 200
    )  # case-insensitive groups


def test_healthz_is_public_but_everything_else_is_not():
    c = make_app(**PROXY).test_client()
    assert c.get("/healthz", environ_overrides={"REMOTE_ADDR": "203.0.113.9"}).status_code == 200
    assert c.get("/who", environ_overrides={"REMOTE_ADDR": "203.0.113.9"}).status_code == 401


def test_metrics_requires_admin_when_auth_enabled_and_token_when_configured():
    c = make_app(**PROXY).test_client()
    env = {"REMOTE_ADDR": "10.2.3.4"}
    assert c.get("/metrics", headers=hdrs(groups="sec-analysts"), environ_overrides=env).status_code == 403
    assert c.get("/metrics", headers=hdrs(groups="sec-admins"), environ_overrides=env).status_code == 200
    t = make_app(**PROXY, metrics_token="scrape-token-123").test_client()
    assert t.get("/metrics", environ_overrides=env).status_code == 401
    assert (
        t.get("/metrics", headers={"Authorization": "Bearer wrong"}, environ_overrides=env).status_code == 401
    )
    assert (
        t.get(
            "/metrics", headers={"Authorization": "Bearer scrape-token-123"}, environ_overrides=env
        ).status_code
        == 200
    )


def test_security_headers_present_even_on_errors():
    c = make_app(**PROXY).test_client()
    r = c.get("/who", environ_overrides={"REMOTE_ADDR": "203.0.113.9"})
    assert (
        r.headers["X-Content-Type-Options"] == "nosniff"
        and "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]
    )
    assert "Strict-Transport-Security" in r.headers


@pytest.mark.parametrize(
    "target,expected",
    [
        ("/sast?sev=HIGH", "/sast?sev=HIGH"),
        (None, "/"),
        ("", "/"),
        ("https://evil.example/x", "/"),
        ("//evil.example", "/"),
        ("/\\evil.example", "/"),
        ("javascript:alert(1)", "/"),
        ("sast", "/"),
    ],
)
def test_safe_next_blocks_open_redirects(target, expected):
    assert safe_next(target) == expected


def _oidc_app():
    return make_app(
        auth_mode="oidc",
        oidc_issuer="https://idp.example.invalid",
        oidc_client_id="cid",
        oidc_client_secret="secretsecret",
        session_secret="x" * 40,
        role_admin_groups="admins",
    )


def test_oidc_unauthenticated_browser_is_redirected_to_login():
    c = _oidc_app().test_client()
    r = c.get("/who")
    assert r.status_code == 302 and "/login" in r.headers["Location"]
    assert c.post("/_dash-update-component").status_code == 401  # API calls get 401, not a redirect


def test_oidc_session_principal_and_expiry():
    app = _oidc_app()
    c = app.test_client()
    roles, scope = RoleMapper(["admins"], []), ScopeMap(None)
    with c.session_transaction() as sess:
        sess["principal"] = principal_session_data(
            {"sub": "u1", "email": "u@x.y", "groups": ["admins"]}, "groups", roles, scope
        )
    assert c.get("/who").json["role"] == "admin"
    with c.session_transaction() as sess:
        sess["principal"] = {**sess["principal"], "iat": int(time.time()) - SESSION_MAX_AGE_SECONDS - 5}
    assert c.get("/who").status_code == 302  # expired -> login again


def test_oidc_cookie_flags():
    app = _oidc_app()
    assert app.config["SESSION_COOKIE_SECURE"] is True and app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"


def test_principal_session_data_roles_scope_and_garbage():
    roles = RoleMapper(["admins"], ["analysts"])
    scope = ScopeMap({"team-a": ["App A"], "team-b": ["App B"]})
    assert principal_session_data({}, "groups", roles, scope) is None
    d = principal_session_data({"sub": "1", "groups": ["team-a", "analysts"]}, "groups", roles, scope)
    assert d["role"] == "analyst" and d["scope"] == ["App A"]
    admin = principal_session_data({"sub": "2", "groups": ["admins"]}, "groups", roles, scope)
    assert admin["scope"] is None  # admins are unrestricted
    nobody = principal_session_data({"sub": "3", "groups": []}, "groups", roles, scope)
    assert (
        nobody["scope"] == [] and nobody["role"] == "viewer"
    )  # scoped feature on, no mapping -> sees nothing
    assert (
        principal_session_data({"sub": "4", "groups": "single"}, "groups", roles, ScopeMap(None))["scope"]
        is None
    )
    huge = principal_session_data(
        {"sub": "5", "groups": [f"g{i}" for i in range(5000)]}, "groups", roles, scope
    )
    assert huge is not None


def test_scope_map_loading(tmp_path):
    f = tmp_path / "scope_map.yaml"
    f.write_text("team-a: [App A]\nteam-b: [App B, App C]\n", encoding="utf-8")
    sm = ScopeMap.load(str(f))
    assert sm.applications_for(["TEAM-B"], "viewer") == ("App B", "App C")
    f.write_text("team-a: not-a-list\n", encoding="utf-8")
    with pytest.raises(ValueError):
        ScopeMap.load(str(f))
    f.write_text("!!python/object/apply:os.system ['echo pwned']\n", encoding="utf-8")
    with pytest.raises(Exception):  # noqa: B017 - yaml.safe_load must refuse arbitrary python objects
        ScopeMap.load(str(f))
    assert not ScopeMap.load("").enabled


def test_cross_origin_posts_are_rejected():
    c = make_app().test_client()
    assert c.post("/who", headers={"Origin": "https://evil.example"}).status_code == 403
    # same-origin and non-browser (no Origin) requests are not blocked by this check (405 = route is GET-only)
    assert c.post("/who", headers={"Origin": "http://localhost"}).status_code == 405
    assert c.post("/who").status_code == 405


def test_redis_url_is_masked_in_effective_config():
    s = make_settings(redis_url="redis://:topsecretpw@redis:6379/0")
    assert "topsecretpw" not in str(s.masked_dump())
    assert s.masked_dump()["redis_url"] == "********"
