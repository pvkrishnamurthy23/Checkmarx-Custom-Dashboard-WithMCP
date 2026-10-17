"""Dash app factory (spec 4/10). ``cxdash.ui.app:server`` is the WSGI entry point (gunicorn/waitress)."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import dash
import dash_bootstrap_components as dbc
from dash import ALL, Input, Output, State, clientside_callback, html
from flask import Flask
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import text

from cxdash.config import Settings, get_settings
from cxdash.container import Container, build_container
from cxdash.domain import ROLE_ADMIN
from cxdash.logging import configure_logging
from cxdash.security.auth import build_authenticator, install_ops_routes, install_security
from cxdash.sync.jobs import SYNC_LAG
from cxdash.ui import (
    services,
    theme,  # noqa: F401  (registers the Plotly template)
)
from cxdash.ui.components import drawer, filter_bar
from cxdash.ui.components.layout import app_shell, theme_toggle, topbar, visible_nav
from cxdash.ui.exporters import install_export_routes
from cxdash.ui.strings import S

log = logging.getLogger(__name__)
UI_DIR = Path(__file__).parent


def health_report(c: Container) -> dict[str, Any]:
    try:
        with c.db.engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        return {"status": "error", "db": "down"}
    last = c.queries.admin.last_sync()
    age = (datetime.now(UTC) - last).total_seconds() if last else None
    stale = age is not None and age > 3 * c.settings.sync_scans_minutes * 60
    return {
        "status": "degraded" if stale else "ok",
        "db": "up",
        "last_sync_age_seconds": int(age) if age is not None else None,
        "sync_stale": stale,
    }


def metrics_render(c: Container) -> tuple[bytes, str]:
    last = c.queries.admin.last_sync()
    if last:
        SYNC_LAG.set((datetime.now(UTC) - last).total_seconds())
    return generate_latest(), CONTENT_TYPE_LATEST


def serve_layout() -> html.Div:
    """Evaluated per page load: navigation and filter options depend on the caller's role and row-level scope."""
    p = services.principal()
    c = services.container()
    signout = (
        html.Form(
            dbc.Button(S.logout, type="submit", size="sm", color="link", className="cx-btn"),
            method="post",
            action="/logout",
            className="d-inline",
        )
        if c.settings.auth_mode == "oidc"
        else None
    )
    return app_shell(
        nav_items=visible_nav(p.has_role(ROLE_ADMIN)),
        top=topbar(user_label=p.email or p.user_id, can_refresh=p.has_role("analyst"), signout=signout),
        filters=filter_bar.layout(c.queries.options.filter_options(p.scope_applications)),
        extra=drawer.layout(),
        sidebar_footer=theme_toggle(),
    )


def create_app(settings: Settings | None = None, container: Container | None = None) -> dash.Dash:
    settings = settings or get_settings()
    configure_logging(settings.log_level, settings.secret_values())
    c = container or build_container(settings)
    services.set_container(c)

    server = Flask(__name__)
    authenticator = build_authenticator(settings)
    install_security(server, settings, authenticator, record_login=c.queries.admin.record_login)
    install_ops_routes(server, settings, lambda: health_report(c), lambda: metrics_render(c))
    install_export_routes(server, c)

    app = dash.Dash(
        __name__,
        server=server,
        use_pages=True,
        pages_folder=str(UI_DIR / "pages"),
        assets_folder=str(UI_DIR / "assets"),
        suppress_callback_exceptions=True,
        title=S.app_title,
        update_title=None,
        meta_tags=[{"name": "viewport", "content": "width=device-width, initial-scale=1"}],
    )
    app.layout = serve_layout

    clientside_callback(
        """(dark) => { const t = dark ? 'dark' : 'light';
            document.documentElement.setAttribute('data-bs-theme', t);
            document.body.setAttribute('data-ag-theme-mode', t);
            return window.dash_clientside.no_update; }""",
        Output("theme-switch", "id"),
        Input("theme-switch", "value"),
    )
    clientside_callback(
        """(search, pathname, ids) => [ids.map(i => i.path + (search || '')), ids.map(i => 'cx-nav-link' + (i.path === pathname ? ' active' : ''))]""",
        Output({"type": "nav", "path": ALL}, "href"),
        Output({"type": "nav", "path": ALL}, "className"),
        Input("url", "search"),
        Input("url", "pathname"),
        State({"type": "nav", "path": ALL}, "id"),
    )
    return app


_app: dash.Dash | None = None


def __getattr__(name: str) -> Any:
    """Lazy WSGI ``server`` so importing this module never needs a configured .env (tests, docs)."""
    global _app
    if name == "server":
        if _app is None:
            _app = create_app()
        return _app.server
    raise AttributeError(name)


if __name__ == "__main__":  # python -m cxdash.ui.app  (development server)
    cfg = get_settings()
    create_app(cfg).run(host=cfg.web_host, port=cfg.web_port, debug=False)
