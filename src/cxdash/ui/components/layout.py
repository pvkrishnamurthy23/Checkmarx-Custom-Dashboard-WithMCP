"""Page scaffolding: CSS-grid helpers, page header, sidebar, top bar and the application shell."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

import dash
import dash_bootstrap_components as dbc
from dash import dcc, html

from cxdash.ui.components.icons import icon
from cxdash.ui.strings import S

Children = Any


# --------------------------------------------------------------------------- grid helpers
def grid(children: Sequence[Children], *, min_col: str = "200px", className: str = "") -> html.Div:
    """Auto-fitting card grid (KPIs, small panels): as many columns of at least ``min_col`` as fit."""
    return html.Div(children, className=f"cx-grid {className}".strip(), style={"--cx-min": min_col})


def split(
    left: Children, right: Children, ratio: tuple[int, int] = (7, 5), *, className: str = ""
) -> html.Div:
    """Two columns with a width ratio that collapse to one column on narrow screens."""
    return html.Div(
        [left, right],
        className=f"cx-split {className}".strip(),
        style={"--cx-cols": f"minmax(0, {ratio[0]}fr) minmax(0, {ratio[1]}fr)"},
    )


def stack(children: Sequence[Children], *, className: str = "") -> html.Div:
    """Vertical rhythm container (consistent gap between sections)."""
    return html.Div(children, className=f"cx-stack {className}".strip())


def page_header(
    title: str, subtitle: str | None = None, *, actions: Children = None, icon_name: str | None = None
) -> html.Div:
    return html.Div(
        [
            html.Div(
                [
                    html.Div(
                        [
                            icon(icon_name, className="cx-page-icon") if icon_name else None,
                            html.H1(title, className="cx-page-title"),
                        ],
                        className="cx-page-titlerow",
                    ),
                    html.P(subtitle, className="cx-page-sub") if subtitle else None,
                ]
            ),
            html.Div(actions, className="cx-page-actions") if actions else None,
        ],
        className="cx-page-header",
    )


# --------------------------------------------------------------------------- navigation
@dataclass(frozen=True)
class NavItem:
    label: str
    path: str
    icon_name: str
    group: str
    admin_only: bool = False


NAV: tuple[NavItem, ...] = (
    NavItem("Overview", "/", "overview", "Dashboard"),
    NavItem("SAST", "/sast", "shield", "Scanners"),
    NavItem("SCA", "/sca", "package", "Scanners"),
    NavItem("Containers", "/containers", "container", "Scanners"),
    NavItem("IaC", "/iac", "layers", "Scanners"),
    NavItem("Secrets & API", "/secrets-apisec", "key", "Scanners"),
    NavItem("Projects", "/projects", "folder", "Insights"),
    NavItem("Scan Health", "/scan-health", "pulse", "Insights"),
    NavItem("Executive", "/executive", "report", "Insights"),
    NavItem("Admin", "/admin", "gear", "Manage", admin_only=True),
)


def visible_nav(is_admin: bool) -> list[NavItem]:
    return [n for n in NAV if is_admin or not n.admin_only]


def nav_link(item: NavItem) -> dcc.Link:
    return dcc.Link(
        [icon(item.icon_name, className="cx-nav-icon"), html.Span(item.label, className="cx-nav-label")],
        href=item.path,
        id={"type": "nav", "path": item.path},
        className="cx-nav-link",
        title=item.label,
    )


def sidebar(items: Sequence[NavItem], *, footer: Children = None) -> html.Aside:
    groups: dict[str, list[NavItem]] = {}
    for item in items:
        groups.setdefault(item.group, []).append(item)
    sections = [
        html.Nav(
            [html.Div(group, className="cx-nav-group"), *[nav_link(i) for i in members]],
            className="cx-nav-section",
            **{"aria-label": group},
        )
        for group, members in groups.items()
    ]
    brand = html.Div(
        [
            html.Span("CX", className="cx-brand-mark"),
            html.Div(
                [
                    html.Div("Checkmarx One", className="cx-brand-name"),
                    html.Div("Security Dashboard", className="cx-brand-sub"),
                ],
                className="cx-brand-text",
            ),
        ],
        className="cx-brand",
    )
    return html.Aside(
        [brand, html.Div(sections, className="cx-nav"), html.Div(footer, className="cx-side-footer")],
        className="cx-sidebar",
    )


def topbar(*, user_label: str, can_refresh: bool, signout: Children = None) -> html.Header:
    sync = html.Div(
        [icon("clock"), html.Span(id="hdr-sync", children=S.never_synced)],
        className="cx-sync-pill",
        title="Time of the last successful scan sync",
    )
    refresh = dbc.Button(
        [icon("refresh"), html.Span(S.refresh, className="cx-btn-label")],
        id="hdr-refresh",
        size="sm",
        color="primary",
        outline=True,
        disabled=not can_refresh,
        className="cx-btn",
        title="Queue a sync (analyst role, once a minute)",
    )
    user = html.Div(
        [icon("user"), html.Span(user_label, className="cx-user-label")],
        className="cx-user",
        title="Signed-in user",
    )
    return html.Header(
        [
            html.Div(
                "Checkmarx One / read-only view",
                className="cx-topbar-title",
                title="This dashboard never changes anything in Checkmarx One",
            ),
            html.Div(
                [sync, refresh, html.Span(id="hdr-refresh-msg", className="cx-topbar-msg"), user, signout],
                className="cx-topbar-right",
            ),
        ],
        className="cx-topbar",
    )


def theme_toggle() -> html.Div:
    """Light/dark switch (id kept stable: the clientside callback and tests use ``theme-switch``)."""
    return html.Div(
        [
            icon("sun"),
            dbc.Switch(id="theme-switch", value=False, className="cx-theme-switch", label=""),
            icon("moon"),
        ],
        className="cx-theme-toggle",
        title="Switch light / dark theme",
    )


def app_shell(
    *,
    nav_items: Sequence[NavItem],
    top: Children,
    filters: Children,
    extra: Children = None,
    sidebar_footer: Children = None,
) -> html.Div:
    return html.Div(
        [
            dcc.Location(id="url", refresh=False),
            dcc.Store(id="filters", data={}, storage_type="memory"),
            dcc.Interval(id="hdr-tick", interval=60_000),
            html.A("Skip to content", href="#main", className="cx-skip"),
            sidebar(nav_items, footer=sidebar_footer),
            html.Div(
                [
                    html.Div([top, filters], className="cx-sticky"),
                    html.Main(dash.page_container, id="main", className="cx-main"),
                ],
                className="cx-content",
            ),
            extra,
        ],
        className="cx-app",
    )
