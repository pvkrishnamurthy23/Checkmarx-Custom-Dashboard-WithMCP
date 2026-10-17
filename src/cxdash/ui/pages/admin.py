"""Admin (role-gated): sync runs, API errors/calls, freshness, effective config (masked), manual sync, roles."""

from __future__ import annotations

import json
from typing import Any

import dash
import dash_bootstrap_components as dbc
from dash import Input, Output, State, callback, ctx, html, no_update
from sqlalchemy import select

from cxdash.db import models as m
from cxdash.domain import ROLE_ADMIN
from cxdash.ui import services
from cxdash.ui.components.badges import pill
from cxdash.ui.components.cards import empty_state, kv_list, panel
from cxdash.ui.components.layout import page_header, split, stack
from cxdash.ui.components.simple_grid import simple_grid

dash.register_page(__name__, path="/admin", name="Admin", title="Admin · Checkmarx One", order=9)


def _fmt(ts: Any) -> str:
    return ts.strftime("%Y-%m-%d %H:%M:%S") if ts else "–"


def layout(**_: Any) -> Any:
    if not services.principal().has_role(ROLE_ADMIN):
        return stack(
            [
                page_header("Admin", icon_name="gear"),
                dbc.Alert("The Admin page requires the admin role.", color="warning"),
            ]
        )

    def grid_panel(
        grid_id: str,
        columns: list[dict[str, Any]],
        title: str,
        height: str,
        subtitle: str | None = None,
        empty: str = "Nothing to show",
        paginate: bool = False,
    ) -> Any:
        return panel(
            simple_grid(grid_id, columns, height=height, empty_text=empty, paginate=paginate),
            title=title,
            subtitle=subtitle,
            flush=True,
        )

    return stack(
        [
            page_header(
                "Administration",
                "Sync activity, data freshness, effective configuration (secrets masked), users and the audit log.",
                icon_name="gear",
            ),
            panel(
                html.Div(
                    [
                        dbc.Button(
                            "Sync scans now", id="ad-scans", size="sm", color="primary", className="cx-btn"
                        ),
                        dbc.Button(
                            "Sync inventory",
                            id="ad-inv",
                            size="sm",
                            outline=True,
                            color="primary",
                            className="cx-btn",
                        ),
                        dbc.Button(
                            "Full refresh (findings + purge)",
                            id="ad-full",
                            size="sm",
                            outline=True,
                            color="primary",
                            className="cx-btn",
                        ),
                        html.Span(id="ad-msg", className="cx-toolbar-note"),
                    ],
                    className="cx-toolbar",
                    style={"padding": "0"},
                ),
                title="Manual sync",
                subtitle="Queued for the worker, which polls every few seconds. Each request is audit-logged.",
                icon_name="refresh",
            ),
            split(
                panel(
                    html.Div(id="ad-fresh"),
                    title="Data freshness",
                    subtitle="Last successful run per job",
                    icon_name="clock",
                ),
                panel(
                    html.Div(id="ad-api"),
                    title="API calls, last 24 h",
                    subtitle="Per job; the worker enforces a per-run cap",
                    icon_name="trend-up",
                ),
                (1, 1),
            ),
            grid_panel(
                "ad-runs",
                [
                    {"field": "id", "width": 80},
                    {"field": "job", "width": 110},
                    {"field": "started_at", "width": 170},
                    {"field": "ended_at", "width": 170},
                    {"field": "status", "width": 100},
                    {"field": "records", "width": 100},
                    {"field": "api_calls", "width": 100},
                    {"field": "error", "flex": 1, "tooltipField": "error"},
                ],
                "Sync runs",
                "360px",
                paginate=True,
            ),
            split(
                panel(
                    html.Pre(id="ad-config", className="cx-raw"),
                    title="Effective configuration",
                    subtitle="Secrets are masked",
                    icon_name="gear",
                ),
                stack(
                    [
                        grid_panel(
                            "ad-users",
                            [
                                {"field": "id", "flex": 1},
                                {"field": "email", "flex": 1},
                                {"field": "role", "width": 100},
                                {"field": "last_login", "width": 170},
                            ],
                            "Users and roles",
                            "200px",
                            empty="Nobody has signed in yet (users appear here after SSO login)",
                        ),
                        grid_panel(
                            "ad-rules",
                            [
                                {"field": "id", "width": 70},
                                {"field": "name", "flex": 1},
                                {"field": "kind", "width": 130},
                                {"field": "channel", "width": 100},
                                {"field": "enabled", "width": 90},
                            ],
                            "Alert rules",
                            "200px",
                            empty="No alert rules yet: create one with `python -m cxdash.cli alert-add`",
                        ),
                        grid_panel(
                            "ad-audit",
                            [
                                {"field": "at", "width": 170},
                                {"field": "user", "width": 140},
                                {"field": "action", "width": 140},
                                {"field": "detail", "flex": 1},
                            ],
                            "Export and audit log",
                            "240px",
                            empty="No exports or manual syncs recorded yet",
                        ),
                    ]
                ),
                (1, 1),
            ),
        ]
    )


@callback(
    Output("ad-runs", "rowData"),
    Output("ad-fresh", "children"),
    Output("ad-api", "children"),
    Output("ad-config", "children"),
    Output("ad-users", "rowData"),
    Output("ad-rules", "rowData"),
    Output("ad-audit", "rowData"),
    Input("url", "pathname"),
    Input("ad-msg", "children"),
)
def load(pathname: str | None, _: Any) -> list[Any]:
    if pathname != "/admin" or not services.principal().has_role(ROLE_ADMIN):
        return [no_update] * 7
    c = services.container()
    a = c.queries.admin
    runs = [
        {**r, "started_at": _fmt(r["started_at"]), "ended_at": _fmt(r["ended_at"])} for r in a.sync_runs(100)
    ]
    fresh = (
        kv_list([(job, _fmt(t)) for job, t in sorted(a.freshness().items())])
        if a.freshness()
        else empty_state(
            "No successful sync yet",
            "Run a sync from the buttons above or start the worker.",
            icon_name="clock",
        )
    )
    totals = a.api_call_totals()
    failed = sum(1 for r in runs if r["status"] == "failed")
    api = html.Div(
        [
            kv_list([(job, f"{n:,}") for job, n in sorted(totals.items())])
            if totals
            else empty_state("No API calls in the last 24 h"),
            html.Div(
                [
                    pill(
                        f"{failed} failed run{'s' if failed != 1 else ''} in the last 100",
                        "danger" if failed else "success",
                    )
                ],
                style={"marginTop": "10px"},
            ),
        ]
    )
    with c.db.session() as s:
        rules = [
            {"id": r.id, "name": r.name, "kind": r.kind, "channel": r.channel, "enabled": bool(r.enabled)}
            for r in s.scalars(select(m.AlertRule))
        ]
    audit = [
        {**r, "at": _fmt(r["at"]), "detail": json.dumps(r["detail"], default=str)[:300]}
        for r in c.queries.users.audit_rows(100)
    ]
    users = [{**u, "last_login": _fmt(u["last_login"])} for u in a.users()]
    return [
        runs,
        fresh,
        api,
        json.dumps(c.settings.masked_dump(), indent=2, default=str),
        users,
        rules,
        audit,
    ]


@callback(
    Output("ad-msg", "children"),
    Input("ad-scans", "n_clicks"),
    Input("ad-inv", "n_clicks"),
    Input("ad-full", "n_clicks"),
    State("ad-msg", "children"),
    prevent_initial_call=True,
)
def manual_sync(_a: Any, _b: Any, _c: Any, _msg: Any) -> str:
    p = services.principal()
    if not p.has_role(ROLE_ADMIN):
        return "Forbidden"
    job = {"ad-scans": "scans", "ad-inv": "inventory", "ad-full": "full"}.get(ctx.triggered_id or "", "")
    if not job:
        return ""
    c = services.container()
    c.requests.enqueue(p.user_id, job)
    c.queries.users.audit(p.user_id, "manual_sync", {"job": job})
    return f"Queued '{job}' sync. The worker polls every {c.settings.sync_request_poll_seconds} s."
