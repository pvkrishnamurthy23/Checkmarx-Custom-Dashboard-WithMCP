"""Projects / Applications inventory with risk score, scan age and scanner coverage (spec 10.2)."""

from __future__ import annotations

from typing import Any

import dash
import dash_bootstrap_components as dbc
from dash import Input, Output, callback, dcc, html, no_update

from cxdash.domain import ENGINE_LABELS
from cxdash.ui import services
from cxdash.ui.components import charts
from cxdash.ui.components.cards import panel
from cxdash.ui.components.layout import page_header, stack
from cxdash.ui.components.simple_grid import simple_grid
from cxdash.ui.theme import GRAPH_CONFIG

dash.register_page(__name__, path="/projects", name="Projects", title="Projects · Checkmarx One", order=6)


SHORT = {"containers": "Cont.", "kics": "IaC", "secrets": "Secrets", "apisec": "API", "sscs": "SSCS"}


def _columns(engines: tuple[str, ...]) -> list[dict[str, Any]]:
    cols: list[dict[str, Any]] = [
        {
            "field": "project",
            "headerName": "Project",
            "flex": 3,
            "minWidth": 280,
            "pinned": "left",
            "tooltipField": "project",
        },
        {
            "field": "application",
            "headerName": "Application",
            "flex": 2,
            "minWidth": 170,
            "tooltipField": "application",
        },
        {"field": "last_scan", "headerName": "Last scan", "width": 120},
        {"field": "age_days", "headerName": "Age (d)", "width": 95, "type": "numericColumn"},
    ]
    cols += [
        {
            "field": f"open_{e}",
            "headerName": SHORT.get(e, ENGINE_LABELS[e]),
            "headerTooltip": ENGINE_LABELS[e],
            "width": 88,
            "type": "numericColumn",
        }
        for e in engines
    ]
    cols += [
        {"field": "open_total", "headerName": "Open", "width": 95, "type": "numericColumn"},
        {
            "field": "risk",
            "headerName": "Risk (0-100)",
            "width": 120,
            "type": "numericColumn",
            "sort": "desc",
        },
        {"field": "coverage", "headerName": "Coverage", "width": 130, "tooltipField": "coverage_tip"},
        {"field": "no_scan", "headerName": "No scan on branch", "width": 170},
    ]
    return cols


def layout(**_: Any) -> Any:
    engines = services.container().settings.cx_engines
    return stack(
        [
            page_header(
                "Projects",
                "Open findings, risk score and scanner coverage per project. Click a row for its trend and top findings.",
                icon_name="folder",
            ),
            panel(
                html.Div(
                    simple_grid("pj-grid", _columns(engines), height="640px", selectable=True),
                    className="cx-grid-wrap",
                ),
                title="Project inventory",
                subtitle="Sorted by risk score (0-100, percentile rank). Counts are from the latest scan of each project.",
                icon_name="folder",
                flush=True,
            ),
            dbc.Offcanvas(
                [
                    dcc.Graph(id="pj-trend", config=GRAPH_CONFIG, style={"height": "260px"}),
                    html.H3("Top findings", className="cx-drawer-title mt-3"),
                    html.Div(id="pj-findings"),
                ],
                id="pj-panel",
                title="Project",
                placement="end",
                is_open=False,
                style={"width": "680px", "maxWidth": "95vw"},
            ),
        ]
    )


def row_for(r: dict[str, Any], engines: tuple[str, ...]) -> dict[str, Any]:
    cov = r["coverage"]
    ok = sum(1 for e in engines if cov.get(e))
    out = {
        "project_id": r["project_id"],
        "project": r["project"],
        "application": r["application"],
        "last_scan": r["last_scan"].date().isoformat() if r["last_scan"] else "never",
        "age_days": r["age_days"],
        "open_total": r["open_total"],
        "risk": r["risk"],
        "coverage": f"{'●' * ok}{'○' * (len(engines) - ok)}  {ok}/{len(engines)}",
        "coverage_tip": ", ".join(f"{ENGINE_LABELS[e]}: {'ok' if cov.get(e) else 'gap'}" for e in engines),
        "no_scan": ", ".join(r["no_scan_branches"]),
    }
    out.update({f"open_{e}": r["open_by_engine"].get(e, 0) for e in engines})
    return out


@callback(Output("pj-grid", "rowData"), Input("filters", "data"))
def table(store: dict[str, Any] | None) -> list[dict[str, Any]]:
    c = services.container()
    f = services.current_filters(store)
    return [row_for(r, c.settings.cx_engines) for r in c.queries.projects.table(f)]


@callback(
    Output("pj-panel", "is_open"),
    Output("pj-panel", "title"),
    Output("pj-trend", "figure"),
    Output("pj-findings", "children"),
    Input("pj-grid", "selectedRows"),
    Input("filters", "data"),
    prevent_initial_call=True,
)
def detail(selected: list[dict[str, Any]] | None, store: dict[str, Any] | None) -> tuple[Any, ...]:
    if not selected:
        return no_update, no_update, no_update, no_update
    row = selected[0]
    c = services.container()
    f = services.current_filters(store)
    pf = f.with_values(projects=(row["project_id"],))
    rows, total = c.queries.findings.page(pf, 0, 25)
    items = [html.Li(f"{r['severity']} · {r['engine']} · {r['title']}", className="small") for r in rows]
    body = html.Div([html.Div(f"{total:,} open findings", className="small text-muted"), html.Ul(items)])
    return (
        True,
        row["project"],
        charts.trend_area(c.queries.projects.project_trend(row["project_id"], f)),
        body,
    )
