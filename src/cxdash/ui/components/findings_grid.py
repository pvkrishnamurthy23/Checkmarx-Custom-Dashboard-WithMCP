"""Findings grid: dash-ag-grid infinite row model backed by server-side SQL paging (spec 10.3)."""

from __future__ import annotations

import csv
import io
from collections.abc import Sequence
from datetime import datetime
from typing import Any
from urllib.parse import urlencode

import dash_ag_grid as dag
import dash_bootstrap_components as dbc
from dash import Input, Output, State, callback, dcc, html, no_update

from cxdash.domain import ROLE_ANALYST
from cxdash.exporting import sanitize_cell
from cxdash.metrics.aging import age_days
from cxdash.metrics.sla import is_breach
from cxdash.ui import services, state
from cxdash.ui.components.actions import link_button
from cxdash.ui.components.icons import icon
from cxdash.ui.strings import S

SEVERITY_STYLE = {
    "styleConditions": [
        {"condition": f"params.value == '{sev}'", "style": {"color": color, "fontWeight": 600}}
        for sev, color in (
            ("CRITICAL", "#d03b3b"),
            ("HIGH", "#c4572b"),
            ("MEDIUM", "#9a6b00"),
            ("LOW", "#2a78d6"),
            ("INFO", "#6b6a66"),
        )
    ]
}

ALL_COLUMNS: list[dict[str, Any]] = [
    {
        "field": "severity",
        "headerName": "Severity",
        "width": 110,
        "cellStyle": SEVERITY_STYLE,
        "sortable": True,
    },
    {
        "field": "engine",
        "headerName": "Scanner",
        "width": 105,
        "sortable": True,
        "filter": "agTextColumnFilter",
    },
    {
        "field": "title",
        "headerName": "Title",
        "flex": 2,
        "minWidth": 220,
        "sortable": True,
        "filter": "agTextColumnFilter",
        "tooltipField": "title",
    },
    {"field": "project", "headerName": "Project", "width": 160, "sortable": False},
    {
        "field": "branch",
        "headerName": "Branch",
        "width": 120,
        "sortable": True,
        "filter": "agTextColumnFilter",
    },
    {"field": "state", "headerName": "State", "width": 140, "sortable": True, "filter": "agTextColumnFilter"},
    {"field": "status", "headerName": "Status", "width": 110, "sortable": True},
    {"field": "age_days", "headerName": "Age (d)", "width": 95, "sortable": False, "type": "numericColumn"},
    {"field": "sla", "headerName": "SLA", "width": 90, "sortable": False},
    {
        "field": "cwe",
        "headerName": "CWE",
        "width": 100,
        "sortable": True,
        "filter": "agTextColumnFilter",
        "hide": True,
    },
    {"field": "cve", "headerName": "CVE", "width": 140, "sortable": True, "filter": "agTextColumnFilter"},
    {"field": "cvss", "headerName": "CVSS", "width": 90, "sortable": True, "hide": True},
    {
        "field": "package",
        "headerName": "Package",
        "width": 160,
        "sortable": True,
        "filter": "agTextColumnFilter",
    },
    {"field": "package_version", "headerName": "Version", "width": 100, "hide": True},
    {"field": "fixed_version", "headerName": "Fix", "width": 100, "hide": True},
    {
        "field": "image",
        "headerName": "Image",
        "width": 200,
        "sortable": True,
        "filter": "agTextColumnFilter",
        "hide": True,
    },
    {
        "field": "file_path",
        "headerName": "File",
        "flex": 1,
        "minWidth": 180,
        "sortable": True,
        "filter": "agTextColumnFilter",
        "tooltipField": "file_path",
    },
    {"field": "line", "headerName": "Line", "width": 80, "sortable": True, "type": "numericColumn"},
    {"field": "language", "headerName": "Language", "width": 110, "hide": True},
    {
        "field": "category",
        "headerName": "Category",
        "width": 180,
        "filter": "agTextColumnFilter",
        "hide": True,
    },
    {"field": "first_found_at", "headerName": "First found", "width": 120, "sortable": True},
]

# Per-page column subsets (OCP: new pages pass their own list, nothing else changes).
PAGE_COLUMNS: dict[str, list[str]] = {
    "sast": [
        "severity",
        "title",
        "project",
        "branch",
        "state",
        "status",
        "age_days",
        "sla",
        "cwe",
        "file_path",
        "line",
        "language",
        "category",
        "first_found_at",
    ],
    "sca": [
        "severity",
        "title",
        "project",
        "branch",
        "state",
        "status",
        "age_days",
        "sla",
        "cve",
        "cvss",
        "package",
        "package_version",
        "fixed_version",
        "first_found_at",
    ],
    "containers": [
        "severity",
        "title",
        "project",
        "branch",
        "state",
        "status",
        "age_days",
        "sla",
        "image",
        "cve",
        "cvss",
        "package",
        "package_version",
        "fixed_version",
    ],
    "kics": [
        "severity",
        "title",
        "project",
        "branch",
        "state",
        "status",
        "age_days",
        "sla",
        "category",
        "file_path",
        "line",
        "first_found_at",
    ],
    "secrets_apisec": [
        "severity",
        "engine",
        "title",
        "project",
        "branch",
        "state",
        "status",
        "age_days",
        "sla",
        "category",
        "file_path",
        "line",
    ],
}


def columns_for(page: str) -> list[dict[str, Any]]:
    wanted = PAGE_COLUMNS.get(page)
    by_field = {c["field"]: c for c in ALL_COLUMNS}
    if not wanted:
        return [dict(c) for c in ALL_COLUMNS]
    return [{**by_field[f], "hide": False} for f in wanted if f in by_field]


def to_grid_row(row: dict[str, Any]) -> dict[str, Any]:
    c = services.container()
    out = dict(row)
    ff = row.get("first_found_at")
    days = age_days(ff, None)
    out["age_days"] = days
    out["sla"] = (
        "Breach"
        if is_breach(row["severity"], days, c.settings)
        else ("OK" if c.settings.sla_days(row["severity"]) else "-")
    )
    out["first_found_at"] = ff.date().isoformat() if isinstance(ff, datetime) else ff
    out["row_id"] = f"{row['scan_id']}||{row['finding_id']}"
    out.pop("raw_json", None)
    return out


def build_grid(grid_id: str, page: str, height: str = "560px") -> dag.AgGrid:
    return dag.AgGrid(
        id=grid_id,
        columnDefs=columns_for(page),
        defaultColDef={"resizable": True, "sortable": False, "filter": False, "tooltipShowDelay": 400},
        rowModelType="infinite",
        getRowId="params.data.row_id",
        dashGridOptions={
            "rowSelection": {
                "mode": "multiRow",
                "checkboxes": True,
                "headerCheckbox": False,
                "enableClickSelection": False,
            },
            "cacheBlockSize": 100,
            "maxBlocksInCache": 20,
            "rowBuffer": 20,
            "localeText": {"noRowsToShow": S.no_data},
            "animateRows": False,
        },
        style={"height": height},
    )


def grid_component(grid_id: str) -> html.Div:
    """Toolbar + a wrapper that is rebuilt whenever the filters change (resets the infinite datasource)."""
    toolbar = html.Div(
        [
            link_button(f"{grid_id}-csv", S.export_csv, "download"),
            link_button(f"{grid_id}-xlsx", S.export_xlsx, "download"),
            dbc.Button(
                [icon("check"), html.Span(S.export_selection)],
                id=f"{grid_id}-sel",
                size="sm",
                outline=True,
                color="secondary",
                className="cx-btn",
            ),
            html.Span(id=f"{grid_id}-count", className="cx-toolbar-note"),
            dcc.Download(id=f"{grid_id}-download"),
        ],
        className="cx-toolbar",
    )
    return html.Div(
        [toolbar, html.Div(dcc.Loading(html.Div(id=f"{grid_id}-wrap"), type="dot"), className="cx-grid-wrap")]
    )


def register(grid_id: str, engines: Sequence[str], page: str) -> None:
    """Register the callbacks for one grid instance (called once per page module)."""
    eng = tuple(engines)

    @callback(Output(f"{grid_id}-wrap", "children"), Input("filters", "data"))
    def rebuild(_: Any) -> dag.AgGrid:
        return build_grid(grid_id, page)

    @callback(Output(grid_id, "getRowsResponse"), Input(grid_id, "getRowsRequest"), State("filters", "data"))
    def rows(request: dict[str, Any] | None, store: dict[str, Any] | None) -> Any:
        if not request:
            return no_update
        f = services.current_filters(store)
        data, total = services.container().queries.findings.page(
            f,
            int(request.get("startRow", 0)),
            int(request.get("endRow", 100)),
            request.get("sortModel"),
            request.get("filterModel"),
            eng,
        )
        return {"rowData": [to_grid_row(r) for r in data], "rowCount": total}

    @callback(
        [
            Output(f"{grid_id}-csv", "href"),
            Output(f"{grid_id}-xlsx", "href"),
            Output(f"{grid_id}-count", "children"),
        ],
        Input("filters", "data"),
    )
    def export_links(store: dict[str, Any] | None) -> tuple[Any, Any, str]:
        f = services.current_filters(store)
        q = state.to_query(f)
        sep = "&" if q else "?"
        suffix = f"{sep}{urlencode({'engines': ','.join(eng)})}"
        n = services.container().queries.findings.count(f, eng)
        allowed = services.principal().has_role(ROLE_ANALYST)
        return (
            f"/export/findings.csv{q}{suffix}" if allowed else "#",
            f"/export/findings.xlsx{q}{suffix}" if allowed else "#",
            f"{n:,} findings",
        )

    @callback(
        Output(f"{grid_id}-download", "data"),
        Input(f"{grid_id}-sel", "n_clicks"),
        State(grid_id, "selectedRows"),
        State("filters", "data"),
        prevent_initial_call=True,
    )
    def export_selection(
        _: int | None, selected: list[dict[str, Any]] | None, store: dict[str, Any] | None
    ) -> Any:
        p = services.principal()
        if not p.has_role(ROLE_ANALYST) or not selected:
            return no_update
        cols = [c["field"] for c in columns_for("")]
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(cols)
        for r in selected[:5000]:
            w.writerow([sanitize_cell(r.get(c)) for c in cols])
        services.container().queries.users.audit(
            p.user_id,
            "export_selection",
            {"rows": len(selected), "filter": services.current_filters(store).fingerprint()},
        )
        return {"content": "﻿" + buf.getvalue(), "filename": "selection.csv", "type": "text/csv;charset=utf-8"}

    @callback(
        Output("drawer-target", "data", allow_duplicate=True),
        Input(grid_id, "cellClicked"),
        prevent_initial_call=True,
    )
    def open_drawer(cell: dict[str, Any] | None) -> Any:
        rid = (cell or {}).get("rowId")
        if not rid or "||" not in str(rid):
            return no_update
        scan_id, _, finding_id = str(rid).partition("||")
        return {"scan_id": scan_id, "finding_id": finding_id}
