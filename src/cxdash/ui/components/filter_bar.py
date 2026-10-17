"""Global filter bar + header actions (spec 10.1).

State flow (single source of truth = ``dcc.Store('filters')``):

    URL --C--> store + controls            (page load / back button / shared link)
    controls --A--> store                  (user edits a control)
    store --D--> controls                  (chart click, saved view, reset, removed chip)
    store --B--> URL

Every hop compares before writing (``no_update`` when equal) so the loop terminates.
Layout: one compact primary row (search + the five most-used filters), a collapsible "More filters" row,
and a row of removable chips that always shows what is currently applied (``filter_chips``).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import dash_bootstrap_components as dbc
from dash import Input, Output, State, callback, ctx, dcc, html, no_update

from cxdash.domain import ROLE_ANALYST
from cxdash.ui import services, state
from cxdash.ui.components import filter_chips
from cxdash.ui.components.icons import icon
from cxdash.ui.strings import S

CONTROL_IDS = ["f-app", "f-proj", "f-tag", "f-branch", "f-engine", "f-sev", "f-state", "f-status"]
FILTER_FIELDS = [
    "applications",
    "projects",
    "tags",
    "branches",
    "engines",
    "severities",
    "states",
    "statuses",
]
ADVANCED_FIELDS = ("tags", "states", "statuses")  # live in the collapsible row (plus the date range)

OPTION_KEYS = {
    "f-app": "applications",
    "f-proj": "projects",
    "f-tag": "tags",
    "f-branch": "branches",
    "f-engine": "engines",
    "f-sev": "severities",
    "f-state": "states",
    "f-status": "statuses",
}


def _field(label: str, control: Any, *, wide: bool = False) -> html.Div:
    """Label above a control (reusable for every filter)."""
    return html.Div(
        [html.Label(label, className="cx-field-label"), control],
        className="cx-field" + (" cx-field-wide" if wide else ""),
    )


def _dd(cid: str, label: str, options: dict[str, list[Any]]) -> html.Div:
    # Options are rendered with the layout (not loaded by a callback) so a value restored from the URL
    # is valid on first paint; a dropdown would otherwise discard it and clear the filter.
    return _field(
        label,
        dcc.Dropdown(
            id=cid,
            multi=True,
            placeholder="All",
            options=options[OPTION_KEYS[cid]],
            maxHeight=280,
            className="cx-dd",
        ),
    )


def layout(options: dict[str, list[Any]]) -> html.Div:
    search = _field(
        S.search,
        html.Div(
            [
                icon("search", className="cx-input-icon"),
                dcc.Input(
                    id="f-text",
                    type="text",
                    debounce=True,
                    maxLength=200,
                    placeholder=S.search_placeholder,
                    className="cx-input",
                ),
            ],
            className="cx-input-wrap",
        ),
        wide=True,
    )
    actions = html.Div(
        [
            dbc.Button(
                [
                    icon("filter"),
                    html.Span(S.more_filters, className="cx-btn-label"),
                    html.Span("", id="f-more-count", className="cx-count"),
                ],
                id="f-more-btn",
                size="sm",
                color="secondary",
                outline=True,
                className="cx-btn",
            ),
            dbc.Button(S.reset, id="f-reset", size="sm", color="secondary", outline=True, className="cx-btn"),
            dbc.Button(
                [icon("bookmark"), html.Span(S.save_view, className="cx-btn-label")],
                id="f-save-open",
                size="sm",
                color="primary",
                outline=True,
                className="cx-btn",
            ),
            dcc.Dropdown(
                id="f-views",
                placeholder=S.saved_views,
                options=[],
                clearable=True,
                className="cx-dd cx-dd-views",
            ),
        ],
        className="cx-filter-actions",
    )
    return html.Div(
        className="cx-filterbar",
        children=[
            html.Div(
                [
                    search,
                    _dd("f-app", S.application, options),
                    _dd("f-proj", S.project, options),
                    _dd("f-branch", S.branch, options),
                    _dd("f-engine", S.scanner, options),
                    _dd("f-sev", S.severity, options),
                    actions,
                ],
                className="cx-filter-row",
            ),
            dbc.Collapse(
                html.Div(
                    [
                        _dd("f-tag", S.tag, options),
                        _dd("f-state", S.state, options),
                        _dd("f-status", S.status, options),
                        _field(
                            f"{S.from_date} - {S.to_date}",
                            dcc.DatePickerRange(
                                id="f-date",
                                display_format="YYYY-MM-DD",
                                start_date_placeholder_text=S.from_date,
                                end_date_placeholder_text=S.to_date,
                                clearable=True,
                                className="cx-date",
                            ),
                        ),
                    ],
                    className="cx-filter-row cx-filter-row-more",
                ),
                id="f-more",
                is_open=False,
            ),
            filter_chips.layout(),
            dbc.Modal(
                [
                    dbc.ModalHeader(dbc.ModalTitle(S.save_view)),
                    dbc.ModalBody(dbc.Input(id="f-view-name", placeholder=S.view_name, maxlength=80)),
                    dbc.ModalFooter(
                        [
                            html.Span(id="f-view-msg", className="me-auto small"),
                            dbc.Button(S.save, id="f-save-do", color="primary"),
                        ]
                    ),
                ],
                id="f-save-modal",
                is_open=False,
            ),
        ],
    )


def _controls_from(f: Any) -> list[Any]:
    vals: list[Any] = [list(getattr(f, name)) for name in FILTER_FIELDS]
    vals.append(f.date_from.isoformat() if f.date_from else None)
    vals.append(f.date_to.isoformat() if f.date_to else None)
    vals.append(f.text or "")
    return vals


def _store_from_controls(vals: list[Any]) -> dict[str, Any]:
    *lists, start, end, text = vals
    data: dict[str, Any] = {name: list(v or []) for name, v in zip(FILTER_FIELDS, lists, strict=True)}
    data["date_from"], data["date_to"], data["text"] = (start or None), (end or None), (text or "")[:200]
    return state.to_store(state.from_store(data))  # validate + canonicalise


CONTROL_OUTPUTS = [Output(c, "value", allow_duplicate=True) for c in CONTROL_IDS] + [
    Output("f-date", "start_date", allow_duplicate=True),
    Output("f-date", "end_date", allow_duplicate=True),
    Output("f-text", "value", allow_duplicate=True),
]
CONTROL_STATES = [State(c, "value") for c in CONTROL_IDS] + [
    State("f-date", "start_date"),
    State("f-date", "end_date"),
    State("f-text", "value"),
]


def _diff(desired: list[Any], current: list[Any]) -> list[Any]:
    """no_update for every control that already shows the desired value."""
    return [no_update if _norm(d) == _norm(c) else d for d, c in zip(desired, current, strict=True)]


def _norm(v: Any) -> Any:
    if v in (None, "", []):
        return None
    return v


# ---- C: URL -> store + controls
@callback(
    [Output("filters", "data", allow_duplicate=True), *CONTROL_OUTPUTS],
    Input("url", "search"),
    State("filters", "data"),
    *CONTROL_STATES,
    prevent_initial_call="initial_duplicate",
)
def url_to_state(search: str | None, store: dict[str, Any] | None, *controls: Any) -> list[Any]:
    f = state.from_query(search)
    new_store = state.to_store(f)
    same_store = state.from_store(store) == f
    return [no_update if same_store else new_store, *_diff(_controls_from(f), list(controls))]


# ---- A: controls -> store
@callback(
    Output("filters", "data", allow_duplicate=True),
    [Input(c, "value") for c in CONTROL_IDS]
    + [Input("f-date", "start_date"), Input("f-date", "end_date"), Input("f-text", "value")],
    State("filters", "data"),
    prevent_initial_call=True,
)
def controls_to_store(*args: Any) -> Any:
    *vals, current = args
    new = _store_from_controls(list(vals))
    cur = state.to_store(state.from_store(current))
    # keep facets/other store-only keys that have no control (chart-click facets)
    new["facets"] = cur.get("facets", [])
    return no_update if new == cur else new


# ---- D: store -> controls
@callback(
    CONTROL_OUTPUTS,
    Input("filters", "data"),
    CONTROL_STATES,
    prevent_initial_call=True,
)
def store_to_controls(store: dict[str, Any] | None, *controls: Any) -> list[Any]:
    return _diff(_controls_from(state.from_store(store)), list(controls))


# ---- B: store -> URL
@callback(
    Output("url", "search", allow_duplicate=True),
    Input("filters", "data"),
    State("url", "search"),
    prevent_initial_call=True,
)
def store_to_url(store: dict[str, Any] | None, search: str | None) -> Any:
    wanted = state.to_query(state.from_store(store))
    return no_update if state.from_query(search) == state.from_store(store) else wanted


@callback(
    Output("filters", "data", allow_duplicate=True), Input("f-reset", "n_clicks"), prevent_initial_call=True
)
def reset(_: int | None) -> dict[str, Any]:
    return state.to_store(state.from_store(None))


# ---- saved views
@callback(Output("f-views", "options"), Input("url", "pathname"), Input("f-view-msg", "children"))
def load_views(*_: Any) -> list[dict[str, Any]]:
    uid = services.principal().user_id
    return [
        {"label": v["name"], "value": v["id"]} for v in services.container().queries.users.saved_views(uid)
    ]


@callback(
    Output("f-save-modal", "is_open"),
    Input("f-save-open", "n_clicks"),
    Input("f-save-do", "n_clicks"),
    State("f-save-modal", "is_open"),
    prevent_initial_call=True,
)
def toggle_modal(open_clicks: int | None, _save: int | None, is_open: bool) -> bool:
    if ctx.triggered_id == "f-save-open":
        return services.principal().has_role(ROLE_ANALYST)
    return False


@callback(
    Output("f-view-msg", "children"),
    Input("f-save-do", "n_clicks"),
    State("f-view-name", "value"),
    State("filters", "data"),
    prevent_initial_call=True,
)
def save_view(_: int | None, name: str | None, store: dict[str, Any] | None) -> str:
    p = services.principal()
    if not p.has_role(ROLE_ANALYST):
        return S.forbidden
    try:
        services.container().queries.users.save_view(
            p.user_id, name or "", state.to_store(state.from_store(store))
        )
    except ValueError as exc:
        return str(exc)
    return S.saved


@callback(
    Output("filters", "data", allow_duplicate=True), Input("f-views", "value"), prevent_initial_call=True
)
def apply_view(view_id: int | None) -> Any:
    if view_id is None:
        return no_update
    for v in services.container().queries.users.saved_views(services.principal().user_id):
        if v["id"] == view_id:
            return state.to_store(state.from_store(v["filters"]))
    return no_update


# ---- header: freshness + refresh
@callback(Output("hdr-sync", "children"), Input("url", "pathname"), Input("hdr-tick", "n_intervals"))
def sync_stamp(*_: Any) -> str:
    last = services.container().queries.admin.last_sync()
    if last is None:
        return S.never_synced
    mins = int((datetime.now(UTC) - last).total_seconds() // 60)
    return S.last_synced.format(
        time=last.strftime("%Y-%m-%d %H:%M UTC"),
        ago=f"{mins} min ago" if mins < 120 else f"{mins // 60} h ago",
    )


@callback(Output("hdr-refresh-msg", "children"), Input("hdr-refresh", "n_clicks"), prevent_initial_call=True)
def refresh(_: int | None) -> str:
    p = services.principal()
    if not p.has_role(ROLE_ANALYST):
        return S.forbidden
    c = services.container()
    last = c.requests.last_request_at(p.user_id)
    if last and (datetime.now(UTC) - last).total_seconds() < c.settings.refresh_rate_limit_seconds:
        return S.refresh_rate_limited
    c.requests.enqueue(p.user_id, "scans")
    c.queries.users.audit(p.user_id, "refresh", {})
    return S.refresh_queued


# ---- "More filters" toggle + badge counting the advanced filters that are applied
@callback(
    Output("f-more", "is_open"),
    Input("f-more-btn", "n_clicks"),
    State("f-more", "is_open"),
    prevent_initial_call=True,
)
def toggle_more(n: int | None, is_open: bool) -> bool:
    return (not is_open) if n else is_open


def advanced_count(f: Any) -> int:
    return sum(1 for name in ADVANCED_FIELDS if getattr(f, name)) + (1 if (f.date_from or f.date_to) else 0)


@callback(Output("f-more-count", "children"), Output("f-more-count", "className"), Input("filters", "data"))
def more_badge(store: dict[str, Any] | None) -> tuple[str, str]:
    n = advanced_count(state.from_store(store))
    return (str(n), "cx-count cx-count-on") if n else ("", "cx-count")
