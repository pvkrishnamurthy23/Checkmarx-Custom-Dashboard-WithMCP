"""Removable chips that show every active filter (so nothing is hidden behind a collapsed panel)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from dash import ALL, Input, Output, State, callback, ctx, html, no_update

from cxdash.domain import ENGINE_LABELS
from cxdash.filters import FilterSpec
from cxdash.ui import services, state
from cxdash.ui.components.icons import icon

FIELD_LABELS = {
    "applications": "Application",
    "projects": "Project",
    "tags": "Tag",
    "branches": "Branch",
    "engines": "Scanner",
    "severities": "Severity",
    "states": "State",
    "statuses": "Status",
    "facets": "Chart filter",
}
MAX_LABEL = 40


@dataclass(frozen=True)
class Chip:
    field: str
    value: str  # the raw value to remove
    label: str  # what the user reads


def _short(text: str) -> str:
    return text if len(text) <= MAX_LABEL else text[: MAX_LABEL - 1] + "…"


def chips_for(f: FilterSpec, project_names: dict[str, str] | None = None) -> list[Chip]:
    """Pure function: filter spec -> chips (unit-tested; no Dash needed)."""
    names = project_names or {}
    chips: list[Chip] = []
    for field, label in FIELD_LABELS.items():
        for value in getattr(f, field):
            if field == "projects":
                shown = names.get(value, value)
            elif field == "engines":
                shown = ENGINE_LABELS.get(value, value)
            elif field in ("severities", "states", "statuses"):
                shown = value.replace("_", " ").title()
            elif field == "facets":
                key, _, val = value.partition(":")
                shown = f"{key.replace('_', ' ')}: {val}"
            else:
                shown = value
            chips.append(Chip(field, value, f"{label}: {_short(shown)}"))
    if f.date_from:
        chips.append(Chip("date_from", f.date_from.isoformat(), f"From: {f.date_from.isoformat()}"))
    if f.date_to:
        chips.append(Chip("date_to", f.date_to.isoformat(), f"To: {f.date_to.isoformat()}"))
    if f.text:
        chips.append(Chip("text", f.text, f"Search: {_short(f.text)}"))
    return chips


def chip_button(chip: Chip) -> html.Button:
    return html.Button(
        [html.Span(chip.label, className="cx-chip-text"), icon("x", className="cx-chip-x")],
        id={"type": "chip", "field": chip.field, "value": chip.value},
        n_clicks=0,
        className="cx-chip",
        title=f"Remove filter - {chip.label}",
        **{"aria-label": f"Remove filter {chip.label}"},
    )


def layout() -> html.Div:
    return html.Div(id="f-chips", className="cx-chips", **{"aria-live": "polite"})


@callback(Output("f-chips", "children"), Output("f-chips", "className"), Input("filters", "data"))
def render(store: dict[str, Any] | None) -> tuple[list[html.Button], str]:
    f = state.from_store(store)
    names = services.container().queries.options.project_names(f.projects) if f.projects else {}
    chips = chips_for(f, names)
    return [chip_button(c) for c in chips], "cx-chips cx-chips-on" if chips else "cx-chips"


@callback(
    Output("filters", "data", allow_duplicate=True),
    Input({"type": "chip", "field": ALL, "value": ALL}, "n_clicks"),
    State("filters", "data"),
    prevent_initial_call=True,
)
def remove(_clicks: list[int | None], store: dict[str, Any] | None) -> Any:
    trig = ctx.triggered_id
    # chips are re-created on every filter change; only a real click (value >= 1) may remove a filter
    if not isinstance(trig, dict) or not ctx.triggered or not ctx.triggered[0].get("value"):
        return no_update
    return state.to_store(state.remove_filter_value(state.from_store(store), trig["field"], trig["value"]))
