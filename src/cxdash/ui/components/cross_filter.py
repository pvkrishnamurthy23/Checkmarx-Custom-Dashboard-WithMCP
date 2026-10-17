"""Cross-filtering: chart/KPI clicks write into the filter store (spec 10.3)."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from dash import Input, Output, State, callback, ctx, no_update

from cxdash.ui import state


def register_clicks(chart_ids: Iterable[str], kpi_values: dict[str, tuple[str, str]] | None = None) -> None:
    """``kpi_values`` maps a KPI element id to the (field, value) a click applies."""
    charts = list(chart_ids)
    kpis = kpi_values or {}
    inputs = [Input(c, "clickData") for c in charts] + [Input(k, "n_clicks") for k in kpis]

    @callback(
        Output("filters", "data", allow_duplicate=True),
        inputs,
        State("filters", "data"),
        prevent_initial_call=True,
    )
    def on_click(*args: Any) -> Any:
        store = args[-1]
        trig = ctx.triggered_id
        # Dash re-fires callbacks when a page's components first render; a real click has a truthy value
        # (n_clicks >= 1 / clickData present), the initial render does not.
        if not ctx.triggered or not ctx.triggered[0].get("value"):
            return no_update
        if trig in kpis:
            pairs = [kpis[trig]]
        elif trig in charts:
            pairs = state.parse_click(args[charts.index(trig)])
        else:
            return no_update
        if not pairs:
            return no_update
        return state.to_store(state.apply_click(state.from_store(store), pairs))
