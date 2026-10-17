"""Executive: one-page summary for leadership, with PDF export (analyst+)."""

from __future__ import annotations

from typing import Any

import dash
from dash import Input, Output, callback

from cxdash.domain import ROLE_ANALYST, SEVERITY_ORDER
from cxdash.ui import services, state
from cxdash.ui.components import charts
from cxdash.ui.components.actions import link_button
from cxdash.ui.components.cards import chart_panel, stat_card
from cxdash.ui.components.layout import grid, page_header, split, stack

dash.register_page(__name__, path="/executive", name="Executive", title="Executive · Checkmarx One", order=10)


def layout(**_: Any) -> Any:
    sevs = SEVERITY_ORDER[:4]
    cards = [stat_card(f"ex-{s}", s.title(), tone=s) for s in sevs] + [
        stat_card("ex-total", "Total open", icon_name="shield"),
        stat_card("ex-sla", "SLA breaches", icon_name="alert"),
        stat_card("ex-gaps", "Coverage gaps", icon_name="layers"),
    ]
    return stack(
        [
            page_header(
                "Executive summary",
                "One-page view for leadership. Exports respect the active filters and are audit-logged.",
                icon_name="report",
                actions=[
                    link_button("ex-html", "Printable HTML", "report"),
                    link_button("ex-pdf", "Export PDF", "download"),
                ],
            ),
            grid(cards, min_col="170px"),
            split(
                chart_panel("ex-trend", "Trend by severity", subtitle="Last 90 days", height="300px"),
                chart_panel("ex-top", "Top 10 projects by risk", height="300px"),
                (7, 5),
            ),
        ]
    )


@callback(
    [Output(f"ex-{s}-v", "children") for s in SEVERITY_ORDER[:4]]
    + [Output("ex-total-v", "children"), Output("ex-sla-v", "children"), Output("ex-gaps-v", "children")]
    + [
        Output("ex-trend", "figure"),
        Output("ex-top", "figure"),
        Output("ex-pdf", "href"),
        Output("ex-html", "href"),
    ],
    Input("filters", "data"),
)
def update(store: dict[str, Any] | None) -> list[Any]:
    f = services.current_filters(store)
    b = services.overview_bundle(f)
    q = state.to_query(f)
    allowed = services.principal().has_role(ROLE_ANALYST)
    return [
        *(f"{b['kpis'][s]:,}" for s in SEVERITY_ORDER[:4]),
        f"{b['kpis']['TOTAL']:,}",
        f"{b['sla_breaches']:,}",
        f"{b['coverage_gaps']:,}",
        charts.trend_area(services.trend(f, 90)),
        charts.stacked_hbar(services.top_projects(f, 10), "project"),
        f"/export/executive.pdf{q}" if allowed else "#",
        f"/export/executive.html{q}" if allowed else "#",
    ]
