"""Overview: KPIs with trend, scanner x severity heatmap, donut, 90-day trend, top risky projects, scan health."""

from __future__ import annotations

from typing import Any

import dash
from dash import Input, Output, callback

from cxdash.domain import SEVERITY_ORDER
from cxdash.ui import services
from cxdash.ui.components import charts
from cxdash.ui.components.cards import chart_panel, delta, stat_card
from cxdash.ui.components.cross_filter import register_clicks
from cxdash.ui.components.layout import grid, page_header, split, stack
from cxdash.ui.theme import SEVERITY_COLORS

dash.register_page(__name__, path="/", name="Overview", title="Overview · Checkmarx One", order=0)

SEVS = SEVERITY_ORDER[:4]
KPI_IDS = {f"kpi-{s}": ("severity", s) for s in SEVS}
ACCENT = "#2563eb"
SPARK_DAYS = 30
DELTA_DAYS = 7


def layout(**_: Any) -> Any:
    cards = [
        stat_card(f"kpi-{s}", s.title(), tone=s, clickable=True, spark=True, with_delta=True) for s in SEVS
    ] + [
        stat_card("kpi-total", "Total open", icon_name="shield", spark=True, with_delta=True),
        stat_card("kpi-sla", "SLA breaches", icon_name="alert", hint="open findings past their SLA"),
        stat_card("kpi-gaps", "Coverage gaps", icon_name="layers", hint="project/branch missing an engine"),
    ]
    return stack(
        [
            page_header(
                "Security overview",
                "Open findings from the latest scan of every project and branch in scope. Click a card, bar or cell to filter the whole dashboard.",
                icon_name="overview",
            ),
            grid(cards, min_col="150px"),
            split(
                chart_panel(
                    "ov-heat",
                    "Scanner × severity",
                    subtitle="Open findings; click a cell to filter",
                    height="310px",
                ),
                chart_panel("ov-donut", "Open findings by scanner", height="310px"),
                (7, 5),
            ),
            chart_panel(
                "ov-trend",
                "Trend by severity",
                subtitle="Open findings per day, from scan summaries",
                height="300px",
            ),
            split(
                chart_panel(
                    "ov-top",
                    "Top 10 risky projects",
                    subtitle="Risk-weighted (critical 10, high 5, medium 2, low 0.5)",
                    height="380px",
                ),
                chart_panel("ov-scans", "Scans, last 7 days", subtitle="Succeeded vs failed", height="380px"),
                (7, 5),
            ),
        ]
    )


register_clicks(["ov-heat", "ov-donut", "ov-top"], KPI_IDS)

_CARD_IDS = [f"kpi-{s}" for s in SEVS] + ["kpi-total"]


def _series(trend: list[dict[str, Any]], key: str) -> list[float]:
    if key == "total":
        return [sum(r[s] for s in SEVERITY_ORDER) for r in trend]
    return [r[key] for r in trend]


@callback(
    [Output(f"{cid}-v", "children") for cid in _CARD_IDS]
    + [Output("kpi-sla-v", "children"), Output("kpi-gaps-v", "children")]
    + [Output(f"{cid}-spark", "figure") for cid in _CARD_IDS]
    + [Output(f"{cid}-delta", "children") for cid in _CARD_IDS]
    + [
        Output("ov-heat", "figure"),
        Output("ov-donut", "figure"),
        Output("ov-trend", "figure"),
        Output("ov-top", "figure"),
        Output("ov-scans", "figure"),
    ],
    Input("filters", "data"),
)
def update(store: dict[str, Any] | None) -> list[Any]:
    f = services.current_filters(store)
    bundle = services.overview_bundle(f)
    kp = bundle["kpis"]
    engines = list(services.container().settings.cx_engines)
    trend = services.trend(f, 90)
    values = [f"{kp[s]:,}" for s in SEVS] + [f"{kp['TOTAL']:,}"]
    sparks, deltas = [], []
    for key in [*SEVS, "total"]:
        series = _series(trend, key)
        color = SEVERITY_COLORS.get(key, ACCENT)
        sparks.append(charts.sparkline(series[-SPARK_DAYS:], color))
        has_history = len(series) > DELTA_DAYS and any(series[:-DELTA_DAYS])
        deltas.append(delta(series[-1] - series[-1 - DELTA_DAYS]) if has_history else delta(None))
    return [
        *values,
        f"{bundle['sla_breaches']:,}",
        f"{bundle['coverage_gaps']:,}",
        *sparks,
        *deltas,
        charts.heatmap(services.matrix_from_bundle(bundle), engines),
        charts.donut_by_engine(bundle["by_engine"]),
        charts.trend_area(trend),
        charts.stacked_hbar(services.top_projects(f, 10), "project", field="project"),
        charts.scans_stacked(services.container().queries.overview.scans_last_days(f, 7)),
    ]
