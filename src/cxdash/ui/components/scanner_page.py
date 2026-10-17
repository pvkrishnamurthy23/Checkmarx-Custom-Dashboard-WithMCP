"""Declarative scanner pages (OCP): a page lists its charts, the factory wires layout + callbacks + grid.

Adding a scanner page means writing a ``ScannerPageSpec`` with chart builders, nothing else.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

import plotly.graph_objects as go
from dash import Input, Output, callback, html

from cxdash.db.queries.findings import FindingQueries
from cxdash.domain import SEVERITY_ORDER
from cxdash.filters import FilterSpec
from cxdash.ui import services
from cxdash.ui.components import findings_grid
from cxdash.ui.components.cards import chart_panel, panel, stat_card
from cxdash.ui.components.cross_filter import register_clicks
from cxdash.ui.components.layout import grid, page_header, stack

Builder = Callable[[FindingQueries, FilterSpec, Sequence[str]], go.Figure]


@dataclass(frozen=True)
class ChartSpec:
    key: str
    title: str
    build: Builder
    width: int = 6  # 12 = full row; anything else shares the row (auto-fit grid)
    height: str = "300px"
    subtitle: str = ""


@dataclass(frozen=True)
class ScannerPageSpec:
    key: str  # unique prefix for component ids
    title: str
    engines: tuple[str, ...]
    charts: tuple[ChartSpec, ...]
    subtitle: str = ""
    icon_name: str = "shield"
    extra_kpis: tuple[tuple[str, str, Callable[[FindingQueries, FilterSpec, Sequence[str]], str]], ...] = (
        field(default=())
    )


def build(spec: ScannerPageSpec) -> Callable[..., html.Div]:
    """Register callbacks for ``spec`` and return the page ``layout`` function."""
    pid = lambda name: f"{spec.key}-{name}"  # noqa: E731
    grid_id = pid("grid")
    kpi_ids = {pid(f"kpi-{s}"): ("severity", s) for s in SEVERITY_ORDER[:4]}
    chart_ids = [pid(f"c-{c.key}") for c in spec.charts]

    def layout(**_: Any) -> Any:
        panels = [
            html.Div(
                chart_panel(pid(f"c-{c.key}"), c.title, subtitle=c.subtitle or None, height=c.height),
                style={"gridColumn": "1 / -1"} if c.width >= 12 else None,
            )
            for c in spec.charts
        ]
        cards = [stat_card(pid(f"kpi-{s}"), s.title(), tone=s, clickable=True) for s in SEVERITY_ORDER[:4]]
        cards.append(stat_card(pid("kpi-total"), "Total open", icon_name=spec.icon_name))
        cards += [stat_card(pid(f"x-{k}"), label) for k, label, _ in spec.extra_kpis]
        return stack(
            [
                page_header(spec.title, spec.subtitle or None, icon_name=spec.icon_name),
                grid(cards, min_col="170px"),
                grid(panels, min_col="440px"),
                panel(
                    findings_grid.grid_component(grid_id),
                    title="Findings",
                    subtitle="Open findings in the current filter. Click a row for details; sort and filter columns in the grid.",
                    icon_name="search",
                    flush=True,
                ),
            ]
        )

    outputs = (
        [Output(pid(f"kpi-{s}-v"), "children") for s in SEVERITY_ORDER[:4]]
        + [Output(pid("kpi-total-v"), "children")]
        + [Output(pid(f"x-{k}-v"), "children") for k, _, _ in spec.extra_kpis]
        + [Output(cid, "figure") for cid in chart_ids]
    )

    @callback(outputs, Input("filters", "data"))
    def update(store: dict[str, Any] | None) -> list[Any]:
        f = services.current_filters(store)
        c = services.container()
        q = c.queries.findings
        page_engines = tuple(e for e in spec.engines if not f.engines or e in f.engines)
        counts = dict.fromkeys(SEVERITY_ORDER, 0)
        if page_engines:
            for (_engine, sev), n in c.queries.overview.open_by_engine_severity(
                f.with_values(engines=page_engines)
            ).items():
                counts[sev] += n
        extra = [fn(q, f, page_engines) for _, _, fn in spec.extra_kpis]
        figs = [cs.build(q, f, page_engines) for cs in spec.charts]
        return [*(f"{counts[s]:,}" for s in SEVERITY_ORDER[:4]), f"{sum(counts.values()):,}", *extra, *figs]

    register_clicks(chart_ids, kpi_ids)
    findings_grid.register(grid_id, spec.engines, spec.key)
    return layout
