"""Figure builders. Pure functions: data in, ``go.Figure`` out (easy to unit test).

Every point carries ``customdata`` = "field:value" so a click can cross-filter (state.parse_click).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import plotly.graph_objects as go

from cxdash.domain import ENGINE_LABELS, SEVERITY_ORDER
from cxdash.ui.state import click_value
from cxdash.ui.theme import ENGINE_COLORS, GRID, INK, NEUTRAL, SEQUENTIAL, SEVERITY_COLORS

BAR_RADIUS = 4


def empty_figure(message: str = "No data for these filters") -> go.Figure:
    fig = go.Figure()
    fig.add_annotation(
        text=message,
        showarrow=False,
        font={"size": 14, "color": INK},
        xref="paper",
        yref="paper",
        x=0.5,
        y=0.5,
    )
    fig.update_xaxes(visible=False)
    fig.update_yaxes(visible=False)
    fig.update_layout(height=260)
    return fig


def severity_bars(counts: dict[str, int], height: int = 260) -> go.Figure:
    sevs = [s for s in SEVERITY_ORDER if counts.get(s)]
    if not sevs:
        return empty_figure()
    fig = go.Figure(
        go.Bar(
            x=sevs, y=[counts[s] for s in sevs], marker={"color": [SEVERITY_COLORS[s] for s in sevs], "cornerradius": BAR_RADIUS},
            customdata=[click_value("severity", s) for s in sevs], text=[f"{counts[s]:,}" for s in sevs], textposition="outside",
            hovertemplate="%{x}: %{y:,}<extra></extra>", cliponaxis=False,
        )
    )  # fmt: skip
    fig.update_layout(height=height, showlegend=False, yaxis={"title": None}, xaxis={"title": None})
    return fig


def donut_by_engine(totals: dict[str, int], height: int = 300) -> go.Figure:
    engines = [e for e in ENGINE_LABELS if totals.get(e)]
    if not engines:
        return empty_figure()
    fig = go.Figure(
        go.Pie(
            labels=[ENGINE_LABELS[e] for e in engines], values=[totals[e] for e in engines], hole=0.58, sort=False,
            marker={"colors": [ENGINE_COLORS[e] for e in engines], "line": {"width": 2, "color": "rgba(0,0,0,0)"}},
            customdata=[click_value("engine", e) for e in engines], textinfo="percent", hovertemplate="%{label}: %{value:,} (%{percent})<extra></extra>",
        )
    )  # fmt: skip
    total = sum(totals[e] for e in engines)
    fig.add_annotation(
        text=f"<b>{total:,}</b><br>open",
        showarrow=False,
        font={"size": 16, "color": INK},
        x=0.5,
        y=0.5,
        xref="paper",
        yref="paper",
    )
    fig.update_layout(height=height, legend={"orientation": "v", "x": 1.0, "y": 0.5})
    return fig


def sparkline(values: Sequence[float], color: str, *, height: int = 38) -> go.Figure:
    """Axis-free trend line for stat cards (static, no hover)."""
    fig = go.Figure(
        go.Scatter(
            y=list(values), mode="lines", line={"width": 1.8, "color": color, "shape": "spline", "smoothing": 0.6},
            fill="tozeroy", fillcolor=_alpha(color, 0.14), hoverinfo="skip",
        )
    )  # fmt: skip
    fig.update_xaxes(visible=False, fixedrange=True)
    fig.update_yaxes(visible=False, fixedrange=True, rangemode="tozero")
    fig.update_layout(height=height, margin={"l": 0, "r": 0, "t": 2, "b": 0}, showlegend=False)
    return fig


def heatmap(matrix: dict[tuple[str, str], int], engines: Sequence[str], height: int = 300) -> go.Figure:
    if not any(matrix.values()):
        return empty_figure()
    sevs = list(SEVERITY_ORDER)
    z = [[matrix.get((e, s), 0) for s in sevs] for e in engines]
    custom = [[f"{click_value('engine', e)}|{click_value('severity', s)}" for s in sevs] for e in engines]
    fig = go.Figure(
        go.Heatmap(
            z=z, x=sevs, y=[ENGINE_LABELS[e] for e in engines], customdata=custom, colorscale=[[i / (len(SEQUENTIAL) - 1), c] for i, c in enumerate(SEQUENTIAL)],
            text=[[f"{v:,}" for v in row] for row in z], texttemplate="%{text}", hovertemplate="%{y} / %{x}: %{z:,}<extra></extra>",
            xgap=2, ygap=2, showscale=False,
        )
    )  # fmt: skip
    fig.update_yaxes(autorange="reversed")
    fig.update_xaxes(side="top")
    fig.update_layout(height=height)
    return fig


def trend_area(rows: list[dict[str, Any]], height: int = 300) -> go.Figure:
    if not rows or not any(r[s] for r in rows for s in SEVERITY_ORDER):
        return empty_figure("No scan history in this window")
    fig = go.Figure()
    for sev in reversed(SEVERITY_ORDER):
        fig.add_scatter(
            x=[r["date"] for r in rows], y=[r[sev] for r in rows], name=sev.title(), stackgroup="one", mode="lines",
            line={"width": 1.5, "color": SEVERITY_COLORS[sev]}, fillcolor=_alpha(SEVERITY_COLORS[sev], 0.55),
            hovertemplate="%{y:,}<extra>" + sev.title() + "</extra>",
        )  # fmt: skip
    fig.update_layout(height=height, hovermode="x unified")
    return fig


def _alpha(hex_color: str, a: float) -> str:
    h = hex_color.lstrip("#")
    r, g, b = (int(h[i : i + 2], 16) for i in (0, 2, 4))
    return f"rgba({r},{g},{b},{a})"


def hbar(
    items: Sequence[tuple[str, int]],
    *,
    field: str | None = None,
    color: str = "#2a78d6",
    height: int | None = None,
    max_label: int = 38,
) -> go.Figure:
    """Horizontal ranked bars; click filters by ``field`` when given."""
    if not items:
        return empty_figure()
    labels = [_trim(k, max_label) for k, _ in items]
    fig = go.Figure(
        go.Bar(
            y=labels, x=[v for _, v in items], orientation="h", marker={"color": color, "cornerradius": BAR_RADIUS},
            customdata=[click_value(field, k) for k, _ in items] if field else None, text=[f"{v:,}" for _, v in items], textposition="outside",
            hovertext=[k for k, _ in items], hovertemplate="%{hovertext}: %{x:,}<extra></extra>", cliponaxis=False,
        )
    )  # fmt: skip
    fig.update_yaxes(autorange="reversed")
    fig.update_layout(height=height or max(220, 28 * len(items) + 40), showlegend=False)
    return fig


def _trim(text: str, n: int) -> str:
    return text if len(text) <= n else text[: n - 1] + "…"


def stacked_hbar(
    rows: list[dict[str, Any]], label_key: str, *, field: str | None = None, height: int | None = None
) -> go.Figure:
    """Rows like {'project': 'x', 'CRITICAL': 1, ...} -> stacked severity bars."""
    if not rows:
        return empty_figure()
    fig = go.Figure()
    labels = [_trim(str(r[label_key]), 30) for r in rows]
    for sev in SEVERITY_ORDER:
        vals = [r.get(sev, 0) for r in rows]
        if not any(vals):
            continue
        fig.add_bar(
            y=labels, x=vals, name=sev.title(), orientation="h", marker={"color": SEVERITY_COLORS[sev]},
            customdata=[click_value(field, r.get("project_id", r[label_key])) for r in rows] if field else None,
            hovertext=[str(r[label_key]) for r in rows],
            hovertemplate="%{hovertext}: %{x:,}<extra>" + sev.title() + "</extra>",
        )  # fmt: skip
    fig.update_yaxes(autorange="reversed")
    fig.update_layout(
        barmode="stack",
        height=height or max(240, 30 * len(rows) + 60),
        bargap=0.3,
        legend={"traceorder": "normal"},
    )
    fig.update_traces(marker_line={"width": 2, "color": "rgba(0,0,0,0)"})
    return fig


def scans_stacked(rows: list[dict[str, Any]], height: int = 260) -> go.Figure:
    if not rows or not any(r["success"] or r["failed"] or r["other"] for r in rows):
        return empty_figure("No scans in the last 7 days")
    fig = go.Figure()
    for key, color, name in (
        ("success", "#0ca30c", "Succeeded"),
        ("failed", "#d03b3b", "Failed"),
        ("other", NEUTRAL, "Other"),
    ):
        fig.add_bar(
            x=[r["date"] for r in rows],
            y=[r[key] for r in rows],
            name=name,
            marker={"color": color},
            hovertemplate="%{y}<extra>" + name + "</extra>",
        )
    fig.update_layout(barmode="stack", height=height)
    return fig


def column_bars(
    items: Sequence[tuple[str, int]], *, color: str = "#2a78d6", field: str | None = None, height: int = 260
) -> go.Figure:
    if not items or not any(v for _, v in items):
        return empty_figure()
    fig = go.Figure(
        go.Bar(
            x=[k for k, _ in items], y=[v for _, v in items], marker={"color": color, "cornerradius": BAR_RADIUS},
            customdata=[click_value(field, k) for k, _ in items] if field else None, text=[f"{v:,}" for _, v in items], textposition="outside",
            hovertemplate="%{x}: %{y:,}<extra></extra>", cliponaxis=False,
        )
    )  # fmt: skip
    fig.update_layout(height=height, showlegend=False)
    return fig


def grouped_weekly(rows: list[dict[str, Any]], height: int = 280) -> go.Figure:
    if not rows or not any(r["opened"] or r["closed"] for r in rows):
        return empty_figure("No lifecycle data yet")
    fig = go.Figure()
    fig.add_bar(
        x=[r["week"] for r in rows],
        y=[r["opened"] for r in rows],
        name="Opened",
        marker={"color": "#d03b3b", "cornerradius": BAR_RADIUS},
    )
    fig.add_bar(
        x=[r["week"] for r in rows],
        y=[r["closed"] for r in rows],
        name="Closed",
        marker={"color": "#2a78d6", "cornerradius": BAR_RADIUS},
    )
    fig.update_layout(barmode="group", height=height, bargap=0.25)
    return fig


def donut_generic(
    labels: Sequence[str], values: Sequence[int], colors: Sequence[str], height: int = 260
) -> go.Figure:
    if not values or not any(values):
        return empty_figure()
    fig = go.Figure(
        go.Pie(
            labels=list(labels),
            values=list(values),
            hole=0.58,
            sort=False,
            marker={"colors": list(colors), "line": {"width": 2, "color": "rgba(0,0,0,0)"}},
        )
    )
    fig.update_layout(height=height, legend={"orientation": "v", "x": 1.0, "y": 0.5})
    return fig


def severity_state_bars(rows: list[tuple[str, str, int]], height: int = 280) -> go.Figure:
    """Severity x state grouped bars (SAST page)."""
    if not rows:
        return empty_figure()
    states = sorted({r[1] for r in rows})
    fig = go.Figure()
    shades = SEQUENTIAL[1:] + SEQUENTIAL[:1]
    for i, st in enumerate(states):
        by = {sev: n for sev, s, n in rows if s == st}
        fig.add_bar(
            x=list(SEVERITY_ORDER), y=[by.get(s, 0) for s in SEVERITY_ORDER], name=st.replace("_", " ").title(),
            marker={"color": shades[i % len(shades)] if len(states) > 1 else "#2a78d6"},
            customdata=[f"{click_value('severity', s)}|{click_value('state', st)}" for s in SEVERITY_ORDER],
        )  # fmt: skip
    fig.update_layout(barmode="stack", height=height)
    return fig


def grid_line_color() -> str:
    return GRID
