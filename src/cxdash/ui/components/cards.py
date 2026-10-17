"""Reusable content containers: ``panel``, ``chart_panel``, ``stat_card``, ``delta``, ``empty_state``.

Every page is composed from these (plus ``layout.grid``), so spacing, headers, loading states and
accessibility behave identically everywhere. Component ids are stable: ``stat_card(id=...)`` always exposes
``{id}`` (clickable root), ``{id}-v`` (value), ``{id}-delta`` and ``{id}-spark`` (when enabled).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from dash import dcc, html

from cxdash.ui.components.icons import icon
from cxdash.ui.theme import GRAPH_CONFIG, SEVERITY_COLORS

Children = Any


def panel(
    body: Children,
    *,
    title: str | None = None,
    subtitle: str | None = None,
    actions: Children = None,
    icon_name: str | None = None,
    className: str = "",
    id: str | None = None,
    flush: bool = False,
) -> html.Section:
    """Card with an optional header (title, subtitle, right-aligned actions). ``flush`` removes body padding (grids)."""
    header = None
    if title or actions:
        heading = html.Div(
            [
                html.Div(
                    [
                        icon(icon_name, className="cx-panel-icon") if icon_name else None,
                        html.H2(title, className="cx-panel-title"),
                    ],
                    className="cx-panel-titlerow",
                ),
                html.P(subtitle, className="cx-panel-sub") if subtitle else None,
            ],
            className="cx-panel-heading",
        )
        header = html.Header(
            [heading, html.Div(actions, className="cx-panel-actions") if actions else None],
            className="cx-panel-header",
        )
    props: dict[str, Any] = {"className": f"cx-panel {'cx-panel-flush' if flush else ''} {className}".strip()}
    if id:
        props["id"] = id
    return html.Section([header, html.Div(body, className="cx-panel-body")], **props)


def chart_panel(
    graph_id: str,
    title: str,
    *,
    subtitle: str | None = None,
    height: str = "300px",
    actions: Children = None,
    icon_name: str | None = None,
    className: str = "",
) -> html.Section:
    """Panel holding one Plotly graph with a loading indicator and the shared graph config (PNG download on hover)."""
    graph = dcc.Loading(
        dcc.Graph(id=graph_id, config=GRAPH_CONFIG, style={"height": height}, className="cx-graph"),
        type="circle",
        parent_className="cx-loading",
    )
    return panel(
        graph, title=title, subtitle=subtitle, actions=actions, icon_name=icon_name, className=className
    )


def delta(
    change: float | int | None, *, good_when: str = "down", unit: str = "", suffix: str = "vs 7 d ago"
) -> html.Span:
    """Trend chip, e.g. ``▲ 12 vs 7 d ago``. For findings, rising is bad (``good_when='down'``)."""
    if change is None:
        return html.Span("no history", className="cx-delta cx-delta-flat")
    if change == 0:
        return html.Span(f"no change {suffix}".strip(), className="cx-delta cx-delta-flat")
    rising = change > 0
    good = (not rising) if good_when == "down" else rising
    arrow = icon("trend-up", className="cx-delta-arrow" + ("" if rising else " cx-flip"))
    text = f"{abs(change):,.0f}{unit} {suffix}".strip()
    return html.Span([arrow, text], className=f"cx-delta {'cx-delta-good' if good else 'cx-delta-bad'}")


def stat_card(
    card_id: str,
    label: str,
    value: int | str = "–",
    *,
    tone: str | None = None,
    hint: str | None = None,
    icon_name: str | None = None,
    clickable: bool = False,
    spark: bool = False,
    with_delta: bool = False,
) -> html.Div:
    """Headline number. ``tone`` is a severity name (accent colour) or ``None``; ``clickable`` cross-filters on click."""
    accent = SEVERITY_COLORS.get(tone or "", None)
    style = {"--cx-accent": accent} if accent else {}
    header = html.Div(
        [
            html.Span(label, className="cx-stat-label"),
            icon(icon_name, className="cx-stat-icon") if icon_name else None,
        ],
        className="cx-stat-head",
    )
    shown = f"{value:,}" if isinstance(value, int) else value
    body = [
        header,
        html.Div(shown, id=f"{card_id}-v", className="cx-stat-value"),
        html.Div(html.Span(id=f"{card_id}-delta"), className="cx-stat-delta") if with_delta else None,
        html.Div(hint, className="cx-stat-hint") if hint else None,
        dcc.Graph(
            id=f"{card_id}-spark",
            config={"displayModeBar": False, "staticPlot": True},
            className="cx-spark",
            style={"height": "38px"},
        )
        if spark
        else None,
    ]
    props: dict[str, Any] = {
        "id": card_id,
        "n_clicks": 0,
        "className": f"cx-stat{' cx-stat-click' if clickable else ''}{' cx-stat-accent' if accent else ''}",
        "style": style,
    }
    if clickable:
        props.update({"role": "button", "tabIndex": 0, "title": "Click to filter by this severity"})
    return html.Div(body, **props)


def empty_state(title: str, text: str = "", *, icon_name: str = "inbox") -> html.Div:
    return html.Div(
        [
            icon(icon_name, className="cx-empty-icon"),
            html.Div(title, className="cx-empty-title"),
            html.P(text, className="cx-empty-text") if text else None,
        ],
        className="cx-empty",
    )


def kv_list(items: Sequence[tuple[str, Children]]) -> html.Dl:
    """Definition list used by the drawer and admin panels."""
    rows: list[Children] = []
    for label, value in items:
        rows += [html.Dt(label), html.Dd(value)]
    return html.Dl(rows, className="cx-kv")
