"""Colour tokens and the shared Plotly template.

Severity uses the reserved status ramp (never reused for categories); engines use the fixed
categorical order. Figures use transparent backgrounds and neutral ink so one figure reads
correctly on both the light and dark Bootstrap themes (data-bs-theme).
"""

from __future__ import annotations

import plotly.graph_objects as go
import plotly.io as pio

SEVERITY_COLORS = {
    "CRITICAL": "#d03b3b",
    "HIGH": "#ec835a",
    "MEDIUM": "#fab219",
    "LOW": "#2a78d6",
    "INFO": "#898781",
}
ENGINE_COLORS = {
    "sast": "#2a78d6",
    "sca": "#eb6834",
    "containers": "#1baf7a",
    "kics": "#eda100",
    "secrets": "#e87ba4",
    "apisec": "#008300",
    "sscs": "#4a3aa7",
}
NEUTRAL = "#898781"
SEQUENTIAL = ["#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95"]  # single hue, light -> dark
GRID = "rgba(137,135,129,0.25)"
INK = "#898781"

TEMPLATE = go.layout.Template(
    layout=go.Layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"family": "Inter, Segoe UI, system-ui, -apple-system, sans-serif", "size": 12, "color": INK},
        margin={"l": 8, "r": 8, "t": 28, "b": 8},
        xaxis={"gridcolor": GRID, "linecolor": GRID, "zeroline": False, "automargin": True},
        yaxis={"gridcolor": GRID, "linecolor": GRID, "zeroline": False, "automargin": True},
        legend={"orientation": "h", "yanchor": "bottom", "y": 1.02, "x": 0, "font": {"size": 11}},
        hoverlabel={"font": {"size": 12}},
        bargap=0.35,
        colorway=list(ENGINE_COLORS.values()),
    )
)
pio.templates["cxdash"] = TEMPLATE
pio.templates.default = "cxdash"

# Plotly's modebar offers a client-side "download as PNG" (spec 11: any chart to PNG).
GRAPH_CONFIG = {
    "displaylogo": False,
    "displayModeBar": "hover",
    "responsive": True,
    "modeBarButtonsToRemove": ["lasso2d", "select2d", "autoScale2d"],
    "toImageButtonOptions": {"format": "png", "scale": 2, "filename": "cxdash-chart"},
}
