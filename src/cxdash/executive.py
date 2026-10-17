"""Executive summary data + rendering (shared by the Executive page and the PDF export)."""

from __future__ import annotations

import base64
from datetime import UTC, datetime
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape

from cxdash.container import Container
from cxdash.exporting import figure_to_png, html_to_pdf
from cxdash.filters import FilterSpec

_env = Environment(
    loader=PackageLoader("cxdash", "templates"), autoescape=select_autoescape(["html", "j2"], default=True)
)


def filters_label(f: FilterSpec) -> str:
    parts = [
        f"{k}={','.join(map(str, v))}" for k, v in f.model_dump(mode="json").items() if v and k != "text"
    ]
    if f.text:
        parts.append(f"text={f.text!r}")
    return "; ".join(parts) or "none"


def build(c: Container, f: FilterSpec, *, with_png: bool = False) -> dict[str, Any]:
    ov = c.queries.overview
    trend = ov.trend(f, 90)
    kpis = ov.kpis(f)
    last = c.queries.admin.last_sync()
    data: dict[str, Any] = {
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        "synced": last.strftime("%Y-%m-%d %H:%M UTC") if last else "never",
        "filters_label": filters_label(f),
        "kpis": kpis,
        "sla_breaches": ov.sla_breach_count(f),
        "coverage_gaps": ov.coverage_gap_count(f),
        "top_projects": ov.top_projects(f, 10),
        "trend": trend,
        "trend_sample": [*trend[::15], trend[-1]] if trend else [],
        "trend_png": None,
    }
    if with_png:
        from cxdash.ui.components.charts import trend_area

        png = figure_to_png(trend_area(trend), 900, 360)
        data["trend_png"] = base64.b64encode(png).decode() if png else None
    return data


def render_html(data: dict[str, Any]) -> str:
    return _env.get_template("executive.html.j2").render(d=data)


def render_pdf(data: dict[str, Any]) -> bytes | None:
    return html_to_pdf(render_html(data))
