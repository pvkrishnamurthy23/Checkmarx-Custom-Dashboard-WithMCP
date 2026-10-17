"""Small status primitives: severity badge, generic pill, engine tag."""

from __future__ import annotations

from dash import html

from cxdash.domain import ENGINE_LABELS, Severity
from cxdash.ui.theme import ENGINE_COLORS, SEVERITY_COLORS

TONES = ("neutral", "info", "success", "warning", "danger")


def pill(text: str, tone: str = "neutral", *, className: str = "", title: str | None = None) -> html.Span:
    """Rounded label. ``tone`` is one of ``TONES``; colour never carries meaning alone (text always present)."""
    if tone not in TONES:
        raise ValueError(f"unknown tone {tone!r}")
    props: dict[str, object] = {"className": f"cx-pill cx-pill-{tone} {className}".strip()}
    if title:
        props["title"] = title
    return html.Span(text, **props)


def severity_badge(severity: str) -> html.Span:
    sev = Severity.parse(severity)
    return html.Span(
        [html.Span(className="cx-dot", style={"backgroundColor": SEVERITY_COLORS[sev]}), sev.value.title()],
        className="cx-sev-badge",
    )


def engine_tag(engine: str) -> html.Span:
    return html.Span(
        [
            html.Span(className="cx-dot", style={"backgroundColor": ENGINE_COLORS.get(engine, "#898781")}),
            ENGINE_LABELS.get(engine, engine),
        ],
        className="cx-sev-badge",
    )
