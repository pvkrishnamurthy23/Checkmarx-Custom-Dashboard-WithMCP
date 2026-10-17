"""Icon component. Glyphs live in ``ui/icon_set.py`` and are compiled to ``assets/30-icons.css``."""

from __future__ import annotations

from dash import html

from cxdash.ui.icon_set import ICONS


def icon(name: str, *, className: str = "", title: str | None = None) -> html.Span:
    """An inline icon that inherits the surrounding text colour (CSS mask, no image request)."""
    if name not in ICONS:
        raise ValueError(f"unknown icon {name!r}")
    props: dict[str, object] = {
        "className": f"cx-icon cx-icon-{name} {className}".strip(),
        "aria-hidden": "true",
    }
    if title:
        props.update({"title": title, "aria-hidden": "false", "role": "img", "aria-label": title})
    return html.Span(**props)
