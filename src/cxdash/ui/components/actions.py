"""Reusable action controls (download links, icon buttons) so toolbars look the same on every page."""

from __future__ import annotations

from dash import html

from cxdash.ui.components.icons import icon


def link_button(
    button_id: str, label: str, icon_name: str, *, href: str = "#", new_tab: bool = True
) -> html.A:
    """Anchor styled as a button (exports); ``href`` is filled in by a callback so it always carries the active filters."""
    props: dict[str, object] = {"id": button_id, "href": href, "className": "cx-btn-link"}
    if new_tab:
        props.update({"target": "_blank", "rel": "noopener"})
    return html.A([icon(icon_name), html.Span(label)], **props)
