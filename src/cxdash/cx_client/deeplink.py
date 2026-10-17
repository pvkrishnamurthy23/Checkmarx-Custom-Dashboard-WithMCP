"""Deep links into the Checkmarx One portal (spec 10.3, risk #5).

The portal URL pattern is an assumption to confirm against the real portal; it
is isolated here and overridable with CX_DEEPLINK_TEMPLATE so no code change is
needed when it turns out different.
"""

from __future__ import annotations

from urllib.parse import quote, urlsplit

_ALLOWED_FIELDS = {"ui_base", "scan_id", "project_id", "engine", "finding_id"}


def validate_template(template: str) -> None:
    import string

    names = {f for _, f, _, _ in string.Formatter().parse(template) if f}
    unknown = names - _ALLOWED_FIELDS
    if unknown:
        raise ValueError(f"unknown placeholder(s) in CX_DEEPLINK_TEMPLATE: {sorted(unknown)}")


def build_deeplink(
    ui_base_url: str, template: str, *, scan_id: str, project_id: str, engine: str, finding_id: str = ""
) -> str | None:
    """Return the portal URL, or ``None`` if the result is not an http(s) URL."""
    url = template.format(
        ui_base=ui_base_url.rstrip("/"),
        scan_id=quote(scan_id, safe=""),
        project_id=quote(project_id, safe=""),
        engine=quote(engine, safe=""),
        finding_id=quote(finding_id, safe=""),
    )
    return url if urlsplit(url).scheme in ("http", "https") else None
