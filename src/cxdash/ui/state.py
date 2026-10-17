"""Filter state codec: URL query string <-> dcc.Store dict <-> ``FilterSpec`` (spec 10.1).

URL input is untrusted: every value is length-capped and validated before it reaches a query.
"""

from __future__ import annotations

from datetime import date
from typing import Any
from urllib.parse import parse_qs, urlencode

from cxdash.config import ENGINES
from cxdash.domain import SEVERITY_ORDER
from cxdash.filters import FACET_FIELDS, MAX_TEXT_LENGTH, FilterSpec

MAX_VALUES = 50
MAX_VALUE_LEN = 300

# FilterSpec field -> URL parameter
PARAMS: dict[str, str] = {
    "applications": "app", "projects": "prj", "tags": "tag", "branches": "br", "engines": "eng",
    "severities": "sev", "states": "st", "statuses": "ss", "facets": "fc",
}  # fmt: skip
LIST_FIELDS = tuple(PARAMS)
STORE_ID = "filters"


def _clean_list(values: list[str]) -> tuple[str, ...]:
    seen: dict[str, None] = {}
    for v in values[:MAX_VALUES]:
        v = v.strip()[:MAX_VALUE_LEN]
        if v:
            seen.setdefault(v, None)
    return tuple(seen)


def _parse_date(value: str | None) -> date | None:
    try:
        return date.fromisoformat(value) if value else None
    except ValueError:
        return None


def _sanitize(f: FilterSpec) -> FilterSpec:
    """Drop values that cannot be valid so a hand-edited URL never errors a callback."""
    return f.with_values(
        engines=tuple(e for e in (x.lower() for x in f.engines) if e in ENGINES),
        severities=tuple(s for s in (x.upper() for x in f.severities) if s in SEVERITY_ORDER),
        states=tuple(x.upper() for x in f.states),
        statuses=tuple(x.upper() for x in f.statuses),
        facets=tuple(x for x in f.facets if x.partition(":")[0] in FACET_FIELDS),
        text=f.text[:MAX_TEXT_LENGTH],
    )


def from_query(search: str | None) -> FilterSpec:
    try:
        qs = parse_qs((search or "").lstrip("?"), keep_blank_values=False, max_num_fields=100)
    except ValueError:  # too many fields: treat as no filters rather than failing the callback
        return FilterSpec()
    kwargs: dict[str, Any] = {field: _clean_list(qs.get(param, [])) for field, param in PARAMS.items()}
    kwargs["date_from"] = _parse_date((qs.get("from") or [""])[0])
    kwargs["date_to"] = _parse_date((qs.get("to") or [""])[0])
    kwargs["text"] = ((qs.get("q") or [""])[0]).strip()[:MAX_TEXT_LENGTH]
    return _sanitize(FilterSpec(**kwargs))


def to_query(f: FilterSpec) -> str:
    """Canonical query string ('' when no filter is active)."""
    items: list[tuple[str, str]] = []
    for field, param in PARAMS.items():
        items += [(param, v) for v in getattr(f, field)]
    if f.date_from:
        items.append(("from", f.date_from.isoformat()))
    if f.date_to:
        items.append(("to", f.date_to.isoformat()))
    if f.text:
        items.append(("q", f.text))
    return ("?" + urlencode(items)) if items else ""


def to_store(f: FilterSpec) -> dict[str, Any]:
    return f.model_dump(mode="json")


def from_store(data: dict[str, Any] | None) -> FilterSpec:
    if not data:
        return FilterSpec()
    try:
        return _sanitize(
            FilterSpec.model_validate({k: v for k, v in data.items() if k != "scope_applications"})
        )
    except ValueError:
        return FilterSpec()


# ------------------------------------------------------------------ cross-filtering (chart clicks)
CLICK_FIELDS = {
    "engine": "engines",
    "severity": "severities",
    "state": "states",
    "status": "statuses",
    "project": "projects",
}


def parse_click(click: dict[str, Any] | None) -> list[tuple[str, str]]:
    """Chart points carry ``customdata`` = ``"field:value|field:value"``; returns [(field, value)]."""
    try:
        raw = click["points"][0]["customdata"]  # type: ignore[index]
    except (TypeError, KeyError, IndexError):
        return []
    if isinstance(raw, list):
        raw = raw[0] if raw else ""
    pairs = []
    for part in str(raw).split("|"):
        field, _, value = part.partition(":")
        if field and value:
            pairs.append((field, value))
    return pairs


def apply_click(f: FilterSpec, pairs: list[tuple[str, str]]) -> FilterSpec:
    """Clicking sets the value; clicking the same value again clears it (spec 10.3)."""
    for field, value in pairs:
        if field in CLICK_FIELDS:
            attr = CLICK_FIELDS[field]
            current = getattr(f, attr)
            f = f.with_values(**{attr: () if current == (value,) else (value,)})
        elif field in FACET_FIELDS:
            entry = f"{field}:{value}"
            f = f.with_values(facets=() if f.facets == (entry,) else (entry,))
    return _sanitize(f)


def click_value(field: str, value: object) -> str:
    return f"{field}:{value}"


def remove_filter_value(f: FilterSpec, field: str, value: str) -> FilterSpec:
    """Drop one active filter value (used by the removable filter chips)."""
    if field in LIST_FIELDS:
        return f.with_values(**{field: tuple(v for v in getattr(f, field) if v != value)})
    if field in ("date_from", "date_to"):
        return f.with_values(**{field: None})
    if field == "text":
        return f.with_values(text="")
    return f
