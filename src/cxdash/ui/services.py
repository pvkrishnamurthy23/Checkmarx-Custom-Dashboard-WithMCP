"""Glue between Dash callbacks and the application core.

Callbacks stay thin: they decode filters, call a service function, build a figure.
"""

from __future__ import annotations

from typing import Any

from flask import g, has_request_context

from cxdash.container import Container, build_container
from cxdash.domain import ENGINE_LABELS, SEVERITY_ORDER
from cxdash.filters import FilterSpec
from cxdash.security.principal import ANONYMOUS_DEV, Principal
from cxdash.ui import state

_container: Container | None = None


def set_container(c: Container) -> None:
    global _container
    _container = c


def container() -> Container:
    global _container
    if _container is None:
        _container = build_container()
    return _container


def principal() -> Principal:
    if has_request_context():
        p = getattr(g, "principal", None)
        if p is not None:
            return p  # type: ignore[no-any-return]
    return ANONYMOUS_DEV


def current_filters(store_data: dict[str, Any] | None) -> FilterSpec:
    """Decode the store and inject the caller's row-level scope (never taken from the client)."""
    f = state.from_store(store_data)
    return f.with_values(scope_applications=principal().scope_applications)


# --------------------------------------------------------------------- cached bundles (JSON-safe)
def overview_bundle(f: FilterSpec) -> dict[str, Any]:
    c = container()

    def compute() -> dict[str, Any]:
        ov = c.queries.overview
        matrix = ov.open_by_engine_severity(f)
        by_engine: dict[str, int] = {}
        for (e, _), n in matrix.items():
            by_engine[e] = by_engine.get(e, 0) + n
        kp = {sev: sum(n for (_, s), n in matrix.items() if s == sev) for sev in SEVERITY_ORDER}
        kp["TOTAL"] = sum(kp.values())
        return {
            "kpis": kp,
            "matrix": [[e, s, n] for (e, s), n in matrix.items()],
            "by_engine": by_engine,
            "sla_breaches": ov.sla_breach_count(f),
            "coverage_gaps": ov.coverage_gap_count(f),
        }

    return c.cache.get_or_compute("overview", f.fingerprint(), compute)


def trend(f: FilterSpec, days: int = 90) -> list[dict[str, Any]]:
    c = container()
    return c.cache.get_or_compute(f"trend{days}", f.fingerprint(), lambda: c.queries.overview.trend(f, days))


def top_projects(f: FilterSpec, n: int = 10) -> list[dict[str, Any]]:
    c = container()
    return c.cache.get_or_compute(f"top{n}", f.fingerprint(), lambda: c.queries.overview.top_projects(f, n))


def matrix_from_bundle(bundle: dict[str, Any]) -> dict[tuple[str, str], int]:
    return {(e, s): n for e, s, n in bundle["matrix"]}


def engine_label(e: str) -> str:
    return ENGINE_LABELS.get(e, e)
