"""SAST page: severity/state bars, top queries, CWE, OWASP, language split, new/recurring/fixed."""

from __future__ import annotations

import dash

from cxdash.ui.components import charts, scanner_page
from cxdash.ui.components.scanner_page import ChartSpec, ScannerPageSpec
from cxdash.ui.theme import ENGINE_COLORS

dash.register_page(__name__, path="/sast", name="SAST", title="SAST · Checkmarx One", order=1)


def _status_fig(q, f, engines):
    counts = q.status_counts(f, engines)
    items = [(k.title(), counts.get(k, 0)) for k in ("NEW", "RECURRENT")] + [
        ("Fixed (30 d)", q.fixed_in_window(f, 30))
    ]
    return charts.column_bars(items, color=ENGINE_COLORS["sast"])


SPEC = ScannerPageSpec(
    key="sast",
    title="SAST",
    subtitle="Static application security testing: vulnerable queries, CWE and OWASP categories, languages and lifecycle status.",
    icon_name="shield",
    engines=("sast",),
    charts=(
        ChartSpec(
            "sevstate",
            "Severity by state",
            lambda q, f, e: charts.severity_state_bars(q.severity_state(f, e)),
        ),
        ChartSpec(
            "queries",
            "Top 15 vulnerability queries",
            lambda q, f, e: charts.hbar(q.group_counts(f, "title", e, limit=15), field="title"),
            6,
            "420px",
        ),
        ChartSpec(
            "cwe",
            "Top 10 CWE",
            lambda q, f, e: charts.hbar(q.group_counts(f, "cwe", e, limit=10), field="cwe", color="#eb6834"),
        ),
        ChartSpec(
            "owasp",
            "OWASP Top 10 category",
            lambda q, f, e: charts.hbar(
                q.group_counts(f, "category", e, limit=10), field="category", color="#1baf7a"
            ),
        ),
        ChartSpec(
            "lang",
            "Language split",
            lambda q, f, e: charts.hbar(
                q.group_counts(f, "language", e, limit=10), field="language", color="#4a3aa7"
            ),
        ),
        ChartSpec("status", "New / Recurring / Fixed", _status_fig),
    ),
)
layout = scanner_page.build(SPEC)
