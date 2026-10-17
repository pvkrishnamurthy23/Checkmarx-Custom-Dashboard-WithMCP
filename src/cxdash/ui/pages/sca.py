"""SCA page: severity, vulnerable packages, CVEs, CVSS histogram, fixable vs not.

Not yet implemented (needs real payload fixtures to locate the fields; see docs/TRACEABILITY.md):
direct-vs-transitive split and the exploitable (network attack vector) toggle.
"""

from __future__ import annotations

from typing import Any

import dash

from cxdash.ui.components import charts, scanner_page
from cxdash.ui.components.scanner_page import ChartSpec, ScannerPageSpec

dash.register_page(__name__, path="/sca", name="SCA", title="SCA · Checkmarx One", order=2)


def _fixable_fig(q: Any, f: Any, e: Any) -> Any:
    split = q.fixable_split(f, e)
    if not split:
        return charts.empty_figure()
    labels = list(split)
    return charts.donut_generic(
        labels, [split[k] for k in labels], ["#1baf7a" if k == "Fix available" else "#898781" for k in labels]
    )


SPEC = ScannerPageSpec(
    key="sca",
    title="SCA",
    subtitle="Open-source dependency risk: vulnerable packages, CVEs, severity of the CVSS score and whether a fix exists.",
    icon_name="package",
    engines=("sca",),
    charts=(
        ChartSpec(
            "sev",
            "Open findings by severity",
            lambda q, f, e: charts.severity_bars(dict(q.group_counts(f, "severity", e, limit=5))),
        ),
        ChartSpec(
            "pkgs",
            "Top vulnerable packages",
            lambda q, f, e: charts.hbar(q.group_counts(f, "package", e, limit=15), field="package"),
            6,
            "420px",
        ),
        ChartSpec(
            "cves",
            "Top CVEs",
            lambda q, f, e: charts.hbar(q.group_counts(f, "cve", e, limit=15), field="cve", color="#eb6834"),
            6,
            "420px",
        ),
        ChartSpec(
            "cvss",
            "CVSS distribution",
            lambda q, f, e: charts.column_bars(
                [(f"{b}–{b + 1}", n) for b, n in q.cvss_histogram(f, e)], color="#d03b3b"
            ),
        ),
        ChartSpec("fix", "Fixable vs not fixable", _fixable_fig),
    ),
    extra_kpis=(
        (
            "fixpct",
            "Fix available",
            lambda q, f, e: f"{p}%" if (p := q.fix_available_pct(f, e)) is not None else "–",
        ),
    ),
)
layout = scanner_page.build(SPEC)
