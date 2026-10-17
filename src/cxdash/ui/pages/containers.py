"""Containers page: images by open Critical/High, CVEs by package, fix-available %, severity bars."""

from __future__ import annotations

import dash

from cxdash.ui.components import charts, scanner_page
from cxdash.ui.components.scanner_page import ChartSpec, ScannerPageSpec

dash.register_page(
    __name__, path="/containers", name="Containers", title="Containers · Checkmarx One", order=3
)


def _images(q, f, e):
    rows = q.image_ranking(f, 15)
    return (
        charts.hbar([(r["image"], r["critical_high"]) for r in rows], field="image", color="#d03b3b")
        if rows
        else charts.empty_figure()
    )


SPEC = ScannerPageSpec(
    key="containers",
    title="Containers",
    subtitle="Vulnerabilities found in container images referenced by your repositories.",
    icon_name="container",
    engines=("containers",),
    charts=(
        ChartSpec(
            "sev",
            "Open findings by severity",
            lambda q, f, e: charts.severity_bars(dict(q.group_counts(f, "severity", e, limit=5))),
        ),
        ChartSpec("images", "Images ranked by open Critical + High", _images, 6, "420px"),
        ChartSpec(
            "pkg",
            "Vulnerable packages",
            lambda q, f, e: charts.hbar(
                q.group_counts(f, "package", e, limit=15), field="package", color="#eb6834"
            ),
            6,
            "420px",
        ),
        ChartSpec(
            "cve",
            "Top CVEs",
            lambda q, f, e: charts.hbar(q.group_counts(f, "cve", e, limit=15), field="cve"),
            6,
            "420px",
        ),
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
