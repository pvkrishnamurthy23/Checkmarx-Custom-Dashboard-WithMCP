"""Secrets, API Security and SSCS page (spec 10.2): one page, three engine groups, one grid."""

from __future__ import annotations

import dash

from cxdash.ui.components import charts, scanner_page
from cxdash.ui.components.scanner_page import ChartSpec, ScannerPageSpec

dash.register_page(
    __name__,
    path="/secrets-apisec",
    name="Secrets & API Security",
    title="Secrets, API Security, SSCS · Checkmarx One",
    order=5,
)

SPEC = ScannerPageSpec(
    key="sas",
    title="Secrets, API Security and SSCS",
    subtitle="Exposed secrets, API risks mapped to the OWASP API Top 10, and software supply chain scorecard checks.",
    icon_name="key",
    engines=("secrets", "apisec", "sscs"),
    charts=(
        ChartSpec(
            "stype",
            "Secrets by type",
            lambda q, f, e: (
                charts.hbar(
                    q.group_counts(f, "title", [x for x in e if x == "secrets"], limit=10),
                    field="title",
                    color="#e87ba4",
                )
                if "secrets" in e
                else charts.empty_figure("Secrets engine not selected")
            ),
        ),
        ChartSpec(
            "svalid",
            "Secrets by validity",
            lambda q, f, e: (
                charts.hbar(
                    q.group_counts(f, "category", [x for x in e if x == "secrets"], limit=5),
                    field="category",
                    color="#e87ba4",
                )
                if "secrets" in e
                else charts.empty_figure("Secrets engine not selected")
            ),
        ),
        ChartSpec(
            "owasp",
            "OWASP API Top 10",
            lambda q, f, e: (
                charts.hbar(
                    q.group_counts(f, "category", [x for x in e if x == "apisec"], limit=10),
                    field="category",
                    color="#008300",
                )
                if "apisec" in e
                else charts.empty_figure("API Security engine not selected")
            ),
        ),
        ChartSpec(
            "scorecard",
            "SSCS scorecard check results",
            lambda q, f, e: (
                charts.hbar(
                    q.group_counts(f, "title", [x for x in e if x == "sscs"], limit=12),
                    field="title",
                    color="#4a3aa7",
                )
                if "sscs" in e
                else charts.empty_figure("SSCS engine not selected")
            ),
        ),
    ),
    extra_kpis=(("repos", "Projects affected", lambda q, f, e: f"{q.distinct_projects(f, e):,}"),),
)
layout = scanner_page.build(SPEC)
