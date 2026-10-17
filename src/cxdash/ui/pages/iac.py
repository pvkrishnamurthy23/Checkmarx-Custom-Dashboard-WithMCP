"""IaC (KICS) page: failed rules, platform split, top files, severity bars."""

from __future__ import annotations

import dash

from cxdash.ui.components import charts, scanner_page
from cxdash.ui.components.scanner_page import ChartSpec, ScannerPageSpec

dash.register_page(__name__, path="/iac", name="IaC", title="IaC · Checkmarx One", order=4)

SPEC = ScannerPageSpec(
    key="iac",
    title="Infrastructure as Code (KICS)",
    subtitle="Misconfigurations in Terraform, Kubernetes, Dockerfiles, CloudFormation and more.",
    icon_name="layers",
    engines=("kics",),
    charts=(
        ChartSpec(
            "sev",
            "Open findings by severity",
            lambda q, f, e: charts.severity_bars(dict(q.group_counts(f, "severity", e, limit=5))),
        ),
        ChartSpec(
            "platform",
            "Platform split",
            lambda q, f, e: charts.hbar(
                q.group_counts(f, "category", e, limit=10), field="category", color="#1baf7a"
            ),
        ),
        ChartSpec(
            "rules",
            "Failed rules",
            lambda q, f, e: charts.hbar(q.group_counts(f, "title", e, limit=15), field="title"),
            6,
            "420px",
        ),
        ChartSpec(
            "files",
            "Top files",
            lambda q, f, e: charts.hbar(
                q.group_counts(f, "file_path", e, limit=15), field="file_path", color="#eb6834"
            ),
            6,
            "420px",
        ),
    ),
)
layout = scanner_page.build(SPEC)
