"""Finding detail drawer (spec 10.3): normalised fields, collapsible raw JSON, age/SLA badge, deep link."""

from __future__ import annotations

import json
from typing import Any

import dash_bootstrap_components as dbc
from dash import Input, Output, callback, dcc, html

from cxdash.cx_client.deeplink import build_deeplink
from cxdash.domain import ENGINE_LABELS
from cxdash.ui import services
from cxdash.ui.components.actions import link_button
from cxdash.ui.components.badges import engine_tag, pill, severity_badge
from cxdash.ui.components.cards import empty_state, kv_list
from cxdash.ui.strings import S

FIELDS = [
    ("Project", "project"),
    ("Branch", "branch"),
    ("State", "state"),
    ("Status", "status"),
    ("CWE", "cwe"),
    ("CVE", "cve"),
    ("CVSS", "cvss"),
    ("Package", "package"),
    ("Version", "package_version"),
    ("Fixed in", "fixed_version"),
    ("Image", "image"),
    ("File", "file_path"),
    ("Line", "line"),
    ("Language", "language"),
    ("Category", "category"),
    ("First found", "first_found_at"),
    ("Found at", "found_at"),
    ("Scan", "scan_id"),
    ("Similarity id", "similarity_id"),
]
RAW_JSON_LIMIT = 20_000


def layout() -> html.Div:
    return html.Div(
        [
            dcc.Store(id="drawer-target"),
            dbc.Offcanvas(
                id="drawer",
                title="Finding",
                placement="end",
                is_open=False,
                scrollable=True,
                style={"width": "580px", "maxWidth": "95vw"},
            ),
        ]
    )


def _badges(d: dict[str, Any]) -> html.Div:
    items: list[Any] = [severity_badge(d["severity"]), engine_tag(d["engine"])]
    items.append(pill("Open", "warning") if d["is_open"] else pill("Closed", "success"))
    if d["age_days"] is not None:
        items.append(pill(f"{d['age_days']} days old"))
    over = d.get("sla_over_days")
    if over is not None and d["is_open"]:
        items.append(
            pill(f"SLA breached by {over} d", "danger")
            if over > 0
            else pill(f"Within SLA ({d['sla_days']} d)", "success")
        )
    return html.Div(items, className="cx-drawer-badges")


def render(d: dict[str, Any]) -> list[Any]:
    c = services.container()
    link = build_deeplink(
        c.settings.ui_base_url,
        c.settings.cx_deeplink_template,
        scan_id=d["scan_id"],
        project_id=d["project_id"],
        engine=d["engine"],
        finding_id=d["finding_id"],
    )
    raw = json.dumps(d.get("raw_json") or {}, indent=2, default=str)
    truncated = len(raw) > RAW_JSON_LIMIT
    fields = [(label, str(d[key])) for label, key in FIELDS if d.get(key) not in (None, "")]
    # Every value is rendered as text by React (never as HTML), so untrusted finding content cannot inject markup.
    body: list[Any] = [
        html.H2(d["title"] or "(untitled)", className="cx-drawer-title"),
        _badges(d),
        link_button("drawer-open-cx", S.open_in_cx, "external", href=link) if link else None,
        html.P(d["description"], className="cx-drawer-desc") if d.get("description") else None,
        html.Div(kv_list(fields), className="cx-drawer-section"),
        html.Details(
            [
                html.Summary("Raw JSON"),
                html.Pre((raw[:RAW_JSON_LIMIT] + "\n… truncated") if truncated else raw, className="cx-raw"),
            ],
            className="cx-drawer-section",
        ),
    ]
    return [b for b in body if b is not None]


@callback(
    Output("drawer", "is_open"),
    Output("drawer", "children"),
    Output("drawer", "title"),
    Input("drawer-target", "data"),
    prevent_initial_call=True,
)
def show(target: dict[str, str] | None) -> tuple[bool, Any, str]:
    if not target:
        return False, [], "Finding"
    detail = services.container().queries.findings.detail(target["scan_id"], target["finding_id"])
    if detail is None:
        return (
            True,
            empty_state("This finding is no longer available", "It may have been purged after a newer scan."),
            "Finding",
        )
    return True, render(detail), ENGINE_LABELS.get(detail["engine"], detail["engine"].upper())
