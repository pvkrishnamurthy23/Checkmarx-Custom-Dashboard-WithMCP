from __future__ import annotations

import pytest

PAGES = [
    "/",
    "/sast",
    "/sca",
    "/containers",
    "/iac",
    "/secrets-apisec",
    "/projects",
    "/scan-health",
    "/admin",
    "/executive",
]


def num(text: str) -> int:
    return int(text.replace(",", ""))


@pytest.mark.parametrize("path", PAGES)
def test_every_page_renders(client, path):
    assert client.get(path).status_code == 200


def test_layout_and_dependencies_load(client):
    assert client.get("/_dash-layout").status_code == 200
    assert len(client.get("/_dash-dependencies").json) > 40


def test_healthz_and_metrics(client):
    body = client.get("/healthz").json
    assert body["status"] == "ok" and body["db"] == "up"
    assert "cxdash_sync_lag_seconds" in client.get("/metrics").get_data(as_text=True)


def test_security_headers(client):
    h = client.get("/").headers
    assert "frame-ancestors 'none'" in h["Content-Security-Policy"]
    assert "object-src 'none'" in h["Content-Security-Policy"]
    assert h["X-Content-Type-Options"] == "nosniff" and h["X-Frame-Options"] == "DENY"


def test_overview_callback_returns_kpis_and_figures(caller):
    out = caller.call("kpi-CRITICAL-v.children", {"filters.data": {}})
    assert num(out["kpi-total-v"]["children"]) > 0
    assert out["ov-heat"]["figure"]["data"]
    assert out["ov-trend"]["figure"]["data"]


def test_overview_respects_filters(caller):
    base = caller.call("kpi-CRITICAL-v.children", {"filters.data": {}})
    sast = caller.call("kpi-CRITICAL-v.children", {"filters.data": {"engines": ["sast"]}})
    assert 0 < num(sast["kpi-total-v"]["children"]) < num(base["kpi-total-v"]["children"])


def test_scanner_pages_update(caller):
    for key in ("sast", "sca", "containers", "iac", "sas"):
        out = caller.call(f"{key}-kpi-total-v.children", {"filters.data": {}})
        assert num(out[f"{key}-kpi-total-v"]["children"]) >= 0
        figs = [v for k, v in out.items() if k.startswith(f"{key}-c-")]
        assert figs and all("figure" in f for f in figs)


def test_grid_getrows_pages_and_sorts(caller):
    req = {
        "startRow": 0,
        "endRow": 50,
        "sortModel": [{"colId": "severity", "sort": "asc"}],
        "filterModel": {},
    }
    resp = caller.call("sast-grid.getRowsResponse", {"sast-grid.getRowsRequest": req, "filters.data": {}})[
        "sast-grid"
    ]["getRowsResponse"]
    assert resp["rowCount"] > 0 and len(resp["rowData"]) <= 50
    assert {r["engine"] for r in resp["rowData"]} == {"sast"}
    assert all("||" in r["row_id"] for r in resp["rowData"])
    sevs = [r["severity"] for r in resp["rowData"]]
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    assert sevs == sorted(sevs, key=order.index)


def test_grid_inputs_cannot_inject_sql(caller):
    req = {
        "startRow": 0,
        "endRow": 10,
        "filterModel": {
            "title": {"filter": "'; DROP TABLE finding;--%_", "type": "contains"},
            "evil; drop": {"filter": "x"},
        },
        "sortModel": [{"colId": "title; DROP TABLE finding", "sort": "asc"}],
    }
    out = caller.call(
        "sast-grid.getRowsResponse",
        {"sast-grid.getRowsRequest": req, "filters.data": {"text": "' OR 1=1 --"}},
    )
    assert out["sast-grid"]["getRowsResponse"]["rowCount"] == 0
    after = caller.call(
        "sast-grid.getRowsResponse",
        {"sast-grid.getRowsRequest": {"startRow": 0, "endRow": 5}, "filters.data": {}},
    )
    assert after["sast-grid"]["getRowsResponse"]["rowCount"] > 0  # table still exists


def test_projects_health_admin(caller):
    rows = caller.call("pj-grid.rowData", {"filters.data": {}})["pj-grid"]["rowData"]
    assert rows and rows[0]["risk"] >= rows[-1]["risk"]
    health = caller.call("sh-rate-v.children", {"filters.data": {}})
    assert health["sh-rate-v"]["children"].endswith("%")
    admin = caller.call("ad-runs.rowData", {"url.pathname": "/admin"})
    assert admin["ad-runs"]["rowData"]
    config = admin["ad-config"]["children"]
    assert "********" in config and "test-api-key-value" not in config


def test_drawer_shows_detail_and_deeplink(caller, seeded):
    from cxdash.filters import FilterSpec

    _, c = seeded
    rows, _ = c.queries.findings.page(FilterSpec(), 0, 1)
    out = caller.call(
        "drawer.is_open",
        {"drawer-target.data": {"scan_id": rows[0]["scan_id"], "finding_id": rows[0]["finding_id"]}},
    )
    assert out["drawer"]["is_open"] is True
    assert "Open in Checkmarx One" in str(out["drawer"]["children"])
    missing = caller.call("drawer.is_open", {"drawer-target.data": {"scan_id": "x", "finding_id": "y"}})
    assert "no longer available" in str(missing["drawer"]["children"])


def test_url_to_state(caller):
    out = caller.call(
        "filters.data", {"url.search": "?sev=HIGH&eng=sast&q=sql", "filters.data": {}}, via="url.search"
    )
    store = out["filters"]["data"]
    assert store["severities"] == ["HIGH"] and store["engines"] == ["sast"] and store["text"] == "sql"


def test_every_navigation_target_is_a_registered_page():
    import dash

    from cxdash.ui.components.layout import NAV

    registered = {p["path"] for p in dash.page_registry.values()}
    assert {n.path for n in NAV} <= registered


def test_active_filter_chips_are_rendered(caller):
    out = caller.call(
        "f-chips.children", {"filters.data": {"severities": ["HIGH"], "engines": ["sast"], "text": "sql"}}
    )
    text = str(out["f-chips"]["children"])
    assert "Severity: High" in text and "Scanner: SAST" in text and "Search: sql" in text
    assert out["f-chips"]["className"] == "cx-chips cx-chips-on"
    empty = caller.call("f-chips.children", {"filters.data": {}})
    assert empty["f-chips"]["children"] == [] and empty["f-chips"]["className"] == "cx-chips"


def test_more_filters_badge_counts_advanced_filters(caller):
    out = caller.call(
        "f-more-count.children", {"filters.data": {"states": ["TO_VERIFY"], "date_from": "2026-01-01"}}
    )
    assert out["f-more-count"]["children"] == "2" and "cx-count-on" in out["f-more-count"]["className"]
    none = caller.call("f-more-count.children", {"filters.data": {"severities": ["HIGH"]}})
    assert none["f-more-count"]["children"] == ""  # severity is a primary filter, not an advanced one


def test_overview_cards_get_sparklines_and_deltas(caller):
    out = caller.call("kpi-CRITICAL-v.children", {"filters.data": {}})
    assert out["kpi-CRITICAL-spark"]["figure"]["data"] and out["kpi-total-spark"]["figure"]["data"]
    assert "7 d ago" in str(out["kpi-HIGH-delta"]["children"]) or "no history" in str(
        out["kpi-HIGH-delta"]["children"]
    )
