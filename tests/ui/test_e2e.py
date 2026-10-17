"""Browser test (spec section 15, UI): filter -> URL -> chart update, with CSP active.

Run with ``pytest -m e2e`` (needs ``pip install -e .[e2e]`` and ``playwright install chromium``).
"""

from __future__ import annotations

import os
import threading

import pytest
from werkzeug.serving import make_server

pytestmark = pytest.mark.e2e
playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def base_url(app):
    srv = make_server("127.0.0.1", 0, app.server, threaded=True)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


@pytest.fixture(scope="module")
def page(base_url):
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch()
        pg = browser.new_page(viewport={"width": 1500, "height": 1000})
        pg.errors = []  # type: ignore[attr-defined]
        pg.on("console", lambda msg: pg.errors.append(msg.text) if msg.type == "error" else None)  # type: ignore[attr-defined]
        pg.on("pageerror", lambda exc: pg.errors.append(str(exc)))  # type: ignore[attr-defined]
        yield pg
        browser.close()


def test_overview_renders_without_csp_or_js_errors(page, base_url):
    page.goto(base_url + "/")
    page.wait_for_selector("#kpi-total-v:not(:has-text('–'))", timeout=20000)
    assert page.inner_text("#kpi-total-v").replace(",", "").isdigit()
    page.wait_for_selector("#ov-heat .main-svg", timeout=20000)
    shot = os.environ.get("CXDASH_E2E_SHOT")
    if shot:
        page.screenshot(path=shot, full_page=True)
    assert [e for e in page.errors if "favicon" not in e] == []


def test_kpi_click_filters_and_round_trips_through_url(page, base_url):
    page.goto(base_url + "/")
    page.wait_for_selector("#kpi-total-v:not(:has-text('–'))", timeout=20000)
    before = page.inner_text("#kpi-total-v")
    page.click("#kpi-CRITICAL")
    page.wait_for_url("**sev=CRITICAL**", timeout=10000)
    page.wait_for_function(
        "(b) => { const t = document.querySelector('#kpi-total-v').innerText;"
        " return t !== b && t === document.querySelector('#kpi-CRITICAL-v').innerText; }",
        arg=before,
        timeout=20000,
    )
    page.reload()  # shareable URL restores the filter into the controls
    page.wait_for_selector("#f-sev", timeout=10000)
    page.wait_for_function("document.querySelector('#kpi-HIGH-v').innerText.length > 0", timeout=15000)
    assert "sev=CRITICAL" in page.url
    page.click("#kpi-CRITICAL")  # same click clears
    page.wait_for_function("!location.search.includes('sev=')", timeout=10000)


def test_sast_grid_loads_rows_and_drawer_opens(page, base_url):
    page.goto(base_url + "/sast")
    page.wait_for_selector("#sast-grid .ag-center-cols-container .ag-cell", state="attached", timeout=25000)
    page.locator("#sast-grid").scroll_into_view_if_needed()
    rows = page.locator("#sast-grid .ag-center-cols-container .ag-row")
    page.wait_for_function(
        "document.querySelectorAll('#sast-grid .ag-center-cols-container .ag-row').length > 3", timeout=10000
    )
    assert rows.count() > 3
    rows.first.locator("[col-id='title']").click()
    page.wait_for_selector("#drawer .offcanvas-body", timeout=10000)
    assert page.inner_text("#drawer").strip() != ""
    assert page.locator("#drawer-open-cx").count() == 1  # deep link button


def test_theme_switch_sets_attribute(page, base_url):
    page.goto(base_url + "/")
    page.click("#theme-switch")
    page.wait_for_function("document.documentElement.getAttribute('data-bs-theme') === 'dark'", timeout=5000)


ALL_PAGES = [
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


def test_no_console_errors_on_any_page(page, base_url):
    for path in ALL_PAGES:
        page.errors.clear()
        page.goto(base_url + path)
        page.wait_for_selector(".cx-page-title", timeout=20000)
        page.wait_for_timeout(1500)
        assert [e for e in page.errors if "favicon" not in e] == [], f"console errors on {path}"


def test_chips_show_active_filters_and_removing_one_updates_the_url(page, base_url):
    page.goto(base_url + "/?sev=HIGH&eng=sast")
    page.wait_for_selector("#f-chips .cx-chip", timeout=20000)
    assert page.locator("#f-chips .cx-chip").count() == 2
    page.locator("#f-chips .cx-chip", has_text="Severity: High").click()
    page.wait_for_function("!location.search.includes('sev=')", timeout=10000)
    assert page.locator("#f-chips .cx-chip").count() == 1
    assert "eng=sast" in page.url


def test_sidebar_navigation_keeps_the_active_filters(page, base_url):
    page.goto(base_url + "/?sev=CRITICAL")
    page.wait_for_selector(".cx-nav-link.active", timeout=20000)
    page.locator(".cx-nav-link", has_text="SAST").click()
    page.wait_for_function(
        "location.pathname === '/sast' && location.search.includes('sev=CRITICAL')", timeout=10000
    )
    page.wait_for_function(
        "[...document.querySelectorAll('.cx-nav-link')].find(a => a.innerText.trim() === 'SAST').classList.contains('active')",
        timeout=5000,
    )


def test_more_filters_panel_opens_and_shows_a_badge(page, base_url):
    page.goto(base_url + "/?st=TO_VERIFY")
    page.wait_for_selector("#f-more-btn", timeout=20000)
    page.wait_for_function("document.querySelector('#f-more-count').innerText === '1'", timeout=10000)
    page.click("#f-more-btn")
    page.wait_for_selector("#f-state", state="visible", timeout=5000)
