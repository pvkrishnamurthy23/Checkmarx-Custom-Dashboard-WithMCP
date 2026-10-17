"""The reusable UI component library: structure, stable ids, validation. No Dash server needed."""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest
from dash import html

from cxdash.devtools.build_icons import build_css
from cxdash.filters import FilterSpec
from cxdash.ui import state
from cxdash.ui.components.badges import TONES, engine_tag, pill, severity_badge
from cxdash.ui.components.cards import chart_panel, delta, empty_state, kv_list, panel, stat_card
from cxdash.ui.components.filter_chips import chips_for
from cxdash.ui.components.icons import icon
from cxdash.ui.components.layout import NAV, grid, page_header, sidebar, split, stack, visible_nav
from cxdash.ui.icon_set import ICONS

ASSETS = Path(__file__).resolve().parents[2] / "src" / "cxdash" / "ui" / "assets"


def walk(component):
    """Yield every Dash component in a tree."""
    yield component
    children = getattr(component, "children", None)
    if isinstance(children, (list, tuple)):
        for c in children:
            if c is not None and not isinstance(c, (str, int, float)):
                yield from walk(c)
    elif children is not None and not isinstance(children, (str, int, float)):
        yield from walk(children)


def ids(component):
    return {getattr(c, "id", None) for c in walk(component)} - {None}


# ----------------------------------------------------------------------------------- icons
def test_generated_icon_css_is_up_to_date():
    assert (ASSETS / "30-icons.css").read_text(encoding="utf-8") == build_css(), (
        "run: python -m cxdash.devtools.build_icons"
    )


def test_icon_component_and_validation():
    assert "cx-icon-shield" in icon("shield").className
    assert icon("shield").to_plotly_json()["props"]["aria-hidden"] == "true"
    labelled = icon("alert", title="Problem").to_plotly_json()["props"]
    assert labelled["role"] == "img" and labelled["aria-label"] == "Problem"
    with pytest.raises(ValueError, match="unknown icon"):
        icon("does-not-exist")


def test_every_icon_used_by_navigation_and_components_exists():
    assert {n.icon_name for n in NAV} <= set(ICONS)
    css = (ASSETS / "30-icons.css").read_text(encoding="utf-8")
    assert all(f".cx-icon-{name}{{" in css for name in ICONS)


# ----------------------------------------------------------------------------------- badges
def test_pill_tones_are_validated():
    for tone in TONES:
        assert f"cx-pill-{tone}" in pill("x", tone).className
    with pytest.raises(ValueError):
        pill("x", "rainbow")


def test_severity_and_engine_badges_always_carry_text():
    assert "Critical" in str(severity_badge("CRITICAL").children)
    assert "Info" in str(severity_badge("not-a-severity").children)  # unknown -> INFO, as everywhere else
    assert "SAST" in str(engine_tag("sast").children)


# ----------------------------------------------------------------------------------- cards
def test_stat_card_has_stable_ids_and_options():
    plain = stat_card("kpi-x", "Label", 1234, hint="hint")
    assert ids(plain) == {"kpi-x", "kpi-x-v"}
    rich = stat_card("kpi-y", "Label", tone="CRITICAL", clickable=True, spark=True, with_delta=True)
    assert {"kpi-y", "kpi-y-v", "kpi-y-delta", "kpi-y-spark"} <= ids(rich)
    props = rich.to_plotly_json()["props"]
    assert props["role"] == "button" and props["tabIndex"] == 0 and "cx-stat-click" in props["className"]
    assert "--cx-accent" in props["style"]
    assert next(c for c in walk(plain) if getattr(c, "id", None) == "kpi-x-v").children == "1,234"


def test_panel_header_only_when_needed():
    assert "cx-panel-header" not in str(panel(html.Div("body")).to_plotly_json())
    framed = panel(
        html.Div("body"),
        title="T",
        subtitle="S",
        actions=html.Button("a"),
        icon_name="gear",
        flush=True,
        id="p1",
    )
    text = str(framed.to_plotly_json())
    assert "cx-panel-title" in text and "cx-panel-sub" in text and "cx-panel-flush" in text
    assert framed.id == "p1"


def test_chart_panel_exposes_the_graph_id_and_shared_config():
    cp = chart_panel("my-graph", "Title", subtitle="sub", height="123px")
    graph = next(c for c in walk(cp) if getattr(c, "id", None) == "my-graph")
    assert graph.style == {"height": "123px"} and graph.config["displaylogo"] is False


def test_delta_semantics_rising_findings_are_bad():
    assert "cx-delta-bad" in delta(5).className
    assert "cx-delta-good" in delta(-5).className
    assert "cx-delta-good" in delta(5, good_when="up").className
    assert "cx-delta-flat" in delta(0).className and "cx-delta-flat" in delta(None).className
    assert "12" in str(delta(12).children)


def test_empty_state_and_kv_list():
    assert "Nothing" in str(empty_state("Nothing here", "details").to_plotly_json())
    kv = kv_list([("A", "1"), ("B", html.B("2"))])
    assert [c.__class__.__name__ for c in kv.children] == ["Dt", "Dd", "Dt", "Dd"]


# ----------------------------------------------------------------------------------- layout
def test_grid_split_stack_helpers_set_css_custom_properties():
    assert grid([html.Div()], min_col="150px").style == {"--cx-min": "150px"}
    assert split(html.Div(), html.Div(), (7, 5)).style == {"--cx-cols": "minmax(0, 7fr) minmax(0, 5fr)"}
    assert "cx-stack" in stack([]).className
    header = page_header("Title", "sub", actions=html.Button("x"), icon_name="gear")
    assert "cx-page-title" in str(header.to_plotly_json())


def test_navigation_hides_admin_for_non_admins_and_ids_are_pattern_ids():
    assert [n.label for n in visible_nav(False)][-1] == "Executive"
    assert visible_nav(True)[-1].label == "Admin"
    nav = sidebar(visible_nav(True))
    links = [c for c in walk(nav) if isinstance(getattr(c, "id", None), dict)]
    assert {c.id["path"] for c in links} == {n.path for n in NAV}
    assert all(c.id["type"] == "nav" for c in links)


# ----------------------------------------------------------------------------------- filter chips
def test_chips_describe_every_kind_of_filter():
    f = FilterSpec(
        applications=("Payments",), projects=("p1",), tags=("team:pay",), branches=("master",), engines=("sast", "kics"),
        severities=("HIGH",), states=("TO_VERIFY",), statuses=("NEW",), facets=("cwe:CWE-79",), text="sql",
        date_from=date(2026, 1, 1), date_to=date(2026, 2, 1),
    )  # fmt: skip
    chips = chips_for(f, {"p1": "payments-api"})
    labels = [c.label for c in chips]
    assert (
        "Project: payments-api" in labels and "Scanner: IaC (KICS)" in labels and "State: To Verify" in labels
    )
    assert "Chart filter: cwe: CWE-79" in labels and "Search: sql" in labels and "From: 2026-01-01" in labels
    assert len(chips) == 13
    assert chips_for(FilterSpec()) == []


def test_long_chip_labels_are_truncated():
    chip = chips_for(FilterSpec(applications=("x" * 200,)))[0]
    assert len(chip.label) < 70 and chip.label.endswith("…")


def test_removing_each_chip_restores_the_unfiltered_spec():
    f = FilterSpec(
        applications=("A",), projects=("p1",), engines=("sast",), severities=("HIGH",), statuses=("NEW",), facets=("cwe:CWE-79",),
        text="sql", date_from=date(2026, 1, 1), date_to=date(2026, 2, 1),
    )  # fmt: skip
    for chip in chips_for(f):
        f = state.remove_filter_value(f, chip.field, chip.value)
    assert f == FilterSpec()


def test_removing_one_value_keeps_the_others():
    f = FilterSpec(engines=("sast", "sca"))
    assert state.remove_filter_value(f, "engines", "sast").engines == ("sca",)
    assert state.remove_filter_value(f, "nonsense", "x") == f
