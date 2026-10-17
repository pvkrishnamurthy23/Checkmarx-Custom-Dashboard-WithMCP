from datetime import date

from cxdash.filters import FilterSpec
from cxdash.ui import state


def test_roundtrip_through_query_string():
    f = FilterSpec(
        applications=("Payments",),
        engines=("sast", "sca"),
        severities=("HIGH",),
        date_from=date(2026, 1, 1),
        text="sql injection",
        facets=("title:SQL Injection, v2",),
    )
    assert state.from_query(state.to_query(f)) == f


def test_empty_filters_give_empty_query():
    assert state.to_query(FilterSpec()) == ""
    assert state.from_query("") == FilterSpec()
    assert state.from_query(None) == FilterSpec()


def test_hostile_urls_are_sanitised():
    f = state.from_query(
        "?sev=bogus&sev=critical&eng=evil&eng=SAST&from=notadate&fc=badfield:x&fc=title:ok&q=" + "a" * 5000
    )
    assert f.severities == ("CRITICAL",)
    assert f.engines == ("sast",)
    assert f.date_from is None
    assert f.facets == ("title:ok",)
    assert len(f.text) == 200


def test_value_count_is_capped():
    qs = "?" + "&".join(f"app=a{i}" for i in range(90))
    assert len(state.from_query(qs).applications) == state.MAX_VALUES
    assert (
        state.from_query("?" + "&".join(f"app=a{i}" for i in range(500))) == FilterSpec()
    )  # absurd input -> no filters


def test_click_toggle_sets_then_clears():
    f = state.apply_click(FilterSpec(), [("severity", "HIGH")])
    assert f.severities == ("HIGH",)
    assert state.apply_click(f, [("severity", "HIGH")]).severities == ()
    both = state.apply_click(
        FilterSpec(), state.parse_click({"points": [{"customdata": "engine:sast|severity:CRITICAL"}]})
    )
    assert both.engines == ("sast",) and both.severities == ("CRITICAL",)


def test_click_facet_and_garbage():
    f = state.apply_click(FilterSpec(), [("cwe", "CWE-79")])
    assert f.facets == ("cwe:CWE-79",)
    assert state.parse_click(None) == [] and state.parse_click({"points": []}) == []
    assert state.apply_click(FilterSpec(), [("nonsense", "x")]) == FilterSpec()


def test_from_store_tolerates_garbage():
    assert state.from_store({"severities": 5}) == FilterSpec()
    assert (
        state.from_store({"scope_applications": ["x"]}).scope_applications is None
    )  # a client can never set scope
