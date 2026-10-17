from datetime import UTC, datetime, timedelta

from sqlalchemy import Column, MetaData, String, Table, create_engine, select

from cxdash.metrics.aging import age_days, bucket_for
from cxdash.metrics.mttr import mttr_days_by_severity
from cxdash.metrics.open_rules import OpenRules
from cxdash.metrics.risk import percentile_ranks, risk_score
from cxdash.metrics.sla import days_over_sla, is_breach
from tests.conftest import make_settings

RULES = OpenRules.of(["NOT_EXPLOITABLE"], ["FIXED"])


def test_open_rule_python():
    assert RULES.is_open("TO_VERIFY", "NEW")
    assert RULES.is_open("PROPOSED_NOT_EXPLOITABLE", None)  # open by default (risk #6)
    assert RULES.is_open("custom_state", "recurrent")
    assert not RULES.is_open("not_exploitable", "NEW")
    assert not RULES.is_open("TO_VERIFY", "fixed")


def test_open_rule_sql_matches_python():
    md = MetaData()
    t = Table("f", md, Column("state", String), Column("status", String))
    eng = create_engine("sqlite://")
    md.create_all(eng)
    cases = [
        ("TO_VERIFY", "NEW"),
        ("NOT_EXPLOITABLE", "NEW"),
        ("URGENT", "FIXED"),
        ("confirmed", None),
        ("not_exploitable", None),
    ]
    with eng.begin() as c:
        for st, sta in cases:
            c.execute(t.insert().values(state=st, status=sta))
        rows = c.execute(select(t.c.state, t.c.status).where(RULES.open_sql(t.c.state, t.c.status))).all()
    assert sorted(map(tuple, rows), key=str) == sorted([c for c in cases if RULES.is_open(*c)], key=str)


def test_open_rule_with_empty_closed_sets():
    rules = OpenRules.of([], [])
    assert rules.is_open("NOT_EXPLOITABLE", "FIXED")


def test_risk_score_uses_weights_and_ignores_info():
    s = make_settings()
    score = risk_score({"CRITICAL": 2, "HIGH": 1, "MEDIUM": 3, "LOW": 4, "INFO": 100}, s.risk_weights)
    assert score == 2 * 10 + 5 + 3 * 2 + 4 * 0.5


def test_percentile_rank():
    assert percentile_ranks([]) == []
    assert percentile_ranks([5.0]) == [100.0]
    assert percentile_ranks([0.0]) == [0.0]
    assert percentile_ranks([0.0, 10.0, 20.0, 30.0]) == [0.0, 33.3, 66.7, 100.0]
    assert percentile_ranks([1.0, 1.0, 9.0]) == [0.0, 0.0, 100.0]


def test_age_and_buckets():
    now = datetime(2026, 10, 16, tzinfo=UTC)
    assert age_days(now - timedelta(days=10), None, now) == 10
    assert age_days(None, now - timedelta(days=3), now) == 3
    assert age_days(None, None, now) is None
    assert age_days(now + timedelta(days=2), None, now) == 0
    for d, b in [
        (0, "0-7"),
        (7, "0-7"),
        (8, "8-30"),
        (30, "8-30"),
        (31, "31-90"),
        (90, "31-90"),
        (91, "91-180"),
        (180, "91-180"),
        (181, "180+"),
        (9999, "180+"),
    ]:
        assert bucket_for(d) == b
    assert bucket_for(None) is None


def test_sla_breach():
    s = make_settings()
    assert is_breach("CRITICAL", 8, s)
    assert not is_breach("CRITICAL", 7, s)
    assert is_breach("low", 181, s)
    assert not is_breach("INFO", 10_000, s)
    assert not is_breach("HIGH", None, s)
    assert days_over_sla("HIGH", 40, s) == 10


def test_mttr():
    t0 = datetime(2026, 1, 1, tzinfo=UTC)
    rows = [
        ("HIGH", t0, t0 + timedelta(days=10)),
        ("high", t0, t0 + timedelta(days=20)),
        ("LOW", t0, t0 + timedelta(days=1)),
        ("LOW", t0, t0 - timedelta(days=1)),
    ]
    assert mttr_days_by_severity(rows) == {"HIGH": 15.0, "LOW": 1.0}
