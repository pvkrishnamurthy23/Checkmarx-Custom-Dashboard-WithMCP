"""SLA breach logic (spec section 9): open finding older than SLA_DAYS_<severity>; INFO excluded."""

from __future__ import annotations

from cxdash.config import Settings


def sla_days_for(severity: str, settings: Settings) -> int | None:
    return settings.sla_days(severity)


def is_breach(severity: str, age_days: int | None, settings: Settings) -> bool:
    limit = settings.sla_days(severity)
    return limit is not None and age_days is not None and age_days > limit


def days_over_sla(severity: str, age_days: int | None, settings: Settings) -> int | None:
    limit = settings.sla_days(severity)
    if limit is None or age_days is None:
        return None
    return age_days - limit
