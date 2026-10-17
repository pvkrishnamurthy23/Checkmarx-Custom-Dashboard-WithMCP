"""Mean time to remediate (spec section 9)."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime


def mttr_days_by_severity(rows: Iterable[tuple[str, datetime, datetime]]) -> dict[str, float]:
    """Mean of ``resolved_at - first_seen_at`` (days) per severity.

    ``rows`` are (severity, first_seen_at, resolved_at) for lifecycle rows resolved in the window.
    """
    buckets: dict[str, list[float]] = defaultdict(list)
    for severity, first_seen, resolved in rows:
        if resolved >= first_seen:
            buckets[severity.upper()].append((resolved - first_seen).total_seconds() / 86400)
    return {sev: round(sum(v) / len(v), 1) for sev, v in buckets.items() if v}
