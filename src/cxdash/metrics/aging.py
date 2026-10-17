"""Finding age and age buckets (spec section 9)."""

from __future__ import annotations

from datetime import UTC, datetime

AGE_BUCKETS: tuple[tuple[str, int, int | None], ...] = (
    ("0-7", 0, 7),
    ("8-30", 8, 30),
    ("31-90", 31, 90),
    ("91-180", 91, 180),
    ("180+", 181, None),
)
BUCKET_LABELS: tuple[str, ...] = tuple(b[0] for b in AGE_BUCKETS)


def _aware(dt: datetime) -> datetime:
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt


def age_days(
    first_found_at: datetime | None, first_seen_at: datetime | None, now: datetime | None = None
) -> int | None:
    """now - first_found_at (fallback: lifecycle first_seen_at); whole days."""
    start = first_found_at or first_seen_at
    if start is None:
        return None
    return max(0, (_aware(now or datetime.now(UTC)) - _aware(start)).days)


def bucket_for(days: int | None) -> str | None:
    if days is None:
        return None
    for label, lo, hi in AGE_BUCKETS:
        if days >= lo and (hi is None or days <= hi):
            return label
    return BUCKET_LABELS[-1]
