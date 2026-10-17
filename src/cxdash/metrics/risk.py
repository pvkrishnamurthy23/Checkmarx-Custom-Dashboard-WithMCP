"""Project risk score (spec section 9)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence


def risk_score(open_by_severity: Mapping[str, int | float], weights: Mapping[str, float]) -> float:
    """sum(weight[severity] x open_count); INFO weight is 0 by default."""
    return float(sum(weights.get(sev.upper(), 0.0) * n for sev, n in open_by_severity.items()))


def percentile_ranks(scores: Sequence[float]) -> list[float]:
    """Normalise raw scores to 0-100 by percentile rank (ties share the lowest rank).

    A project with a raw score of 0 is always 0, so clean projects never look risky.
    """
    n = len(scores)
    if n == 0:
        return []
    if n == 1:
        return [100.0 if scores[0] > 0 else 0.0]
    ordered = sorted(scores)
    first_index: dict[float, int] = {}
    for i, s in enumerate(ordered):
        first_index.setdefault(s, i)
    return [0.0 if s <= 0 else round(100.0 * first_index[s] / (n - 1), 1) for s in scores]
