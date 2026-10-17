"""Load test (spec 17, Milestone 4): seed synthetic data, then time the page queries.

    python -m cxdash.devtools.loadtest --projects 5000 --findings-per-engine 40 --runs 20

Uses DATABASE_URL from .env (point it at a throw-away PostgreSQL whose name contains "demo" or "load").
Budget: p95 under 2 s per page query (spec 2.3). Tune indexes if a query exceeds it.
"""

from __future__ import annotations

import argparse
import statistics
import sys
import time
from collections.abc import Callable
from typing import Any

from sqlalchemy import func, select

from cxdash.config import get_settings
from cxdash.db import models as m
from cxdash.db.queries import DashboardQueries
from cxdash.db.session import Database, engine_from_settings
from cxdash.devtools.seed import seed_demo
from cxdash.filters import FilterSpec

BUDGET_SECONDS = 2.0


def percentile(values: list[float], p: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, round(p * (len(ordered) - 1)))]


def timed(fn: Callable[[], Any], runs: int) -> list[float]:
    out = []
    for _ in range(runs):
        t = time.perf_counter()
        fn()
        out.append(time.perf_counter() - t)
    return out


def scenarios(q: DashboardQueries) -> dict[str, Callable[[], Any]]:
    f = FilterSpec()
    sast = ("sast",)
    return {
        "overview.kpis+heatmap": lambda: q.overview.open_by_engine_severity(f),
        "overview.trend(90d)": lambda: q.overview.trend(f, 90),
        "overview.top_projects": lambda: q.overview.top_projects(f, 10),
        "overview.sla_breach_count": lambda: q.overview.sla_breach_count(f),
        "overview.coverage": lambda: q.overview.coverage_gap_count(f),
        "findings.page(first 100)": lambda: q.findings.page(
            f, 0, 100, [{"colId": "severity", "sort": "asc"}]
        ),
        "findings.page(deep offset)": lambda: q.findings.page(f, 50_000, 50_100),
        "findings.page(text search)": lambda: q.findings.page(f.with_values(text="sql"), 0, 100),
        "findings.group_counts(title)": lambda: q.findings.group_counts(f, "title", sast, limit=15),
        "findings.age_buckets": lambda: q.findings.age_buckets(f),
        "projects.table": lambda: q.projects.table(f),
        "projects.scan_health": lambda: q.projects.scan_health(f),
        "analytics.mttr+burndown": lambda: (q.projects.mttr(f), q.projects.burndown(f)),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--projects", type=int, default=500)
    ap.add_argument("--findings-per-engine", type=int, default=20)
    ap.add_argument("--runs", type=int, default=10)
    ap.add_argument("--skip-seed", action="store_true", help="reuse data already in the database")
    args = ap.parse_args(argv)

    settings = get_settings()
    url = settings.database_url.get_secret_value()
    if url.startswith("postgresql") and not any(w in url for w in ("demo", "load")):
        print(
            "refusing to seed: the PostgreSQL URL must contain 'demo' or 'load' (safety check)",
            file=sys.stderr,
        )
        return 2
    db = Database(engine_from_settings(settings))
    if not args.skip_seed:
        t = time.perf_counter()
        info = seed_demo(db, settings, projects=args.projects, findings_per_engine=args.findings_per_engine)
        print(f"seeded {info} in {time.perf_counter() - t:.1f}s")
    with db.session() as s:
        print("finding rows:", s.scalar(select(func.count()).select_from(m.Finding)))
    q = DashboardQueries(db, settings)
    worst = 0.0
    print(f"{'query':<34}{'p50 ms':>10}{'p95 ms':>10}  status")
    for name, fn in scenarios(q).items():
        samples = timed(fn, args.runs)
        p95 = percentile(samples, 0.95)
        worst = max(worst, p95)
        print(
            f"{name:<34}{statistics.median(samples) * 1000:>10.0f}{p95 * 1000:>10.0f}  {'OK' if p95 < BUDGET_SECONDS else 'OVER BUDGET'}"
        )
    return 0 if worst < BUDGET_SECONDS else 1


if __name__ == "__main__":
    sys.exit(main())
