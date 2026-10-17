"""Scan health: success rate, duration percentiles, engine failures, stale projects, coverage gaps."""

from __future__ import annotations

from typing import Any

import dash
from dash import Input, Output, callback

from cxdash.domain import ENGINE_LABELS
from cxdash.ui import services
from cxdash.ui.components import charts
from cxdash.ui.components.cards import chart_panel, panel, stat_card
from cxdash.ui.components.layout import grid, page_header, split, stack
from cxdash.ui.components.simple_grid import simple_grid

dash.register_page(
    __name__, path="/scan-health", name="Scan Health", title="Scan Health · Checkmarx One", order=7
)


def layout(**_: Any) -> Any:
    return stack(
        [
            page_header(
                "Scan health",
                "Reliability of the last 30 days of scans: success rate, duration, engine failures, stale projects and coverage gaps.",
                icon_name="pulse",
            ),
            grid(
                [
                    stat_card("sh-rate", "Success rate", icon_name="check"),
                    stat_card("sh-failed", "Failed scans", icon_name="alert"),
                    stat_card("sh-p50", "Median duration", icon_name="clock"),
                    stat_card("sh-p90", "p90 duration", icon_name="clock"),
                    stat_card(
                        "sh-stale", "Stale projects", icon_name="folder", hint="no completed scan recently"
                    ),
                ],
                min_col="180px",
            ),
            split(
                chart_panel(
                    "sh-engines",
                    "Engine failures and skips",
                    subtitle="Count of scans in the window",
                    height="300px",
                ),
                panel(
                    simple_grid(
                        "sh-missing",
                        [
                            {"field": "project", "headerName": "Project", "flex": 1},
                            {"field": "branch", "headerName": "Branch", "width": 130},
                            {"field": "gaps", "headerName": "Engines with gaps", "flex": 1},
                        ],
                        height="320px",
                        empty_text="Every scanned project has all configured engines",
                    ),
                    title="Projects missing or failing an engine",
                    icon_name="layers",
                    flush=True,
                ),
                (5, 7),
            ),
            panel(
                simple_grid(
                    "sh-stale-grid",
                    [
                        {"field": "project", "headerName": "Project", "flex": 1},
                        {"field": "last_scan", "headerName": "Last completed scan", "width": 200},
                    ],
                    height="320px",
                    empty_text="No stale projects: every project has a recent completed scan",
                ),
                title="Stale projects",
                subtitle="No completed scan on a configured branch within the stale window",
                icon_name="clock",
                flush=True,
            ),
        ]
    )


def _fmt_duration(sec: float | None) -> str:
    if sec is None:
        return "–"
    m, s = divmod(int(sec), 60)
    return f"{m}m {s:02d}s"


@callback(
    Output("sh-rate-v", "children"),
    Output("sh-failed-v", "children"),
    Output("sh-p50-v", "children"),
    Output("sh-p90-v", "children"),
    Output("sh-stale-v", "children"),
    Output("sh-engines", "figure"),
    Output("sh-missing", "rowData"),
    Output("sh-stale-grid", "rowData"),
    Input("filters", "data"),
)
def update(store: dict[str, Any] | None) -> list[Any]:
    f = services.current_filters(store)
    h = services.container().queries.projects.scan_health(f)
    fails = sorted(
        ((ENGINE_LABELS.get(e, e), n) for e, n in h["engine_failures"].items()), key=lambda t: -t[1]
    )
    return [
        f"{h['success_rate']}%" if h["success_rate"] is not None else "–",
        f"{h['failed']:,}",
        _fmt_duration(h["duration_p50"]),
        _fmt_duration(h["duration_p90"]),
        f"{len(h['stale_projects']):,}",
        charts.hbar(fails, color="#d03b3b") if fails else charts.empty_figure("No engine failures"),
        [
            {
                "project": r["project"],
                "branch": r["branch"],
                "gaps": ", ".join(ENGINE_LABELS.get(e, e) for e in r["gaps"]),
            }
            for r in h["missing_engine"]
        ],
        [
            {
                "project": r["project"],
                "last_scan": r["last_scan"].strftime("%Y-%m-%d %H:%M") if r["last_scan"] else "never",
            }
            for r in h["stale_projects"]
        ],
    ]
