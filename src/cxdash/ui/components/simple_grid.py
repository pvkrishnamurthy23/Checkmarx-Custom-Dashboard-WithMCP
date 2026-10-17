"""Small client-side AG Grid for bounded tables (projects, health lists, admin)."""

from __future__ import annotations

from typing import Any

import dash_ag_grid as dag


def header_name(field: str) -> str:
    """'started_at' -> 'Started at' (used when a column has no explicit header)."""
    return field.replace("_", " ").strip().capitalize()


def simple_grid(
    grid_id: str,
    columns: list[dict[str, Any]],
    rows: list[dict[str, Any]] | None = None,
    *,
    height: str = "420px",
    selectable: bool = False,
    empty_text: str = "Nothing to show",
    paginate: bool = True,
) -> dag.AgGrid:
    cols = [{"headerName": header_name(c["field"]), **c} if "headerName" not in c else c for c in columns]
    options: dict[str, Any] = {
        "animateRows": False,
        "localeText": {"noRowsToShow": empty_text},
        "suppressCellFocus": True,
    }
    if paginate:
        options.update(
            {"pagination": True, "paginationPageSize": 50, "paginationPageSizeSelector": [25, 50, 100, 500]}
        )
    if selectable:
        options["rowSelection"] = {"mode": "singleRow", "checkboxes": False, "enableClickSelection": True}
    return dag.AgGrid(
        id=grid_id,
        columnDefs=cols,
        rowData=rows or [],
        defaultColDef={"resizable": True, "sortable": True, "filter": True},
        dashGridOptions=options,
        style={"height": height},
    )
