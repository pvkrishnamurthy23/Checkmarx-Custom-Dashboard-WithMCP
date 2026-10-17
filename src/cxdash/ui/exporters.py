"""Flask export routes (spec section 11). Every route: analyst+ only, audit-logged, filters re-validated."""

from __future__ import annotations

import logging
from typing import Any

from flask import Flask, Response, abort, g, request

from cxdash import executive
from cxdash.config import ENGINES
from cxdash.container import Container
from cxdash.domain import ROLE_ANALYST
from cxdash.exporting import EXPORT_COLUMNS, csv_stream, xlsx_bytes
from cxdash.filters import FilterSpec
from cxdash.security.auth import require_role
from cxdash.ui import state

log = logging.getLogger(__name__)


def _filters() -> FilterSpec:
    p = require_role(ROLE_ANALYST)
    f = state.from_query(request.query_string.decode("utf-8", "ignore"))
    return f.with_values(scope_applications=p.scope_applications)


def _engines() -> list[str] | None:
    raw = request.args.get("engines", "")
    wanted = [e for e in raw.split(",") if e in ENGINES]
    return wanted or None


def install_export_routes(server: Flask, c: Container) -> None:
    def audit(action: str, f: FilterSpec, **extra: Any) -> None:
        c.queries.users.audit(g.principal.user_id, action, {"filter": f.fingerprint(), **extra})

    @server.get("/export/findings.csv")
    def findings_csv() -> Response:
        f, engines = _filters(), _engines()
        total = min(c.queries.findings.count(f, engines), c.settings.export_row_cap)
        audit("export_csv", f, rows=total, engines=engines)
        rows = c.queries.findings.stream(f, engines, cap=c.settings.export_row_cap)
        return Response(
            csv_stream(rows),
            mimetype="text/csv",
            headers={"Content-Disposition": 'attachment; filename="findings.csv"'},
        )

    @server.get("/export/findings.xlsx")
    def findings_xlsx() -> Response:
        f, engines = _filters(), _engines()
        total = min(c.queries.findings.count(f, engines), c.settings.export_row_cap)
        audit("export_xlsx", f, rows=total, engines=engines)
        summary = {"Filters": _label(f), "Engines": engines or list(c.settings.cx_engines), "Rows": total}
        data = xlsx_bytes(
            c.queries.findings.stream(f, engines, cap=c.settings.export_row_cap),
            summary,
            EXPORT_COLUMNS,
            c.settings.export_row_cap,
        )
        return Response(
            data,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": 'attachment; filename="findings.xlsx"'},
        )

    @server.get("/export/executive.html")
    def executive_html() -> Response:
        f = _filters()
        audit("export_exec_html", f)
        return Response(executive.render_html(executive.build(c, f)), mimetype="text/html")

    @server.get("/export/executive.pdf")
    def executive_pdf() -> Response:
        f = _filters()
        audit("export_exec_pdf", f)
        pdf = executive.render_pdf(executive.build(c, f, with_png=True))
        if pdf is None:
            abort(
                Response(
                    "PDF engine not installed. Install the 'pdf' extra (WeasyPrint) or use the printable HTML.",
                    501,
                )
            )
        return Response(
            pdf,
            mimetype="application/pdf",
            headers={"Content-Disposition": 'attachment; filename="executive-summary.pdf"'},
        )


def _label(f: FilterSpec) -> str:
    return executive.filters_label(f)
