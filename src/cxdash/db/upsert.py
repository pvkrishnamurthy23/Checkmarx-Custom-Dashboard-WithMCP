"""Portable INSERT ... ON CONFLICT DO UPDATE (PostgreSQL and SQLite share the construct)."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session


def _chunks(rows: Sequence[Mapping[str, Any]], size: int) -> Iterable[Sequence[Mapping[str, Any]]]:
    for i in range(0, len(rows), size):
        yield rows[i : i + size]


def upsert(
    session: Session,
    table: Any,
    rows: Sequence[Mapping[str, Any]],
    key_cols: Sequence[str],
    *,
    update_cols: Sequence[str] | None = None,
    chunk_size: int = 1000,
) -> int:
    """Upsert ``rows`` keyed on ``key_cols``; duplicates inside one batch keep the last row."""
    if not rows:
        return 0
    insert = pg_insert if session.get_bind().dialect.name == "postgresql" else sqlite_insert
    deduped = list({tuple(r[k] for k in key_cols): r for r in rows}.values())
    cols = update_cols if update_cols is not None else [c for c in deduped[0] if c not in key_cols]
    for chunk in _chunks(deduped, chunk_size):
        stmt = insert(table).values(list(chunk))
        if cols:
            stmt = stmt.on_conflict_do_update(
                index_elements=list(key_cols), set_={c: stmt.excluded[c] for c in cols}
            )
        else:
            stmt = stmt.on_conflict_do_nothing(index_elements=list(key_cols))
        session.execute(stmt)
    return len(deduped)
