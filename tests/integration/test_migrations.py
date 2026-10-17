from pathlib import Path

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect

from cxdash.db import models  # noqa: F401
from cxdash.db.base import Base

ROOT = Path(__file__).resolve().parents[2]


def _cfg(url: str) -> Config:
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    cfg.set_main_option("sqlalchemy.url", url)
    return cfg


def test_upgrade_creates_every_table_and_matches_models(tmp_path):
    url = f"sqlite:///{tmp_path / 'm.db'}"
    command.upgrade(_cfg(url), "head")
    engine = create_engine(url)
    assert set(inspect(engine).get_table_names()) >= set(Base.metadata.tables) | {"alembic_version"}
    with engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    assert diff == [], f"models drifted from migration 0001: {diff}"


def test_downgrade_roundtrip(tmp_path):
    url = f"sqlite:///{tmp_path / 'd.db'}"
    cfg = _cfg(url)
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "base")
    assert inspect(create_engine(url)).get_table_names() == ["alembic_version"]
