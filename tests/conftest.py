from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from cxdash.config import Settings
from cxdash.db.base import Base
from cxdash.db.session import Database, build_engine

FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def make_settings(**overrides: Any) -> Settings:
    base: dict[str, Any] = {
        "cx_region": "eu",
        "cx_tenant": "acme",
        "cx_api_key": "test-api-key-value-1234567890",
        "database_url": "sqlite://",
    }
    base.update(overrides)
    return Settings(_env_file=None, **base)  # type: ignore[call-arg]


@pytest.fixture
def settings() -> Settings:
    return make_settings()


@pytest.fixture
def db(tmp_path: Path) -> Database:
    engine = build_engine(f"sqlite:///{tmp_path / 'test.db'}")
    Base.metadata.create_all(engine)
    return Database(engine)
