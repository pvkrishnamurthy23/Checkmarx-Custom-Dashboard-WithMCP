from __future__ import annotations

import json
from typing import Any

import pytest

from cxdash.container import build_container
from cxdash.db.base import Base
from cxdash.db.session import Database, build_engine
from cxdash.devtools.seed import seed_demo, seed_sync_history
from tests.conftest import make_settings


@pytest.fixture(scope="session")
def seeded(tmp_path_factory):
    d = tmp_path_factory.mktemp("uidb")
    url = f"sqlite:///{d / 'ui.db'}"
    settings = make_settings(database_url=url)
    engine = build_engine(url)
    Base.metadata.create_all(engine)
    db = Database(engine)
    seed_demo(db, settings, projects=12)
    seed_sync_history(db)
    return settings, build_container(settings, db)


@pytest.fixture(scope="session")
def app(seeded):
    from cxdash.ui.app import create_app

    settings, container = seeded
    return create_app(settings, container)


@pytest.fixture(scope="session")
def client(app):
    return app.server.test_client()


class Caller:
    """Invoke a registered Dash callback through the real /_dash-update-component endpoint."""

    def __init__(self, client: Any) -> None:
        self.client = client
        self.deps = client.get("/_dash-dependencies").json

    def find(self, output_fragment: str, via: str | None = None) -> dict[str, Any]:
        matches = [
            d
            for d in self.deps
            if f"..{output_fragment}" in d["output"] or d["output"].startswith(output_fragment)
        ]
        if (
            via
        ):  # several callbacks may write the same output: pick the one triggered by this input ("id.prop")
            matches = [d for d in matches if any(f"{i['id']}.{i['property']}" == via for i in d["inputs"])]
        assert matches, f"no callback outputs {output_fragment} (via {via})"
        return matches[0]

    def call(self, output_fragment: str, values: dict[str, Any] | None = None, via: str | None = None) -> Any:
        values = values or {}
        dep = self.find(output_fragment, via)

        def pack(items):
            return [
                {"id": i["id"], "property": i["property"], "value": values.get(f"{i['id']}.{i['property']}")}
                for i in items
            ]

        inputs, state = pack(dep["inputs"]), pack(dep["state"])
        outs = dep["output"].strip(".").split("...")
        outputs = [{"id": o.rsplit(".", 1)[0], "property": o.rsplit(".", 1)[1]} for o in outs]
        body = {
            "output": dep["output"],
            "outputs": outputs if len(outputs) > 1 else outputs[0],
            "inputs": inputs,
            "state": state,
            "changedPropIds": [f"{inputs[0]['id']}.{inputs[0]['property']}"] if inputs else [],
        }
        resp = self.client.post(
            "/_dash-update-component", data=json.dumps(body), content_type="application/json"
        )
        assert resp.status_code == 200, resp.get_data(as_text=True)[:500]
        return resp.json["response"]


@pytest.fixture(scope="session")
def caller(client):
    return Caller(client)
