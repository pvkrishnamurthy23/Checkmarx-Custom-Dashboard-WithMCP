"""Operator CLI: ``python -m cxdash.cli <command>`` (wrapped by the Makefile).

Commands never print secrets. ``check-config`` validates .env and prints the masked config.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from cxdash.config import get_settings
from cxdash.logging import configure_logging

ROOT = Path(__file__).resolve().parents[2]


def _migrate() -> None:
    from alembic import command
    from alembic.config import Config

    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    command.upgrade(cfg, "head")


async def _sync(what: str) -> int:
    from cxdash.container import build_container
    from cxdash.sync.scheduler import SyncService, open_api

    settings = get_settings()
    container = build_container(settings)
    async with open_api(settings) as api:
        svc = SyncService(container, api)
        outcomes = {
            "backfill": svc.run_backfill,
            "inventory": lambda: _single(svc.run_inventory()),
            "scans": svc.run_scans_cycle,
            "nightly": svc.run_nightly,
        }[what]
        result = await outcomes()
    failed = [o for o in result if o.status == "failed"]
    for o in result:
        print(
            f"{o.job:<10} {o.status:<8} records={o.records} api_calls={o.api_calls}"
            + (f" error={o.error}" if o.error else "")
        )
    return 1 if failed else 0


async def _single(coro):
    return [await coro]


def _alert_params(args: argparse.Namespace) -> dict[str, Any]:
    params: dict[str, Any] = json.loads(args.params)
    for item in args.param:
        key, sep, raw = item.partition("=")
        if not sep or not key:
            raise SystemExit(f"--param expects KEY=VALUE, got {item!r}")
        value: Any = [v.strip() for v in raw.split(",")] if "," in raw else raw
        if isinstance(value, str) and value.lstrip("-").isdigit():
            value = int(value)
        params[key] = value
    return params


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="cxdash")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check-config", help="validate .env and print the masked configuration")
    sub.add_parser("migrate", help="alembic upgrade head")
    for name in ("backfill", "inventory", "scans", "nightly"):
        sub.add_parser(name, help=f"run the {name} sync once")
    seed = sub.add_parser("seed-demo", help="load a SYNTHETIC dataset (never use against production data)")
    seed.add_argument("--projects", type=int, default=40)
    seed.add_argument("--findings-per-engine", type=int, default=12)
    alert = sub.add_parser("alert-add", help="create an alert rule")
    alert.add_argument("--name", required=True)
    alert.add_argument("--kind", required=True)
    alert.add_argument("--channel", default="webhook", choices=["email", "webhook", "both"])
    alert.add_argument(
        "--param",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="rule parameter, repeatable (PowerShell-friendly); commas make a list, numbers stay numbers",
    )
    alert.add_argument(
        "--params",
        default="{}",
        help='JSON, e.g. {"severity":"HIGH"} or {"cron":"0 8 * * 1","recipients":["a@b.c"]}',
    )
    args = p.parse_args(argv)

    settings = get_settings()
    configure_logging(settings.log_level, settings.secret_values())

    if args.cmd == "check-config":
        print(json.dumps(settings.masked_dump(), indent=2, default=str))
        return 0
    if args.cmd == "migrate":
        _migrate()
        return 0
    if args.cmd in ("backfill", "inventory", "scans", "nightly"):
        return asyncio.run(_sync(args.cmd))
    if args.cmd == "seed-demo":
        from cxdash.db.session import Database, engine_from_settings
        from cxdash.devtools.seed import seed_demo, seed_sync_history

        if (
            settings.database_url.get_secret_value().startswith("postgresql")
            and "demo" not in settings.database_url.get_secret_value()
        ):
            print(
                "refusing to seed a PostgreSQL database whose URL does not contain 'demo' (safety check)",
                file=sys.stderr,
            )
            return 2
        db = Database(engine_from_settings(settings))
        print(seed_demo(db, settings, projects=args.projects, findings_per_engine=args.findings_per_engine))
        seed_sync_history(db)
        return 0
    if args.cmd == "alert-add":
        from cxdash.alerts.engine import add_rule
        from cxdash.container import build_container

        rule_id = add_rule(build_container(settings), args.name, args.kind, _alert_params(args), args.channel)
        print(f"created alert rule {rule_id}")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
