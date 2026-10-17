PY ?= python
ifneq ($(wildcard .venv/Scripts/python.exe),)
PY := .venv/Scripts/python.exe
else ifneq ($(wildcard .venv/bin/python),)
PY := .venv/bin/python
endif

.PHONY: install run worker migrate backfill sync seed-demo test test-integration lint format typecheck security check-config clean

install:
	$(PY) -m pip install -e ".[dev]"

run:            ## web UI (development server)
	$(PY) -m cxdash.ui.app

worker:         ## sync worker (exactly one instance)
	$(PY) -m cxdash.sync.scheduler

migrate:
	$(PY) -m cxdash.cli migrate

backfill:
	$(PY) -m cxdash.cli backfill

sync:
	$(PY) -m cxdash.cli scans

seed-demo:      ## load SYNTHETIC data for a demo / UI development
	$(PY) -m cxdash.cli migrate
	$(PY) -m cxdash.cli seed-demo

check-config:
	$(PY) -m cxdash.cli check-config

test:
	$(PY) -m pytest

test-integration: ## needs Docker (testcontainers/PostgreSQL)
	$(PY) -m pytest -m integration

lint:
	$(PY) -m ruff check src tests migrations
	$(PY) -m ruff format --check src tests migrations

format:
	$(PY) -m ruff check --fix src tests migrations
	$(PY) -m ruff format src tests migrations

typecheck:
	$(PY) -m mypy src/cxdash

security:       ## static analysis + dependency audit
	$(PY) -m bandit -q -r src -c pyproject.toml
	$(PY) -m pip_audit

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache build dist
