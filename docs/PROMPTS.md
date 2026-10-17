# Prompts and standing instructions

All prompts and working instructions for AI-assisted development live here, separate from code (standing rule 6).
The application itself contains **no LLM prompts**. If one is ever added, it goes in `src/cxdash/prompts/` as a text/Jinja file and
is listed here.

## 1. Standing instructions (apply to every session)
1. Follow SOLID principles wherever applicable.
2. Keep `CLAUDE.md` up to date with every change.
3. Create and maintain ADR files (`docs/adr/`) and keep them up to date.
4. Maintain `README.md` as the how-to-use guide. Local testing uses a git-ignored `.env`; never put a secret in code.
5. Perform a security review of the code; do not leave vulnerable code (`docs/SECURITY_REVIEW.md`, `make security`).
6. Keep prompts and instructions in separate files (this file, `ui/strings.py`, Jinja templates).
7. Claude-related files (`CLAUDE.md`, `.claude/`, ...) are listed in `.gitignore`.
8. From the spec: do not invent API fields; keep everything configurable in `.env`; stay read-only toward Checkmarx One; work in small
   tested steps; never log secrets or raw findings at INFO; ask before deviating from the spec.

## 2. First prompt from the spec (Milestone 1)
> Read docs/SPEC.md fully. Implement Milestone 1 only (foundation: repo layout, config, Checkmarx client with auth/paging/retry,
> DB schema + Alembic, inventory and scan sync). Follow section 3 (stack), 4 (layout), 5 (.env), 6 (client), 7 (schema), 8 (sync).
> Ask me before deviating from the spec. Use pytest + respx with fixtures for all HTTP calls.

## 3. Prompt used for the full build
> Create the app as per the provided HLD. Plan each and everything in a very detailed manner and follow: (1) SOLID; (2) a CLAUDE.md
> kept updated; (3) ADR files kept updated; (4) a README/instructions file; local testing via `.env`, no secrets in code;
> (5) security review of the code, no vulnerable code; (6) prompts and instructions in a separate file; (7) Claude-related files in .gitignore.

## 4. Reusable prompts
**Add a scanner page**
> Add a page for `<engine>` using `ScannerPageSpec` in `ui/pages/`. Reuse `FindingQueries.group_counts`; add a new query method only if no
> existing one fits. Register the grid columns in `findings_grid.PAGE_COLUMNS`. Add a UI test that calls its callbacks via `tests/ui`.
> Update CLAUDE.md and docs/TRACEABILITY.md.

**Add an engine / fix a mapping after capturing a real payload**
> Save a sanitised payload under `tests/fixtures/`, update the normaliser in `cx_client/normalize.py` (and `TYPE_RULES` or
> `SUMMARY_KEY_TO_ENGINE` if names differ), extend `tests/unit/test_normalize.py`, and update `docs/API_NOTES.md`.

**Add an alert kind**
> Implement a `RuleEvaluator` in `alerts/rules.py`, register it in `DEFAULT_EVALUATORS`, add a template only if the output differs,
> test dedupe/cooldown in `tests/integration/test_features.py`, document the params in README.

**Add or change UI**
> Build it only from `ui/components` (panel, chart_panel, stat_card, page_header, grid/split/stack, badges, icon, link_button). If a needed piece is missing,
> add it as a component with a docstring, stable ids and a unit test in `tests/unit/test_ui_components.py`; add icons via `ui/icon_set.py` and run
> `python -m cxdash.devtools.build_icons`. Check light, dark and a 820 px viewport in a real browser (`tests/ui/test_e2e.py`), and update ADR 0014 if the design rules change.

**Security review**
> Review the diff for: injection (SQL, formula, HTML, header), authz (roles, row-level scope), secret handling and logging, SSRF/open
> redirect, CSRF/Origin, session handling, unsafe deserialisation, dependency risk (`pip-audit`), container hardening. Fix what you find,
> add a regression test, and record it in docs/SECURITY_REVIEW.md.

**ADR**
> Write the next numbered ADR from `docs/adr/0000-template.md` (context, decision, consequences, alternatives), add it to the index,
> and mark any superseded ADR.

**Reconciliation**
> Follow docs/RECONCILE.md for 10 sampled projects and record the results in that file.

## 5. Definition of done
Tests green (`pytest`, plus `-m integration` when SQL changed), `ruff`, `mypy`, `bandit`, `pip-audit` clean, docs updated
(CLAUDE.md, README, ADR, TRACEABILITY, SECURITY_REVIEW, `.env.example`), no secrets in the diff.
