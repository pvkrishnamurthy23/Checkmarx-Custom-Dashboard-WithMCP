# 0014. UI design system and reusable component library

- **Status:** Accepted (supersedes the page layout described in ADR 0001; its other decisions stand)
- **Date:** 2026-10-17
- **Spec reference:** 10.1, 10.2, 10.3

## Context
The first UI worked but looked basic: a Bootstrap top bar, a tall filter block, plain cards and per-page copies of the same panel and KPI
markup. The owner asked for a much better UI built from reusable components.

## Decision
**Look and feel.** Left sidebar navigation (grouped, with icons, collapses to an icon rail under 992 px), a sticky top bar (sync status,
refresh, user), a compact filter bar, then the page. Design tokens (colours, radius, shadow, spacing, fonts) live in `ui/assets/20-app.css`
and drive light and dark themes; severity/engine colours stay in `ui/theme.py` and are the same in charts, badges and cards.

**Filters.** One primary row (search plus the five most-used filters), a collapsible "More" row (tag, state, status, dates) with a count badge,
and removable **chips** that always show what is applied, so nothing hides inside a collapsed panel. The store/URL/controls flow of ADR 0010 is unchanged.

**Component library (`ui/components/`), the only way pages are built:**

| Module | Components |
|--------|------------|
| `layout.py` | `app_shell`, `sidebar`/`NAV`/`NavItem`, `topbar`, `theme_toggle`, `page_header`, `grid`, `split`, `stack` |
| `cards.py` | `panel`, `chart_panel`, `stat_card` (value, accent, sparkline, delta, click-to-filter), `delta`, `empty_state`, `kv_list` |
| `badges.py` | `pill`, `severity_badge`, `engine_tag` |
| `icons.py` + `icon_set.py` | `icon(name)`; glyphs compiled to `30-icons.css` by `python -m cxdash.devtools.build_icons` (CSS masks: no image requests, CSP stays strict, icons follow text colour) |
| `actions.py` | `link_button` (export links that carry the active filters) |
| `filter_bar.py`, `filter_chips.py` | filter controls and chips (pure `chips_for` is unit-tested) |
| `findings_grid.py`, `simple_grid.py` | server-paged findings grid; small client-side grids with friendly empty messages |
| `scanner_page.py` | declarative scanner pages (`ScannerPageSpec`) built from the pieces above |
| `drawer.py`, `cross_filter.py`, `charts.py` | finding drawer, click-to-filter wiring, Plotly figure builders (incl. `sparkline`) |

**Rules.** Pages contain no raw layout markup: they compose the components. Component ids are stable and documented in the component docstrings
(`stat_card("kpi-x")` always exposes `kpi-x`, `kpi-x-v`, `kpi-x-delta`, `kpi-x-spark`). Layout uses CSS grid with custom properties
(`--cx-min`, `--cx-cols`) so responsiveness lives in CSS, not in Bootstrap column props. Colour never carries meaning alone (badges and deltas
carry text). New icons are added to `icon_set.py` and the CSS regenerated (a test fails if the generated file is stale).

## Consequences
* Consistent spacing, headers, loading and empty states everywhere; a new page is a few component calls.
* Bootstrap remains for forms, modals, offcanvas and buttons only; layout no longer depends on it.
* Real-browser tests now cover chips, the "More" panel, sidebar navigation keeping filters, and a clean console on every page.
  This surfaced and fixed an AG Grid option (`overlayNoRowsTemplate`) that the library refuses to evaluate; the empty message now uses `localeText`.
* Trade-off: the generated icon CSS is committed; rebuilding it is a one-liner.
