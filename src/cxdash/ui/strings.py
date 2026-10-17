"""All user-facing UI text lives here (instructions/prompts/strings are kept out of logic)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Strings:
    app_title: str = "Checkmarx One Security Dashboard"
    application: str = "Application"
    project: str = "Project"
    tag: str = "Tag"
    branch: str = "Branch"
    scanner: str = "Scanner"
    severity: str = "Severity"
    state: str = "State"
    status: str = "Status"
    from_date: str = "From"
    to_date: str = "To"
    search_placeholder: str = "Search title, file, CVE, package…"
    search: str = "Search"
    more_filters: str = "More"
    reset: str = "Reset"
    save_view: str = "Save view"
    saved_views: str = "Saved views"
    view_name: str = "View name"
    save: str = "Save"
    saved: str = "Saved."
    forbidden: str = "Your role does not allow this action."
    never_synced: str = "Never synced"
    last_synced: str = "Last synced {time} ({ago})"
    refresh: str = "Refresh"
    refresh_queued: str = "Refresh queued; the worker will pick it up shortly."
    refresh_rate_limited: str = "A refresh was requested less than a minute ago."
    no_data: str = "No data for these filters"
    branch_not_scanned: str = "Branch not scanned"
    export_csv: str = "Export all filtered (CSV)"
    export_xlsx: str = "Export XLSX"
    export_selection: str = "Export selection"
    open_in_cx: str = "Open in Checkmarx One"
    theme: str = "Dark"
    logout: str = "Sign out"


S = Strings()
