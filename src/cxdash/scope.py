"""Scope rules shared by sync and queries: branch matching and project include filters."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from fnmatch import fnmatchcase


def branch_matches(branch: str, patterns: Sequence[str]) -> bool:
    """Exact, case-sensitive match; ``fnmatch`` globs when the pattern contains ``*`` (spec 8.3).

    An empty pattern list means "all branches".
    """
    if not patterns:
        return True
    return any(fnmatchcase(branch, p) if "*" in p else branch == p for p in patterns)


def has_glob(patterns: Iterable[str]) -> bool:
    return any("*" in p for p in patterns)


def tags_match(project_tags: Mapping[str, str], wanted: Sequence[str]) -> bool:
    """``wanted`` entries are ``key`` or ``key:value``; a project must satisfy all of them."""
    for item in wanted:
        key, _, value = item.partition(":")
        if key not in project_tags:
            return False
        if value and project_tags[key] != value:
            return False
    return True


def compile_name_regex(pattern: str) -> re.Pattern[str] | None:
    return re.compile(pattern) if pattern else None
