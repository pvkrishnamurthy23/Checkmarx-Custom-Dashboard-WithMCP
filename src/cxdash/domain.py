"""Shared domain vocabulary (enums, canonical forms). No I/O, no dependencies."""

from __future__ import annotations

from enum import StrEnum
from typing import Final

ENGINE_LABELS: Final[dict[str, str]] = {
    "sast": "SAST",
    "sca": "SCA",
    "containers": "Containers",
    "kics": "IaC (KICS)",
    "secrets": "Secrets",
    "apisec": "API Security",
    "sscs": "SSCS",
}


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @classmethod
    def parse(cls, value: object) -> Severity:
        """Normalise case; unknown values are treated as INFO (spec 6.5)."""
        try:
            return cls(str(value).strip().upper())
        except ValueError:
            return cls.INFO


SEVERITY_ORDER: Final[tuple[str, ...]] = tuple(s.value for s in Severity)

# Scan statuses (spec 6.5, "verify exact strings"); compared case-insensitively.
FINAL_SCAN_STATUSES: Final[frozenset[str]] = frozenset(
    {"COMPLETED", "PARTIAL", "FAILED", "CANCELED", "CANCELLED"}
)
USABLE_SCAN_STATUSES: Final[frozenset[str]] = frozenset({"COMPLETED", "PARTIAL"})
FAILED_SCAN_STATUSES: Final[frozenset[str]] = frozenset({"FAILED"})

# scan_counter.status markers (see ADR 0005)
COUNTER_SUMMARY = "ALL"  # severity totals from /api/scan-summary (state = 'ALL')
COUNTER_STATE = "STATE"  # state totals from /api/scan-summary (severity = 'ALL')
COUNTER_DERIVED = "DERIVED"  # severity x state computed from /api/results

# Application roles
ROLE_VIEWER, ROLE_ANALYST, ROLE_ADMIN = "viewer", "analyst", "admin"
ROLE_RANK: Final[dict[str, int]] = {ROLE_VIEWER: 0, ROLE_ANALYST: 1, ROLE_ADMIN: 2}


def is_final(status: str) -> bool:
    return status.strip().upper() in FINAL_SCAN_STATUSES


def is_usable(status: str) -> bool:
    return status.strip().upper() in USABLE_SCAN_STATUSES
