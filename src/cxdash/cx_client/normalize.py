"""Per-engine normalisers (spec 6.6) and scan-summary counter mapping (spec 8.2).

Design: one small class per engine behind a registry (Open/Closed). Every field
path below is an *assumption* taken from the public API docs; docs/API_NOTES.md
lists what must be confirmed against real payloads. Unknown shapes degrade to
``None`` fields, never to exceptions.
"""

from __future__ import annotations

import hashlib
import logging
import re
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any, ClassVar, Protocol

from pydantic import TypeAdapter

from cxdash.cx_client.models import CounterRow, NormalizedFinding
from cxdash.domain import COUNTER_STATE, COUNTER_SUMMARY, Severity

log = logging.getLogger(__name__)

_DT = TypeAdapter(datetime)

# result ``type`` -> engine. Ordered; first substring match wins. VERIFY (API_NOTES.md #2).
TYPE_RULES: tuple[tuple[str, str], ...] = (
    ("secret", "secrets"),
    ("sscs", "sscs"),
    ("scorecard", "sscs"),
    ("kics", "kics"),
    ("iac", "kics"),
    ("container", "containers"),
    ("apisec", "apisec"),
    ("api-sec", "apisec"),
    ("api_sec", "apisec"),
    ("sca", "sca"),
    ("sast", "sast"),
)

# scan-summary block key -> engine. VERIFY (API_NOTES.md #1). Both container spellings accepted.
SUMMARY_KEY_TO_ENGINE: dict[str, str] = {
    "sastcounters": "sast",
    "scacounters": "sca",
    "kicscounters": "kics",
    "containerscounters": "containers",
    "scacontainerscounters": "containers",
    "apiseccounters": "apisec",
    "microenginescounters": "secrets",
    "secretscounters": "secrets",
    "sscscounters": "sscs",
}
_IGNORED_SUMMARY_KEYS = {"scanid", "scapackagescounters", "totalcounter"}


def _dt(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = _DT.validate_python(value)
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def _get(obj: Any, *path: str) -> Any:
    for key in path:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


def _first(*values: Any) -> Any:
    for v in values:
        if v not in (None, "", []):
            return v
    return None


def _str(value: Any) -> str | None:
    return None if value in (None, "") else str(value)


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _float(value: Any) -> float | None:
    try:
        return round(float(value), 1)
    except (TypeError, ValueError):
        return None


def _cwe(value: Any) -> str | None:
    if value in (None, ""):
        return None
    text = str(value).strip()
    return text if text.upper().startswith("CWE") else f"CWE-{text}"


def fallback_similarity(engine: str, title: str, file_path: Any, line: Any, package: Any, cve: Any) -> str:
    """Spec 7.1: hash of (engine, title, file_path, line, package, cve)."""
    basis = "|".join(str(x or "") for x in (engine, title, file_path, line, package, cve))
    return "h:" + hashlib.sha256(basis.encode()).hexdigest()[:32]


_STATUSES = {"NEW", "RECURRENT", "FIXED"}


class FindingNormalizer(Protocol):
    engine: str

    def normalize(
        self, raw: dict[str, Any], scan_id: str, project_id: str, branch: str
    ) -> NormalizedFinding: ...


class BaseNormalizer:
    """Template method: shared fields here, engine specifics in ``_specific``."""

    engine: ClassVar[str]

    def normalize(self, raw: dict[str, Any], scan_id: str, project_id: str, branch: str) -> NormalizedFinding:
        raw_data, raw_vuln = raw.get("data"), raw.get("vulnerabilityDetails")
        data: dict[str, Any] = raw_data if isinstance(raw_data, dict) else {}
        vuln: dict[str, Any] = raw_vuln if isinstance(raw_vuln, dict) else {}
        specific = self._specific(raw, data, vuln)
        title = (
            specific.pop("title", None)
            or _str(raw.get("label"))
            or _str(raw.get("description"))
            or "(untitled)"
        )
        status = str(raw.get("status") or "").upper()
        fields: dict[str, Any] = {
            "description": _str(raw.get("description")),
            "cwe": _cwe(vuln.get("cweId")),
            "cve": _str(vuln.get("cveName")),
            "cvss": _float(_first(vuln.get("cvssScore"), _get(vuln, "cvss", "score"))),
            **specific,
        }
        similarity = _str(raw.get("similarityId")) or fallback_similarity(
            self.engine,
            title,
            fields.get("file_path"),
            fields.get("line"),
            fields.get("package"),
            fields.get("cve"),
        )
        finding_id = self._finding_id(raw, similarity)
        similarity = self._similarity(raw, data, similarity)
        return NormalizedFinding(
            finding_id=finding_id,
            similarity_id=similarity,
            scan_id=scan_id,
            project_id=project_id,
            branch=branch,
            engine=self.engine,
            severity=Severity.parse(raw.get("severity")),
            state=str(raw.get("state") or "TO_VERIFY").upper(),
            status=status if status in _STATUSES else None,
            title=title,
            first_found_at=_dt(raw.get("firstFoundAt")),
            found_at=_dt(_first(raw.get("foundAt"), raw.get("created"))),
            raw_json=raw,
            **fields,
        )

    def _specific(self, raw: dict[str, Any], data: dict[str, Any], vuln: dict[str, Any]) -> dict[str, Any]:
        return {}

    def _finding_id(self, raw: dict[str, Any], similarity: str) -> str:
        # Verified on a real tenant: SCA and Containers results reuse the CVE as ``id`` across packages/images, while
        # ``alternateId`` is unique per result (and equals ``id`` for SAST/KICS/secrets).
        return _str(raw.get("alternateId")) or _str(raw.get("id")) or similarity

    def _similarity(self, raw: dict[str, Any], data: dict[str, Any], similarity: str) -> str:
        return similarity

    @staticmethod
    def _owasp(vuln: dict[str, Any], marker: str = "OWASP") -> str | None:
        compliances = vuln.get("compliances") or []
        return next((str(c) for c in compliances if marker.lower() in str(c).lower()), None)


class SastNormalizer(BaseNormalizer):
    engine = "sast"

    def _specific(self, raw: dict[str, Any], data: dict[str, Any], vuln: dict[str, Any]) -> dict[str, Any]:
        node = (data.get("nodes") or [{}])[0] or {}
        return {
            "title": _str(data.get("queryName")),
            "file_path": _str(node.get("fileName")),
            "line": _int(node.get("line")),
            "language": _str(data.get("languageName")),
            "category": self._owasp(vuln),
        }


_PKG_ID = re.compile(r"^[^-]+-(?P<name>.+)-(?P<version>[^-]+)$")


class ScaNormalizer(BaseNormalizer):
    engine = "sca"

    # ``similarityId`` is the bare CVE, so the lifecycle key must add the package.
    def _similarity(self, raw: dict[str, Any], data: dict[str, Any], similarity: str) -> str:
        package = _str(data.get("packageIdentifier"))
        return f"{similarity}|{package}" if package else similarity

    def _specific(self, raw: dict[str, Any], data: dict[str, Any], vuln: dict[str, Any]) -> dict[str, Any]:
        ident = _str(data.get("packageIdentifier"))
        name = version = None
        if ident and (m := _PKG_ID.match(ident)):
            name, version = m.group("name"), m.group("version")
        name = _first(_str(data.get("packageName")), name, ident)
        version = _first(_str(data.get("packageVersion")), version)
        cve = _str(vuln.get("cveName"))
        return {
            "title": " ".join(x for x in (name, cve) if x) or None,
            "package": name,
            "package_version": version,
            "fixed_version": _str(data.get("recommendedVersion")),
            "category": _str(data.get("scaType") or _get(data, "packageData", "type")),
        }


class ContainersNormalizer(BaseNormalizer):
    engine = "containers"

    def _similarity(self, raw: dict[str, Any], data: dict[str, Any], similarity: str) -> str:
        # ``similarityId`` is the bare CVE; the same CVE hits many images/packages, so key the lifecycle on all of them.
        where = "|".join(
            _str(data.get(k)) or "" for k in ("imageName", "imageTag", "packageName", "packageVersion")
        )
        return f"{similarity}|{where}"

    def _specific(self, raw: dict[str, Any], data: dict[str, Any], vuln: dict[str, Any]) -> dict[str, Any]:
        image = _str(data.get("imageName"))
        tag = _str(data.get("imageTag"))
        package = _str(data.get("packageName"))
        cve = _str(vuln.get("cveName"))
        return {
            "title": " ".join(x for x in (package, cve) if x) or None,
            "image": f"{image}:{tag}" if image and tag else image,
            "package": package,
            "package_version": _str(data.get("packageVersion")),
            "fixed_version": _str(_first(data.get("recommendedVersion"), data.get("fixedVersion"))),
        }


class KicsNormalizer(BaseNormalizer):
    engine = "kics"

    def _specific(self, raw: dict[str, Any], data: dict[str, Any], vuln: dict[str, Any]) -> dict[str, Any]:
        return {
            "title": _str(data.get("queryName")),
            "file_path": _str(data.get("fileName")),
            "line": _int(data.get("line")),
            "category": _str(data.get("platform")),
        }


class SecretsNormalizer(BaseNormalizer):
    engine = "secrets"

    def _specific(self, raw: dict[str, Any], data: dict[str, Any], vuln: dict[str, Any]) -> dict[str, Any]:
        return {
            "title": _str(_first(data.get("ruleName"), data.get("secretType"), data.get("queryName"))),
            "file_path": _str(_first(data.get("fileName"), data.get("filename"))),
            "line": _int(_first(data.get("line"), data.get("lineNumber"))),
            # For secrets, ``category`` carries validity (Valid / Invalid / Unknown) when present.
            "category": _str(_first(data.get("validity"), data.get("validationStatus"))),
        }


class ApiSecNormalizer(BaseNormalizer):
    engine = "apisec"

    def _specific(self, raw: dict[str, Any], data: dict[str, Any], vuln: dict[str, Any]) -> dict[str, Any]:
        node = (data.get("nodes") or [{}])[0] or {}
        return {
            "title": _str(_first(data.get("queryName"), data.get("riskName"))),
            "file_path": _str(_first(node.get("fileName"), data.get("fileName"))),
            "line": _int(_first(node.get("line"), data.get("line"))),
            "category": self._owasp(vuln, "API") or _str(data.get("owaspCategory")),
        }


class SscsNormalizer(BaseNormalizer):
    engine = "sscs"

    def _specific(self, raw: dict[str, Any], data: dict[str, Any], vuln: dict[str, Any]) -> dict[str, Any]:
        return {
            "title": _str(_first(data.get("ruleName"), data.get("name"), data.get("checkName"))),
            "file_path": _str(data.get("fileName")),
            "line": _int(data.get("line")),
            "category": _str(_first(data.get("category"), "scorecard")),
        }


class NormalizerRegistry:
    def __init__(self, normalizers: Iterable[BaseNormalizer]) -> None:
        self._by_engine = {n.engine: n for n in normalizers}
        self._unknown_types: set[str] = set()

    def engine_for(self, raw: dict[str, Any]) -> str | None:
        rtype = str(raw.get("type") or "").lower()
        for needle, engine in TYPE_RULES:
            if needle in rtype:
                return engine
        if rtype not in self._unknown_types:
            self._unknown_types.add(rtype)
            log.warning("unknown result type ignored", extra={"result_type": rtype})
        return None

    def normalize(
        self, raw: dict[str, Any], scan_id: str, project_id: str, branch: str
    ) -> NormalizedFinding | None:
        engine = self.engine_for(raw)
        if engine is None:
            return None
        return self._by_engine[engine].normalize(raw, scan_id, project_id, branch)


def default_registry() -> NormalizerRegistry:
    return NormalizerRegistry(
        [
            SastNormalizer(),
            ScaNormalizer(),
            ContainersNormalizer(),
            KicsNormalizer(),
            SecretsNormalizer(),
            ApiSecNormalizer(),
            SscsNormalizer(),
        ]
    )


# ----------------------------------------------------------------------------- summaries


def summary_counter_rows(summary: dict[str, Any]) -> list[CounterRow]:
    """Flatten one ``scansSummaries[]`` item into ``scan_counter`` rows (spec 8.2).

    * ``severityCounters``  -> (severity, state='ALL', status='ALL')
    * ``stateCounters``     -> (severity='ALL', state, status='STATE')
    Unknown engine blocks are logged and ignored, never fatal.
    """
    scan_id = str(summary.get("scanId") or summary.get("scanID") or "")
    rows: list[CounterRow] = []
    present = {k.lower() for k in summary}
    for key, block in summary.items():
        lowered = key.lower()
        if lowered in _IGNORED_SUMMARY_KEYS or not isinstance(block, dict):
            continue
        if lowered == "scacontainerscounters" and "containerscounters" in present:
            continue  # tenants return both; the old block has a different shape and is superseded
        engine = SUMMARY_KEY_TO_ENGINE.get(lowered)
        if engine is None:
            if lowered.endswith("counters"):
                log.warning("unknown scan-summary block ignored", extra={"block": key})
            continue
        # legacy containers block: severityVulnerabilitiesCounters / stateVulnerabilitiesCounters
        sev_items = block.get("severityCounters") or block.get("severityVulnerabilitiesCounters") or []
        state_items = block.get("stateCounters") or block.get("stateVulnerabilitiesCounters") or []
        for item in sev_items:
            count = _int(item.get("counter"))
            if count is not None:
                rows.append(
                    CounterRow(
                        scan_id=scan_id,
                        engine=engine,
                        severity=Severity.parse(item.get("severity")).value,
                        state="ALL",
                        status=COUNTER_SUMMARY,
                        count=count,
                    )
                )
        for item in state_items:
            count = _int(item.get("counter"))
            if count is not None:
                rows.append(
                    CounterRow(
                        scan_id=scan_id,
                        engine=engine,
                        severity="ALL",
                        state=str(item.get("state") or "UNKNOWN").upper(),
                        status=COUNTER_STATE,
                        count=count,
                    )
                )
    return rows
