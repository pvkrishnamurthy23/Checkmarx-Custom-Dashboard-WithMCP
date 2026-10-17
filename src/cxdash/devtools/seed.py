"""Synthetic dataset generator for local demos, UI tests and the load test (spec 17, M4).

Everything produced here is FAKE (``demo-*`` ids, ``.invalid`` hosts). It writes straight
to the database through the same tables the sync uses, so the UI cannot tell the difference.
"""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta
from typing import Any

from cxdash.config import Settings
from cxdash.db import models as m
from cxdash.db.repositories import FindingRepository, utcnow
from cxdash.db.session import Database
from cxdash.db.upsert import upsert
from cxdash.domain import COUNTER_SUMMARY
from cxdash.metrics.open_rules import OpenRules

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEV_WEIGHTS = [3, 14, 40, 35, 8]
STATES = [
    "TO_VERIFY",
    "TO_VERIFY",
    "TO_VERIFY",
    "CONFIRMED",
    "URGENT",
    "NOT_EXPLOITABLE",
    "PROPOSED_NOT_EXPLOITABLE",
]
SAST_QUERIES = ["SQL_Injection", "Reflected_XSS", "Stored_XSS", "Path_Traversal", "Log_Forging", "Hardcoded_Password",
                "Insecure_Randomness", "Command_Injection", "XXE", "SSRF", "Open_Redirect", "Weak_Hashing", "CSRF"]  # fmt: skip
LANGS = ["Java", "JavaScript", "Python", "CSharp", "Go", "TypeScript"]
OWASP = ["A01:2021-Broken Access Control", "A02:2021-Cryptographic Failures", "A03:2021-Injection",
         "A05:2021-Security Misconfiguration", "A06:2021-Vulnerable Components", "A07:2021-Auth Failures"]  # fmt: skip
PKGS = [
    "lodash",
    "log4j-core",
    "spring-web",
    "jackson-databind",
    "express",
    "requests",
    "django",
    "openssl",
    "axios",
]
PLATFORMS = ["Terraform", "Dockerfile", "Kubernetes", "CloudFormation", "ARM", "Ansible"]
KICS_RULES = [
    "Privileged Container",
    "S3 Bucket Public",
    "Missing USER",
    "Security Group Open",
    "No Resource Limits",
]
SECRET_TYPES = ["AWS Access Key", "GitHub Token", "Slack Token", "Private Key", "Generic Password"]
API_RISKS = ["API1:2023-Broken Object Level Auth", "API2:2023-Broken Authentication", "API3:2023-Property Level Auth", "API8:2023-Misconfiguration"]  # fmt: skip
SSCS_CHECKS = [
    "Branch-Protection",
    "Code-Review",
    "Pinned-Dependencies",
    "Token-Permissions",
    "Signed-Releases",
]
ENGINE_STATUS_FAIL_RATE = 0.04


def _pick_severity(rng: random.Random) -> str:
    return rng.choices(SEVERITIES, SEV_WEIGHTS)[0]


def _finding_row(
    rng: random.Random, engine: str, scan_id: str, project_id: str, branch: str, idx: int, now: datetime
) -> dict[str, Any]:
    sev = _pick_severity(rng)
    first_found = now - timedelta(
        days=rng.choice([1, 3, 6, 12, 25, 45, 80, 130, 200, 400]) + rng.randint(0, 5)
    )
    base: dict[str, Any] = {
        "scan_id": scan_id, "finding_id": f"{scan_id}-{engine}-{idx}", "project_id": project_id, "branch": branch,
        "engine": engine, "severity": sev, "state": rng.choice(STATES), "status": rng.choice(["NEW", "RECURRENT", "RECURRENT"]),
        "title": None, "description": "Synthetic demo finding", "cwe": None, "cve": None, "cvss": None, "package": None,
        "package_version": None, "fixed_version": None, "image": None, "file_path": None, "line": None, "language": None,
        "category": None, "first_found_at": first_found, "found_at": now, "raw_json": {"synthetic": True},
    }  # fmt: skip
    # similarity ids are stable per (project, branch, engine, slot) so lifecycle continuity works across reseeds
    slot = idx % 400
    base["similarity_id"] = f"demo-{project_id}-{branch}-{engine}-{slot}"
    if engine == "sast":
        q = rng.choice(SAST_QUERIES)
        base.update(title=q, cwe=f"CWE-{rng.choice([79, 89, 22, 117, 259, 330, 78, 611, 918])}", language=rng.choice(LANGS),
                    file_path=f"/src/{q.lower()}/File{rng.randint(1, 60)}.java", line=rng.randint(1, 900), category=rng.choice(OWASP))  # fmt: skip
    elif engine in ("sca", "containers"):
        pkg = rng.choice(PKGS)
        fixed = rng.random() < 0.65
        base.update(title=f"{pkg} CVE-2024-{rng.randint(1000, 9999)}", cve=f"CVE-2024-{rng.randint(1000, 9999)}", cvss=round(rng.uniform(2.0, 9.9), 1),
                    package=pkg, package_version=f"{rng.randint(1, 4)}.{rng.randint(0, 20)}.{rng.randint(0, 9)}",
                    fixed_version=f"{rng.randint(5, 6)}.0.0" if fixed else None, cwe=f"CWE-{rng.choice([79, 400, 502, 20])}")  # fmt: skip
        if engine == "containers":
            base["image"] = (
                f"registry.example.invalid/svc-{rng.randint(1, 15)}:{rng.randint(1, 9)}.{rng.randint(0, 9)}"
            )
    elif engine == "kics":
        base.update(title=rng.choice(KICS_RULES), category=rng.choice(PLATFORMS), file_path=f"/deploy/{rng.choice(['main.tf', 'Dockerfile', 'k8s.yaml'])}", line=rng.randint(1, 200))  # fmt: skip
    elif engine == "secrets":
        base.update(title=rng.choice(SECRET_TYPES), category=rng.choice(["Valid", "Invalid", "Unknown"]), file_path=f"/config/{rng.choice(['prod.env', 'app.yml', '.npmrc'])}", line=rng.randint(1, 50))  # fmt: skip
    elif engine == "apisec":
        base.update(title=f"Risk {rng.randint(1, 9)}", category=rng.choice(API_RISKS), file_path="/api/openapi.yaml", line=rng.randint(1, 400))  # fmt: skip
    else:  # sscs
        base.update(
            title=rng.choice(SSCS_CHECKS),
            category="scorecard",
            severity=rng.choice(["HIGH", "MEDIUM", "LOW"]),
        )
    return base


def seed_demo(
    db: Database,
    settings: Settings,
    *,
    projects: int = 40,
    findings_per_engine: int = 12,
    history_scans: int = 8,
    rng_seed: int = 42,
    now: datetime | None = None,
) -> dict[str, int]:
    rng = random.Random(rng_seed)  # nosec B311
    now = now or utcnow()
    branches = list(settings.cx_branches) or ["master"]
    engines = list(settings.cx_engines)
    rules = OpenRules.from_settings(settings)
    findings_repo = FindingRepository(db, rules)

    apps = [
        {"id": f"demo-app-{i}", "name": n, "criticality": 5 - i, "tags": {}}
        for i, n in enumerate(["Payments", "Storefront", "Back Office", "Data Platform"])
    ]
    proj_rows, scan_rows, status_rows, counter_rows, finding_rows = [], [], [], [], []
    latest_scans: list[tuple[str, str, str]] = []
    for i in range(projects):
        pid = f"demo-p{i:04d}"
        app = apps[i % len(apps)]["id"]
        proj_rows.append({
            "id": pid, "name": f"svc-{i:04d}-{rng.choice(['api', 'web', 'batch', 'ui', 'worker'])}", "repo_url": f"https://git.example.invalid/{pid}",
            "main_branch": branches[0], "groups": [], "tags": {"team": rng.choice(["pay", "web", "data", "ops"])},
            "application_ids": [app], "active": True, "created_at": now - timedelta(days=400), "updated_at": now,
        })  # fmt: skip
        for branch in branches:
            if branch != branches[0] and rng.random() < 0.25:
                continue  # some branches are never scanned -> "no scan on branch"
            run_engines = [e for e in engines if rng.random() > 0.08] or engines[:1]
            for k in range(history_scans):
                created = now - timedelta(
                    days=(history_scans - 1 - k) * 11 + rng.randint(0, 3), hours=rng.randint(0, 8)
                )
                if k == history_scans - 1:
                    created = now - timedelta(hours=rng.randint(1, 40))
                failed = rng.random() < 0.05 and k != history_scans - 1
                sid = f"demo-s-{pid}-{branch.replace('/', '_')}-{k}"
                dur = rng.randint(120, 1500)
                scan_rows.append({
                    "id": sid, "project_id": pid, "branch": branch, "status": "Failed" if failed else "Completed", "initiator": "ci",
                    "source_type": "git", "source_origin": "demo", "engines": run_engines, "created_at": created,
                    "completed_at": created + timedelta(seconds=dur), "duration_seconds": dur, "summary_loaded": not failed,
                    "findings_loaded": False, "is_latest": False,
                })  # fmt: skip
                for e in engines:
                    st = (
                        "Completed"
                        if e in run_engines and not failed
                        else (
                            "Failed"
                            if e in run_engines and rng.random() < ENGINE_STATUS_FAIL_RATE * 5
                            else "Skipped"
                        )
                    )
                    status_rows.append({"scan_id": sid, "engine": e, "status": st, "details": None})
                if failed:
                    continue
                decay = 0.6 + 0.4 * (k / max(1, history_scans - 1))  # backlog grows over time -> upward trend
                for e in run_engines:
                    totals: dict[str, int] = {}
                    for _ in range(max(1, int(findings_per_engine * decay))):
                        sev = _pick_severity(rng)
                        totals[sev] = totals.get(sev, 0) + 1
                    for sev, n in totals.items():
                        counter_rows.append(
                            {
                                "scan_id": sid,
                                "engine": e,
                                "severity": sev,
                                "state": "ALL",
                                "status": COUNTER_SUMMARY,
                                "count": n,
                            }
                        )
                if k == history_scans - 1:
                    latest_scans.append((sid, pid, branch))
                    for e in run_engines:
                        for j in range(findings_per_engine + rng.randint(-3, 8)):
                            finding_rows.append(_finding_row(rng, e, sid, pid, branch, j, now))

    with db.session() as s:
        upsert(s, m.Application.__table__, [{**a, "updated_at": now} for a in apps], ["id"])
        upsert(s, m.Project.__table__, proj_rows, ["id"])
        upsert(s, m.Scan.__table__, scan_rows, ["id"])
        upsert(s, m.ScanEngineStatus.__table__, status_rows, ["scan_id", "engine"])
        upsert(s, m.ScanCounter.__table__, counter_rows, ["scan_id", "engine", "severity", "state", "status"])
    from cxdash.db.repositories import ScanRepository

    ScanRepository(db).recompute_latest()
    with db.session() as s:
        upsert(s, m.Finding.__table__, finding_rows, ["scan_id", "finding_id"], chunk_size=500)
    scans_repo = ScanRepository(db)
    for sid, _pid, _branch in latest_scans:
        with db.session() as s:
            scan = s.get(m.Scan, sid)
        if scan is None or not scan.is_latest:
            continue
        findings_repo.derive_counters(sid)
        findings_repo.update_lifecycle(scan, engines)
        scans_repo.mark_findings_loaded(sid)
    _seed_resolved_history(db, rng, now, latest_scans, engines)
    return {"projects": projects, "scans": len(scan_rows), "findings": len(finding_rows)}


def _seed_resolved_history(
    db: Database, rng: random.Random, now: datetime, latest: list[tuple[str, str, str]], engines: list[str]
) -> None:
    """Add resolved lifecycle rows so MTTR / burndown have data."""
    rows = []
    for _, pid, branch in latest:
        for n in range(rng.randint(2, 10)):
            engine = rng.choice(engines)
            first_seen = now - timedelta(days=rng.randint(20, 150))
            resolved = first_seen + timedelta(days=rng.randint(1, 60))
            if resolved > now:
                resolved = now - timedelta(days=1)
            rows.append({
                "project_id": pid, "branch": branch, "engine": engine, "similarity_id": f"demo-resolved-{pid}-{branch}-{engine}-{n}",
                "first_seen_at": first_seen, "last_seen_at": resolved - timedelta(days=1), "resolved_at": resolved,
                "last_severity": _pick_severity(rng), "last_state": "TO_VERIFY",
            })  # fmt: skip
    with db.session() as s:
        upsert(s, m.FindingLifecycle.__table__, rows, ["project_id", "branch", "engine", "similarity_id"])


def seed_sync_history(db: Database, now: datetime | None = None) -> None:
    now = now or datetime.now(UTC)
    with db.session() as s:
        for job, mins in (("inventory", 20), ("scans", 4), ("summaries", 4), ("findings", 4)):
            s.add(
                m.SyncRun(
                    job=job,
                    started_at=now - timedelta(minutes=mins),
                    ended_at=now - timedelta(minutes=mins - 1),
                    status="success",
                    records=40,
                    api_calls=12,
                )
            )
