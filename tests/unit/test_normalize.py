from cxdash.cx_client.models import ProjectModel, ScanModel
from cxdash.cx_client.normalize import default_registry, fallback_similarity, summary_counter_rows
from cxdash.domain import Severity
from tests.conftest import load_fixture

REG = default_registry()
RESULTS = {r["id"]: r for r in load_fixture("results_s1.json")["results"]}


def norm(rid):
    return REG.normalize(RESULTS[rid], "scan-1", "p1", "master")


def test_every_engine_normalises_fixture():
    engines = {rid: norm(rid) for rid in RESULTS if rid != "r-x"}
    assert {f.engine for f in engines.values()} == {"sast", "sca", "kics", "containers", "secrets"}


def test_sast_fields():
    f = norm("r-sast-1")
    assert (f.title, f.file_path, f.line, f.language) == ("SQL_Injection", "/src/Dao.java", 42, "Java")
    assert f.cwe == "CWE-89"
    assert f.category == "OWASP Top 10 2021"
    assert f.severity is Severity.HIGH and f.state == "TO_VERIFY" and f.status == "NEW"
    assert f.similarity_id == "-111" and f.finding_id == "r-sast-1"
    assert f.first_found_at.year == 2026 and f.first_found_at.tzinfo is not None
    assert f.raw_json["id"] == "r-sast-1"


def test_cwe_already_prefixed_is_kept():
    assert norm("r-sast-2").cwe == "CWE-117"


def test_sca_fields():
    f = norm("r-sca-1")
    assert (f.package, f.package_version, f.fixed_version) == ("lodash", "4.17.20", "4.17.21")
    assert f.cve == "CVE-2021-23337" and f.cvss == 7.2 and f.title == "lodash CVE-2021-23337"
    g = norm("r-sca-2")
    assert g.package == "org.apache.commons-commons-text" and g.package_version == "1.9"
    assert g.fixed_version is None


def test_container_fields():
    f = norm("r-cont-1")
    assert f.engine == "containers" and f.image == "registry.example.invalid/app:1.0"
    assert f.package == "openssl" and f.fixed_version == "1.1.1w"


def test_kics_and_secrets_fields():
    k = norm("r-kics-1")
    assert (k.title, k.category, k.file_path, k.line) == (
        "Privileged Container",
        "Kubernetes",
        "/deploy/k8s.yaml",
        12,
    )
    s = norm("r-sec-1")
    assert (s.engine, s.title, s.category) == ("secrets", "AWS Access Key", "Valid")


def test_unknown_result_type_is_skipped_not_fatal():
    assert REG.normalize(RESULTS["r-x"], "s", "p", "b") is None


def test_unknown_severity_is_info_and_state_defaults():
    f = REG.normalize({"type": "sast", "id": "1", "severity": "bogus", "data": {}}, "s", "p", "b")
    assert f.severity is Severity.INFO and f.state == "TO_VERIFY" and f.title == "(untitled)"


def test_missing_similarity_uses_stable_fallback_hash():
    raw = {
        "type": "kics",
        "id": "k",
        "severity": "LOW",
        "data": {"queryName": "Q", "fileName": "f.tf", "line": 3},
    }
    a = REG.normalize(raw, "s1", "p", "b")
    b = REG.normalize(raw, "s2", "p", "b")
    assert a.similarity_id.startswith("h:") and a.similarity_id == b.similarity_id
    assert a.similarity_id == fallback_similarity("kics", "Q", "f.tf", 3, None, None)


def test_status_outside_enum_becomes_none():
    f = REG.normalize({"type": "sast", "id": "1", "status": "WEIRD", "data": {}}, "s", "p", "b")
    assert f.status is None


def test_custom_state_is_preserved_uppercased():
    f = REG.normalize({"type": "sast", "id": "1", "state": "my_custom", "data": {}}, "s", "p", "b")
    assert f.state == "MY_CUSTOM"


def test_summary_mapping():
    summary = load_fixture("scan_summary.json")["scansSummaries"][0]
    rows = summary_counter_rows(summary)
    by = {(r.engine, r.severity, r.state, r.status): r.count for r in rows}
    assert by[("sast", "HIGH", "ALL", "ALL")] == 2
    assert by[("sast", "ALL", "NOT_EXPLOITABLE", "STATE")] == 1
    assert by[("containers", "HIGH", "ALL", "ALL")] == 4  # scaContainersCounters (old name) accepted
    assert by[("secrets", "HIGH", "ALL", "ALL")] == 1
    assert {r.engine for r in rows} == {
        "sast",
        "sca",
        "kics",
        "containers",
        "secrets",
    }  # unknown block ignored


def test_summary_accepts_new_container_key_and_normalises_severity():
    rows = summary_counter_rows(load_fixture("scan_summary.json")["scansSummaries"][2])
    by = {(r.engine, r.severity): r.count for r in rows}
    assert by[("sast", "CRITICAL")] == 2
    assert by[("sast", "INFO")] == 1  # unknown severity -> INFO
    assert by[("containers", "HIGH")] == 2


def test_models_are_tolerant():
    p = ProjectModel.model_validate(
        {"id": "p", "name": "n", "tags": None, "groups": None, "applicationIds": None, "extra": 1}
    )
    assert p.tags == {} and p.groups == [] and p.applicationIds == []
    s = ScanModel.model_validate(
        {
            "id": "s",
            "status": "Completed",
            "projectId": "p",
            "createdAt": "2026-01-01T00:00:00",
            "branch": None,
        }
    )
    assert s.branch == "" and s.createdAt.tzinfo is not None


# --------------------------------------------------------------- verified against a real tenant (2026-10-16)
def test_sca_ids_are_unique_per_package_even_when_the_cve_repeats():
    """Real SCA results use the CVE as ``id`` and ``similarityId``; the same CVE can hit several packages."""
    base = {
        "type": "sca",
        "id": "CVE-2026-1",
        "similarityId": "CVE-2026-1",
        "alternateId": "hashA=",
        "severity": "HIGH",
        "state": "TO_VERIFY",
    }
    a = REG.normalize({**base, "data": {"packageIdentifier": "Maven-org.x:a-1.0"}}, "s", "p", "b")
    b = REG.normalize(
        {**base, "alternateId": "hashB=", "data": {"packageIdentifier": "Maven-org.x:b-2.0"}}, "s", "p", "b"
    )
    assert a.finding_id != b.finding_id and a.finding_id == "hashA="
    assert a.similarity_id == "CVE-2026-1|Maven-org.x:a-1.0" != b.similarity_id


def test_real_result_shapes_for_secrets_and_containers():
    sec = REG.normalize(
        {
            "type": "sscs-secret-detection",
            "id": "x",
            "similarityId": "h" * 64,
            "severity": "HIGH",
            "state": "TO_VERIFY",
            "data": {"ruleName": "Generic-Api-Key", "fileName": "a.env", "line": 28, "validity": "Unknown"},
            "vulnerabilityDetails": {},
        },
        "s",
        "p",
        "b",
    )
    assert (sec.engine, sec.title, sec.category, sec.line) == ("secrets", "Generic-Api-Key", "Unknown", 28)
    con = REG.normalize(
        {
            "type": "containers",
            "id": "c1",
            "severity": "HIGH",
            "state": "TO_VERIFY",
            "data": {
                "packageName": "zlib",
                "packageVersion": "1.3.2-r0",
                "imageName": "amazoncorretto",
                "imageTag": "21-alpine",
            },
            "vulnerabilityDetails": {"cveName": "CVE-2026-85091", "cvssScore": 8.3, "cweId": "CWE-787"},
        },
        "s",
        "p",
        "b",
    )
    assert (con.engine, con.image, con.package, con.cve, con.cwe) == (
        "containers",
        "amazoncorretto:21-alpine",
        "zlib",
        "CVE-2026-85091",
        "CWE-787",
    )


def test_summary_prefers_new_containers_block_and_reads_the_old_shape_when_alone():
    both = {
        "scanId": "s",
        "scaContainersCounters": {"severityVulnerabilitiesCounters": [{"severity": "HIGH", "counter": 9}]},
        "containersCounters": {"severityCounters": [{"severity": "HIGH", "counter": 1}]},
    }
    assert [(r.engine, r.count) for r in summary_counter_rows(both)] == [
        ("containers", 1)
    ]  # old block ignored, no double count
    old_only = {
        "scanId": "s",
        "scaContainersCounters": {
            "severityVulnerabilitiesCounters": [{"severity": "HIGH", "counter": 9}],
            "stateVulnerabilitiesCounters": [{"state": "TO_VERIFY", "counter": 9}],
        },
    }
    assert sorted((r.severity, r.count) for r in summary_counter_rows(old_only)) == [("ALL", 9), ("HIGH", 9)]


def test_microengines_map_to_secrets_and_sscs_only_when_enabled():
    def scan(cfg):
        return ScanModel.model_validate(
            {
                "id": "s",
                "status": "Completed",
                "projectId": "p",
                "createdAt": "2026-01-01T00:00:00Z",
                "metadata": {"configs": [{"type": "microengines", "value": cfg}]},
            }
        )

    assert scan({"2ms": "true", "scorecard": "false"}).engine_keys("microengines") == ["secrets"]
    assert scan({"2ms": "true", "scorecard": "true"}).engine_keys("microengines") == ["secrets", "sscs"]
    assert scan({"2ms": "false", "scorecard": "false"}).engine_keys("microengines") == []
    assert scan({}).engine_keys("general") == [] and scan({}).engine_keys("SAST") == ["sast"]


def test_incremental_flag_comes_from_the_sast_config():
    def scan(value):
        return ScanModel.model_validate(
            {
                "id": "s",
                "status": "Completed",
                "projectId": "p",
                "createdAt": "2026-01-01T00:00:00Z",
                "metadata": {"configs": [{"type": "sast", "value": value}]},
            }
        )

    assert scan({"incremental": "true"}).is_incremental
    assert not scan({"incremental": "false"}).is_incremental and not scan({}).is_incremental
    assert not ScanModel.model_validate(
        {"id": "s", "status": "Completed", "projectId": "p", "createdAt": "2026-01-01T00:00:00Z"}
    ).is_incremental


def test_containers_with_the_same_cve_on_different_images_stay_distinct():
    """Real data: one CVE on two images -> same ``id``/``similarityId``, different ``alternateId``."""

    def raw(alt, tag):
        return {
            "type": "containers",
            "id": "CVE-2026-9358",
            "alternateId": alt,
            "similarityId": "CVE-2026-9358",
            "severity": "LOW",
            "state": "TO_VERIFY",
            "data": {
                "packageName": "postcss-selector-parser",
                "packageVersion": "7.1.1",
                "imageName": "node",
                "imageTag": tag,
            },
            "vulnerabilityDetails": {"cveName": "CVE-2026-9358"},
        }

    a, b = (
        REG.normalize(raw("111", "24-slim"), "s", "p", "b"),
        REG.normalize(raw("222", "24-alpine"), "s", "p", "b"),
    )
    assert a.finding_id != b.finding_id and a.similarity_id != b.similarity_id
    assert a.similarity_id.startswith("CVE-2026-9358|node|24-slim|postcss-selector-parser|7.1.1")


def test_alternate_id_is_preferred_but_id_is_the_fallback():
    assert (
        REG.normalize({"type": "sast", "id": "A", "alternateId": "B", "data": {}}, "s", "p", "b").finding_id
        == "B"
    )
    assert REG.normalize({"type": "sast", "id": "A", "data": {}}, "s", "p", "b").finding_id == "A"
