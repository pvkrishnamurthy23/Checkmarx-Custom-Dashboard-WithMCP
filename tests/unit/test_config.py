import pytest
from pydantic import ValidationError

from cxdash.config import Settings
from tests.conftest import make_settings


def test_defaults_and_derived_urls():
    s = make_settings()
    assert s.cx_branches == ("master", "dis-devinteg")
    assert s.base_url == "https://eu.ast.checkmarx.net"
    assert s.iam_url == "https://eu.iam.checkmarx.net"
    assert s.token_url == "https://eu.iam.checkmarx.net/auth/realms/acme/protocol/openid-connect/token"
    assert make_settings(cx_region="us").base_url == "https://ast.checkmarx.net"
    assert make_settings(cx_region="eu2").iam_url == "https://eu-2.iam.checkmarx.net"


def test_explicit_url_overrides_allow_unknown_region():
    s = make_settings(cx_region="custom", cx_base_url="https://x.example/", cx_iam_url="https://iam.example/")
    assert s.base_url == "https://x.example"
    assert s.iam_url == "https://iam.example"


def test_unknown_region_without_overrides_fails():
    with pytest.raises(ValidationError, match="CX_REGION"):
        make_settings(cx_region="mars")


def test_comma_lists_are_split_trimmed_and_deduplicated():
    s = make_settings(
        cx_branches=" master, dis-devinteg ,master,,",
        cx_closed_states="not_exploitable, proposed_not_exploitable",
    )
    assert s.cx_branches == ("master", "dis-devinteg")
    assert s.cx_closed_states == ("NOT_EXPLOITABLE", "PROPOSED_NOT_EXPLOITABLE")


def test_empty_branches_means_all():
    s = make_settings(cx_branches="", sync_scan_selection="all")
    assert s.cx_branches == ()
    assert s.all_branches


def test_unknown_engine_is_a_startup_error():
    with pytest.raises(ValidationError, match="unknown engine"):
        make_settings(cx_engines="sast,nope")


def test_engines_are_lowercased():
    assert make_settings(cx_engines="SAST,Sca").cx_engines == ("sast", "sca")


def test_api_key_required_for_api_key_method():
    with pytest.raises(ValidationError, match="CX_API_KEY"):
        make_settings(cx_api_key="")


def test_oauth_client_requires_id_and_secret():
    with pytest.raises(ValidationError, match="CX_CLIENT_ID"):
        make_settings(cx_auth_method="oauth_client", cx_api_key="")
    s = make_settings(
        cx_auth_method="oauth_client", cx_api_key="", cx_client_id="id", cx_client_secret="secretsecret"
    )
    assert s.cx_client_id == "id"


def test_writeback_is_rejected():
    with pytest.raises(ValidationError, match="not implemented"):
        make_settings(enable_writeback=True)


def test_typos_in_env_file_fail_fast(tmp_path):
    env = tmp_path / ".env"
    env.write_text("CX_TENANT=t\nCX_API_KEY=abcdefgh\nCX_REGON=eu\n", encoding="utf-8")
    with pytest.raises(ValidationError):
        Settings(_env_file=str(env))  # type: ignore[call-arg]


def test_oidc_requires_its_settings():
    with pytest.raises(ValidationError, match="OIDC_ISSUER"):
        make_settings(auth_mode="oidc")


def test_proxy_headers_requires_trusted_ips():
    with pytest.raises(ValidationError, match="TRUSTED_PROXY_IPS"):
        make_settings(auth_mode="proxy_headers")


def test_short_session_secret_rejected():
    with pytest.raises(ValidationError, match="SESSION_SECRET"):
        make_settings(session_secret="short")


def test_masked_dump_hides_every_secret():
    s = make_settings(
        database_url="postgresql+psycopg://cx:hunter2hunter2@db:5432/cxdash", smtp_password="smtp-pass-123"
    )
    dump = s.masked_dump()
    text = str(dump)
    assert "test-api-key-value" not in text
    assert "hunter2hunter2" not in text
    assert "smtp-pass-123" not in text
    assert dump["cx_api_key"] == "********"


def test_sla_and_weights():
    s = make_settings()
    assert s.sla_days("critical") == 7
    assert s.sla_days("INFO") is None
    assert s.risk_weights["INFO"] == 0


def test_bad_deeplink_placeholder_rejected():
    with pytest.raises(ValidationError, match="placeholder"):
        make_settings(cx_deeplink_template="{ui_base}/{nope}")


def test_last_scan_is_the_default_and_needs_exact_branches():
    s = make_settings()
    assert (
        s.sync_scan_selection == "last_scan"
        and not s.sync_full_scans_only
        and s.sync_last_scan_status == "Completed"
    )
    assert (
        s.cx_results_page_size == 500
        and s.sync_max_api_calls_per_run == 2500
        and not s.sync_nightly_findings_refresh
    )
    for bad in ("", "release/*,master"):
        with pytest.raises(ValidationError, match="last_scan needs CX_BRANCHES"):
            make_settings(cx_branches=bad)
    assert make_settings(cx_branches="release/*", sync_scan_selection="all").cx_branches == ("release/*",)


def test_api_economy_bounds():
    with pytest.raises(ValidationError):
        make_settings(sync_last_scan_batch=0)
    with pytest.raises(ValidationError):
        make_settings(cx_results_page_size=5000)
    assert make_settings(sync_max_api_calls_per_run=0).sync_max_api_calls_per_run == 0
