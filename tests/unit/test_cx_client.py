import asyncio

import httpx
import pytest
import respx

from cxdash.cx_client.auth import (
    ApiKeyStrategy,
    AuthError,
    ClientCredentialsStrategy,
    TokenManager,
    strategy_from_settings,
)
from cxdash.cx_client.endpoints import CheckmarxApi
from cxdash.cx_client.http import ApiError, CheckmarxHttpClient, ReadOnlyViolation, track_api_calls
from tests.conftest import load_fixture, make_settings

BASE = "https://eu.ast.checkmarx.net"
TOKEN_URL = "https://eu.iam.checkmarx.net/auth/realms/acme/protocol/openid-connect/token"


async def _no_sleep(_: float) -> None:
    return None


def make_client(**kw):
    tm = TokenManager(TOKEN_URL, ApiKeyStrategy("my-api-key"))
    return CheckmarxHttpClient(BASE, tm, sleep=_no_sleep, **kw), tm


@pytest.fixture
def mock():
    with respx.mock(assert_all_called=False) as m:
        m.post(TOKEN_URL).mock(return_value=httpx.Response(200, json=load_fixture("token.json")))
        yield m


async def test_api_key_flow_form_fields(mock):
    client, _ = make_client()
    mock.get(f"{BASE}/api/x").mock(return_value=httpx.Response(200, json={"ok": True}))
    assert await client.get("/api/x") == {"ok": True}
    token_req = next(c.request for c in mock.calls if c.request.method == "POST")
    body = token_req.content.decode()
    assert (
        "grant_type=refresh_token" in body
        and "client_id=ast-app" in body
        and "refresh_token=my-api-key" in body
    )
    api_req = next(c.request for c in mock.calls if c.request.method == "GET")
    assert api_req.headers["Authorization"] == "Bearer test-access-token-1"
    assert api_req.headers["Accept"] == "application/json"
    await client.aclose()


async def test_oauth_client_flow_form_fields(mock):
    tm = TokenManager(TOKEN_URL, ClientCredentialsStrategy("cid", "csecret"))
    client = CheckmarxHttpClient(BASE, tm, sleep=_no_sleep)
    mock.get(f"{BASE}/api/x").mock(return_value=httpx.Response(200, json={}))
    await client.get("/api/x")
    body = next(c.request for c in mock.calls if c.request.method == "POST").content.decode()
    assert (
        "grant_type=client_credentials" in body
        and "client_id=cid" in body
        and "client_secret=csecret" in body
    )
    await client.aclose()


def test_strategy_from_settings():
    assert isinstance(strategy_from_settings(make_settings()), ApiKeyStrategy)
    s = make_settings(
        cx_auth_method="oauth_client", cx_api_key="", cx_client_id="a", cx_client_secret="bbbbbbbb"
    )
    assert isinstance(strategy_from_settings(s), ClientCredentialsStrategy)


async def test_token_cached_and_single_refresh_under_concurrency(mock):
    client, _ = make_client()
    mock.get(f"{BASE}/api/x").mock(return_value=httpx.Response(200, json={}))
    await asyncio.gather(*(client.get("/api/x") for _ in range(10)))
    assert sum(1 for c in mock.calls if c.request.method == "POST") == 1
    await client.aclose()


async def test_token_refreshed_when_near_expiry(mock):
    now = [0.0]
    tm = TokenManager(TOKEN_URL, ApiKeyStrategy("k"), clock=lambda: now[0])
    await tm.get_token()
    now[0] = 300 - 59  # inside the 60s margin
    await tm.get_token()
    assert sum(1 for c in mock.calls if c.request.method == "POST") == 2


async def test_401_refreshes_once_and_retries_once(mock):
    client, _ = make_client()
    route = mock.get(f"{BASE}/api/x").mock(
        side_effect=[httpx.Response(401), httpx.Response(200, json={"a": 1})]
    )
    assert await client.get("/api/x") == {"a": 1}
    assert route.call_count == 2
    assert sum(1 for c in mock.calls if c.request.method == "POST") == 2
    await client.aclose()


async def test_persistent_401_is_not_retried_forever(mock):
    client, _ = make_client()
    route = mock.get(f"{BASE}/api/x").mock(return_value=httpx.Response(401))
    with pytest.raises(ApiError) as exc:
        await client.get("/api/x")
    assert exc.value.status == 401
    assert route.call_count == 2
    await client.aclose()


async def test_429_honours_retry_after_then_succeeds(mock):
    sleeps: list[float] = []

    async def record(d: float) -> None:
        sleeps.append(d)

    tm = TokenManager(TOKEN_URL, ApiKeyStrategy("k"))
    client = CheckmarxHttpClient(BASE, tm, sleep=record)
    route = mock.get(f"{BASE}/api/x").mock(
        side_effect=[httpx.Response(429, headers={"Retry-After": "7"}), httpx.Response(200, json={"ok": 1})]
    )
    assert await client.get("/api/x") == {"ok": 1}
    assert route.call_count == 2
    assert sleeps == [7.0]
    await client.aclose()


@pytest.mark.parametrize("status", [500, 502, 503, 504])
async def test_5xx_retries_until_max_then_raises(mock, status):
    client, _ = make_client(max_retries=3)
    route = mock.get(f"{BASE}/api/x").mock(return_value=httpx.Response(status))
    with pytest.raises(ApiError) as exc:
        await client.get("/api/x")
    assert exc.value.status == status
    assert route.call_count == 3
    await client.aclose()


async def test_connection_error_is_retried(mock):
    client, _ = make_client(max_retries=3)
    route = mock.get(f"{BASE}/api/x").mock(
        side_effect=[httpx.ConnectError("boom"), httpx.Response(200, json={"ok": 1})]
    )
    assert await client.get("/api/x") == {"ok": 1}
    assert route.call_count == 2
    await client.aclose()


async def test_4xx_is_not_retried(mock):
    client, _ = make_client()
    route = mock.get(f"{BASE}/api/x").mock(return_value=httpx.Response(404))
    with pytest.raises(ApiError):
        await client.get("/api/x")
    assert route.call_count == 1
    await client.aclose()


async def test_paging_stops_on_short_page(mock):
    client, _ = make_client(page_size=2)
    route = mock.get(f"{BASE}/api/projects").mock(
        side_effect=[
            httpx.Response(200, json={"projects": [{"id": 1}, {"id": 2}]}),
            httpx.Response(200, json={"projects": [{"id": 3}]}),
        ]
    )
    items = [i async for i in client.paged("/api/projects", "projects")]
    assert [i["id"] for i in items] == [1, 2, 3]
    assert [dict(c.request.url.params) for c in route.calls] == [
        {"limit": "2", "offset": "0"},
        {"limit": "2", "offset": "2"},
    ]
    await client.aclose()


async def test_paging_stops_on_empty_page(mock):
    client, _ = make_client(page_size=2)
    mock.get(f"{BASE}/api/projects").mock(
        side_effect=[
            httpx.Response(200, json={"projects": [{"id": 1}, {"id": 2}]}),
            httpx.Response(200, json={"projects": []}),
        ]
    )
    assert len([i async for i in client.paged("/api/projects", "projects")]) == 2
    await client.aclose()


async def test_none_params_are_dropped(mock):
    client, _ = make_client()
    route = mock.get(f"{BASE}/api/x").mock(return_value=httpx.Response(200, json={}))
    await client.get("/api/x", a=None, b="1")
    assert dict(route.calls[0].request.url.params) == {"b": "1"}
    await client.aclose()


async def test_only_get_is_ever_sent_to_base_url(mock):
    """Spec section 1: no verb other than GET may hit CX_BASE_URL."""
    client, _ = make_client()
    mock.get(f"{BASE}/api/projects").mock(return_value=httpx.Response(200, json={"projects": []}))
    mock.get(f"{BASE}/api/applications").mock(return_value=httpx.Response(200, json={"applications": []}))
    mock.get(f"{BASE}/api/scans").mock(return_value=httpx.Response(200, json={"scans": []}))
    mock.get(f"{BASE}/api/scan-summary").mock(return_value=httpx.Response(200, json={"scansSummaries": []}))
    mock.get(f"{BASE}/api/results").mock(return_value=httpx.Response(200, json={"results": []}))
    api = CheckmarxApi(client)
    [_ async for _ in api.projects()]
    [_ async for _ in api.applications()]
    [_ async for _ in api.scans(branch="master")]
    await api.scan_summaries(["a", "b"])
    [_ async for _ in api.results("s")]
    await client.aclose()
    verbs = {c.request.method for c in mock.calls if str(c.request.url).startswith(BASE)}
    assert verbs == {"GET"}


@pytest.mark.parametrize("verb", ["post", "put", "patch", "delete"])
async def test_write_verbs_are_blocked_by_guard(mock, verb):
    client, _ = make_client()
    assert not hasattr(client, verb)  # the wrapper exposes no write methods
    with pytest.raises(ReadOnlyViolation):
        await client._client.request(verb.upper(), "/api/projects")  # even bypassing the wrapper
    assert not any(c.request.method != "POST" and c.request.method != "GET" for c in mock.calls)
    await client.aclose()


async def test_token_failure_raises_auth_error_without_credentials():
    with respx.mock() as m:
        m.post(TOKEN_URL).mock(
            return_value=httpx.Response(400, json={"error": "invalid_grant", "echo": "my-api-key"})
        )
        tm = TokenManager(TOKEN_URL, ApiKeyStrategy("my-api-key"))
        with pytest.raises(AuthError) as exc:
            await tm.get_token()
        assert "my-api-key" not in str(exc.value)
        assert "400" in str(exc.value)


async def test_api_call_counter(mock):
    client, _ = make_client()
    mock.get(f"{BASE}/api/x").mock(return_value=httpx.Response(200, json={}))
    counter = track_api_calls()
    await client.get("/api/x")
    await client.get("/api/x")
    assert counter.calls == 2
    await client.aclose()


async def test_per_run_api_call_cap_stops_further_calls(mock):
    from cxdash.cx_client.http import ApiBudgetExceeded

    client, _ = make_client()
    mock.get(f"{BASE}/api/x").mock(return_value=httpx.Response(200, json={}))
    track_api_calls(limit=2)
    await client.get("/api/x")
    await client.get("/api/x")
    with pytest.raises(ApiBudgetExceeded):
        await client.get("/api/x")
    assert (
        sum(1 for c in mock.calls if c.request.method == "GET") == 2
    )  # the third call never left the process
    track_api_calls(limit=0)  # unlimited
    await client.get("/api/x")
    await client.aclose()


async def test_last_scans_scans_by_ids_and_results_use_the_verified_parameters(mock):
    client, _ = make_client()
    api = CheckmarxApi(client, results_page_size=500)
    last = mock.get(f"{BASE}/api/projects/last-scan").mock(
        return_value=httpx.Response(
            200, json={"p1": {"id": "s1", "branch": "master"}, "p2": {"note": "no id"}}
        )
    )
    assert list(await api.last_scans(["p1", "p2"], branch="master")) == ["p1"]
    q = dict(last.calls[0].request.url.params)
    assert q == {
        "project-ids": "p1,p2",
        "branch": "master",
        "scan-status": "Completed",
        "limit": "2",
        "offset": "0",
    }

    byid = mock.get(f"{BASE}/api/scans").mock(
        return_value=httpx.Response(
            200,
            json={
                "scans": [
                    {
                        "id": "s1",
                        "status": "Completed",
                        "projectId": "p1",
                        "createdAt": "2026-01-01T00:00:00Z",
                    }
                ]
            },
        )
    )
    got = [s async for s in api.scans_by_ids(["s1", "s2"])]
    assert [s.id for s in got] == ["s1"] and dict(byid.calls[0].request.url.params)["scan-ids"] == "s1,s2"

    results = mock.get(f"{BASE}/api/results").mock(
        return_value=httpx.Response(200, json={"results": [{"id": "r"}]})
    )
    assert [r async for r in api.results("s1")] == [{"id": "r"}]
    assert dict(results.calls[0].request.url.params) == {
        "scan-id": "s1",
        "limit": "500",
        "offset": "0",
    }  # one call for a typical scan

    recent = mock.get(f"{BASE}/api/scans").mock(return_value=httpx.Response(200, json={"scans": []}))
    assert await api.recent_scans("p1", branch="master", status="Completed", limit=20) == []
    assert dict(recent.calls[-1].request.url.params) == {
        "project-id": "p1",
        "branch": "master",
        "statuses": "Completed",
        "limit": "20",
        "offset": "0",
        "sort": "-created_at",
    }
    await client.aclose()
