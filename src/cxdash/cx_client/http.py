"""Read-only async HTTP client for Checkmarx One (spec 6.3).

Only ``get`` and ``paged`` are public. A request hook additionally refuses any
non-GET request, so even a future bug cannot write to ``CX_BASE_URL``.
"""

from __future__ import annotations

import asyncio
import contextvars
import logging
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

import httpx
from prometheus_client import Counter, Histogram
from tenacity import (
    AsyncRetrying,
    RetryCallState,
    retry_if_exception,
    stop_after_attempt,
    wait_random_exponential,
)

from cxdash.cx_client.auth import TokenProvider

log = logging.getLogger(__name__)

API_REQUESTS = Counter("cx_api_requests_total", "Checkmarx One API requests", ["endpoint", "status"])
API_LATENCY = Histogram("cx_api_latency_seconds", "Checkmarx One API latency", ["endpoint"])

RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})
MAX_RETRY_AFTER_SECONDS = 120.0


class ReadOnlyViolation(RuntimeError):
    """Raised when anything other than GET is attempted against the API base URL."""


class ApiError(RuntimeError):
    def __init__(self, status: int, path: str) -> None:
        super().__init__(f"Checkmarx One API returned HTTP {status} for {path}")
        self.status = status
        self.path = path


class _Retryable(Exception):
    def __init__(self, status: int | None, retry_after: float | None = None) -> None:
        super().__init__(f"retryable (status={status})")
        self.status = status
        self.retry_after = retry_after


class ApiBudgetExceeded(RuntimeError):
    """The per-run API call cap (SYNC_MAX_API_CALLS_PER_RUN) was reached; the job stops, the next cycle resumes."""


class ApiCallCounter:
    """Counts API calls for the current sync job (carried through a ContextVar) and enforces the cap."""

    def __init__(self, limit: int = 0) -> None:
        self.calls = 0
        self.limit = limit


_current_counter: contextvars.ContextVar[ApiCallCounter | None] = contextvars.ContextVar(
    "cx_api_call_counter", default=None
)


def track_api_calls(limit: int = 0) -> ApiCallCounter:
    counter = ApiCallCounter(limit)
    _current_counter.set(counter)
    return counter


def _parse_retry_after(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return max(0.0, min(float(value), MAX_RETRY_AFTER_SECONDS))
    except ValueError:
        return None  # HTTP-date form is not worth supporting; fall back to backoff


def _wait(state: RetryCallState) -> float:
    exc = state.outcome.exception() if state.outcome else None
    if isinstance(exc, _Retryable) and exc.retry_after is not None:
        return exc.retry_after
    return wait_random_exponential(multiplier=1, max=30)(state)


class CheckmarxHttpClient:
    def __init__(
        self,
        base_url: str,
        tokens: TokenProvider,
        *,
        max_concurrency: int = 5,
        timeout: float = 60.0,
        max_retries: int = 5,
        page_size: int = 100,
        transport: httpx.AsyncBaseTransport | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._tokens = tokens
        self._max_retries = max_retries
        self._page_size = page_size
        self._sleep = sleep
        self._sem = asyncio.Semaphore(max_concurrency)
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            http2=False,
            timeout=timeout,
            limits=httpx.Limits(max_connections=max_concurrency, max_keepalive_connections=max_concurrency),
            transport=transport,
            event_hooks={"request": [self._guard]},
            follow_redirects=False,
        )

    @staticmethod
    async def _guard(request: httpx.Request) -> None:
        if request.method != "GET":
            raise ReadOnlyViolation(f"{request.method} is not allowed against the Checkmarx One API")

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> CheckmarxHttpClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def get(self, path: str, **params: Any) -> Any:
        """GET ``path`` and return decoded JSON. ``None`` params are dropped."""
        query = {k: v for k, v in params.items() if v is not None}
        retrying = AsyncRetrying(
            stop=stop_after_attempt(self._max_retries),
            wait=_wait,
            retry=retry_if_exception(lambda e: isinstance(e, _Retryable)),
            sleep=self._sleep,
            reraise=True,
        )
        try:
            async for attempt in retrying:
                with attempt:
                    return await self._once(path, query)
        except _Retryable as exc:
            raise ApiError(exc.status or 0, path) from None
        raise AssertionError("unreachable")  # pragma: no cover

    async def _once(self, path: str, query: dict[str, Any]) -> Any:
        resp, token = await self._request(path, query)
        if resp.status_code == 401:
            # refresh once and retry once (spec 6.2)
            await self._tokens.invalidate(token)
            resp, _ = await self._request(path, query)
        if resp.status_code in RETRYABLE_STATUS:
            raise _Retryable(resp.status_code, _parse_retry_after(resp.headers.get("Retry-After")))
        if resp.status_code >= 400:
            raise ApiError(resp.status_code, path)
        return resp.json()

    async def _request(self, path: str, query: dict[str, Any]) -> tuple[httpx.Response, str]:
        token = await self._tokens.get_token()
        counter = _current_counter.get()
        if counter is not None:
            if counter.limit and counter.calls >= counter.limit:
                raise ApiBudgetExceeded(f"API call cap of {counter.limit} per run reached")
            counter.calls += 1
        started = time.perf_counter()
        status = "error"
        try:
            async with self._sem:
                resp = await self._client.get(
                    path,
                    params=query,
                    headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
                )
            status = str(resp.status_code)
            return resp, token
        except (httpx.TransportError, httpx.TimeoutException) as exc:
            raise _Retryable(None) from exc
        finally:
            API_REQUESTS.labels(path, status).inc()
            API_LATENCY.labels(path).observe(time.perf_counter() - started)

    async def paged(
        self, path: str, items_key: str, *, limit: int | None = None, **params: Any
    ) -> AsyncIterator[dict[str, Any]]:
        """Yield items using limit/offset until a short or empty page."""
        size = limit or self._page_size
        offset = 0
        while True:
            body = await self.get(path, limit=size, offset=offset, **params)
            items = (body.get(items_key) if isinstance(body, dict) else body) or []
            for item in items:
                yield item
            if len(items) < size:
                return
            offset += size
