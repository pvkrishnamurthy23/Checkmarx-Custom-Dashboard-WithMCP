"""Token management (spec 6.2).

``TokenRequestStrategy`` isolates the two grant types (Open/Closed): adding a
new auth method means adding a strategy, not editing ``TokenManager``.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from typing import Protocol

import httpx

from cxdash.config import Settings

log = logging.getLogger(__name__)

REFRESH_MARGIN_SECONDS = 60


class AuthError(RuntimeError):
    """Raised when a token cannot be obtained. Never includes credentials."""


class TokenRequestStrategy(Protocol):
    def form(self) -> dict[str, str]: ...


class ApiKeyStrategy:
    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    def form(self) -> dict[str, str]:
        return {"grant_type": "refresh_token", "client_id": "ast-app", "refresh_token": self._api_key}


class ClientCredentialsStrategy:
    def __init__(self, client_id: str, client_secret: str) -> None:
        self._id, self._secret = client_id, client_secret

    def form(self) -> dict[str, str]:
        return {"grant_type": "client_credentials", "client_id": self._id, "client_secret": self._secret}


def strategy_from_settings(settings: Settings) -> TokenRequestStrategy:
    if settings.cx_auth_method == "api_key":
        return ApiKeyStrategy(settings.cx_api_key.get_secret_value())
    return ClientCredentialsStrategy(settings.cx_client_id, settings.cx_client_secret.get_secret_value())


class TokenProvider(Protocol):
    async def get_token(self) -> str: ...
    async def invalidate(self, stale_token: str | None = None) -> None: ...


class TokenManager:
    """Caches the access token in memory; one refresh at a time (asyncio.Lock)."""

    def __init__(
        self,
        token_url: str,
        strategy: TokenRequestStrategy,
        *,
        timeout: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._token_url = token_url
        self._strategy = strategy
        self._timeout = timeout
        self._transport = transport
        self._clock = clock
        self._lock = asyncio.Lock()
        self._token: str | None = None
        self._expires_at = 0.0

    def _valid(self) -> bool:
        return self._token is not None and self._clock() < self._expires_at - REFRESH_MARGIN_SECONDS

    async def get_token(self) -> str:
        if self._valid():
            return self._token  # type: ignore[return-value]
        async with self._lock:
            if self._valid():  # another task refreshed while we waited
                return self._token  # type: ignore[return-value]
            await self._refresh()
            return self._token  # type: ignore[return-value]

    async def invalidate(self, stale_token: str | None = None) -> None:
        """Drop the cached token (only if it is still the one that was rejected)."""
        async with self._lock:
            if stale_token is None or self._token == stale_token:
                self._token = None
                self._expires_at = 0.0

    async def _refresh(self) -> None:
        # This is the only POST the process makes, and it targets the IAM host,
        # never CX_BASE_URL (spec: "GET methods only plus the token POST").
        async with httpx.AsyncClient(timeout=self._timeout, transport=self._transport) as client:
            try:
                resp = await client.post(
                    self._token_url,
                    data=self._strategy.form(),
                    headers={"Accept": "application/json"},
                )
            except httpx.HTTPError as exc:
                raise AuthError(f"token endpoint unreachable: {type(exc).__name__}") from exc
        if resp.status_code != 200:
            # Body deliberately not logged: it may echo request fields.
            raise AuthError(f"token request failed with HTTP {resp.status_code}")
        body = resp.json()
        token = body.get("access_token")
        if not token:
            raise AuthError("token response had no access_token")
        self._token = token
        self._expires_at = self._clock() + float(body.get("expires_in", 300))
        log.info("access token refreshed", extra={"expires_in": body.get("expires_in")})
