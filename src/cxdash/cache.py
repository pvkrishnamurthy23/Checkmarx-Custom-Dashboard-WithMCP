"""Query-result cache (spec 10.3): keyed by (query id, filter hash, data version).

The data version is the time of the last successful sync, so every new sync implicitly
invalidates old entries (no explicit purge needed). Values must be JSON-serialisable.
Redis is optional; without it an in-process TTL cache is used.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections.abc import Callable
from typing import Protocol, TypeVar

log = logging.getLogger(__name__)
T = TypeVar("T")


class CacheBackend(Protocol):
    def get(self, key: str) -> str | None: ...
    def set(self, key: str, value: str, ttl: int) -> None: ...


class MemoryBackend:
    def __init__(self, max_items: int = 512) -> None:
        self._data: dict[str, tuple[float, str]] = {}
        self._lock = threading.Lock()
        self._max = max_items

    def get(self, key: str) -> str | None:
        with self._lock:
            hit = self._data.get(key)
            if hit and hit[0] > time.monotonic():
                return hit[1]
            self._data.pop(key, None)
            return None

    def set(self, key: str, value: str, ttl: int) -> None:
        with self._lock:
            if len(self._data) >= self._max:
                self._data.pop(next(iter(self._data)))
            self._data[key] = (time.monotonic() + ttl, value)


class RedisBackend:
    def __init__(self, url: str) -> None:
        import redis

        self._r = redis.Redis.from_url(url, socket_timeout=2, socket_connect_timeout=2)

    def get(self, key: str) -> str | None:
        try:
            v = self._r.get(key)
            return v.decode() if v else None
        except Exception:  # cache is best-effort; never break a page for it
            log.warning("redis get failed; continuing uncached")
            return None

    def set(self, key: str, value: str, ttl: int) -> None:
        try:
            self._r.set(key, value, ex=ttl)
        except Exception:
            log.warning("redis set failed; continuing uncached")


class QueryCache:
    def __init__(self, backend: CacheBackend, ttl_seconds: int, version: Callable[[], str]) -> None:
        self._backend, self._ttl, self._version = backend, ttl_seconds, version
        self._ver_cache: tuple[float, str] = (0.0, "")

    def _data_version(self) -> str:
        ts, v = self._ver_cache
        if time.monotonic() - ts > 10:  # cheap staleness bound on the version lookup itself
            v = self._version()
            self._ver_cache = (time.monotonic(), v)
        return v

    def get_or_compute(self, query_id: str, filter_hash: str, compute: Callable[[], T]) -> T:
        key = f"cxdash:{self._data_version()}:{query_id}:{filter_hash}"
        raw = self._backend.get(key)
        if raw is not None:
            return json.loads(raw)  # type: ignore[no-any-return]
        value = compute()
        try:
            self._backend.set(key, json.dumps(value, default=str), self._ttl)
        except (TypeError, ValueError):
            log.warning("uncacheable value", extra={"query": query_id})
        return value


def build_backend(redis_url: str) -> CacheBackend:
    if redis_url:
        return RedisBackend(redis_url)
    return MemoryBackend()


__all__ = ["CacheBackend", "MemoryBackend", "QueryCache", "RedisBackend", "build_backend"]
