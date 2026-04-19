"""Fixed-window rate limiting for DID endpoints.

Supports in-memory (single-instance) and Redis (multi-instance) backends.
"""

from __future__ import annotations

import asyncio
import os
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request, Response


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    limit: int
    remaining: int
    reset_epoch_seconds: int

    def headers(self) -> dict[str, str]:
        return {
            "X-RateLimit-Limit": str(self.limit),
            "X-RateLimit-Remaining": str(self.remaining),
            "X-RateLimit-Reset": str(self.reset_epoch_seconds),
        }

    def retry_after_seconds(self) -> int:
        now = int(time.time())
        return max(0, self.reset_epoch_seconds - now)


class RateLimiter:
    async def hit(
        self, *, bucket: str, key: str, limit: int, window_seconds: int
    ) -> RateLimitDecision:
        raise NotImplementedError


class NoOpRateLimiter(RateLimiter):
    """Always allows — for local development and e2e tests."""

    async def hit(
        self, *, bucket: str, key: str, limit: int, window_seconds: int
    ) -> RateLimitDecision:
        return RateLimitDecision(
            allowed=True,
            limit=limit,
            remaining=limit,
            reset_epoch_seconds=int(time.time()) + window_seconds,
        )


class MemoryFixedWindowRateLimiter(RateLimiter):
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._counts: dict[str, tuple[int, int]] = {}
        self._last_prune = 0.0

    async def hit(
        self, *, bucket: str, key: str, limit: int, window_seconds: int
    ) -> RateLimitDecision:
        now = time.time()
        window_id = int(now // window_seconds)
        reset_epoch = int((window_id + 1) * window_seconds)
        map_key = f"{bucket}:{key}"

        async with self._lock:
            if now - self._last_prune > 60:
                cutoff = window_id - 1
                for k, (w, _c) in list(self._counts.items()):
                    if w < cutoff:
                        del self._counts[k]
                self._last_prune = now

            stored = self._counts.get(map_key)
            if stored is None or stored[0] != window_id:
                count = 0
            else:
                count = stored[1]
            count += 1
            self._counts[map_key] = (window_id, count)

        allowed = count <= limit
        remaining = max(0, limit - count)
        return RateLimitDecision(
            allowed=allowed,
            limit=limit,
            remaining=remaining,
            reset_epoch_seconds=reset_epoch,
        )


class RedisFixedWindowRateLimiter(RateLimiter):
    def __init__(self, *, redis) -> None:
        self._redis = redis
        self._lua = (
            "local v = redis.call('INCR', KEYS[1]);"
            "if v == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]); end;"
            "return v;"
        )

    async def hit(
        self, *, bucket: str, key: str, limit: int, window_seconds: int
    ) -> RateLimitDecision:
        now = time.time()
        window_id = int(now // window_seconds)
        reset_epoch = int((window_id + 1) * window_seconds)
        redis_key = f"aweb:rl:{bucket}:{key}:{window_id}"

        v = await self._redis.eval(self._lua, 1, redis_key, int(window_seconds) + 2)
        count = int(v)
        allowed = count <= limit
        remaining = max(0, limit - count)
        return RateLimitDecision(
            allowed=allowed,
            limit=limit,
            remaining=remaining,
            reset_epoch_seconds=reset_epoch,
        )


_BUCKET_DEFAULTS: dict[str, tuple[int, int]] = {
    # bucket_name: (limit, window_seconds) — per-IP fixed-window limits
    "did_register": (10, 3600),
    "did_update": (30, 3600),
    "did_key": (60, 60),
    "did_addresses": (60, 60),
    "did_log": (30, 60),
    "did_head": (120, 60),
    "did_full": (30, 60),
    "namespace_register": (10, 3600),
    "namespace_get": (60, 60),
    "namespace_rotate": (30, 3600),
    "namespace_reverify": (10, 3600),
    "namespace_list": (30, 60),
    "namespace_delete": (10, 3600),
    "address_register": (30, 3600),
    "address_get": (60, 60),
    "address_list": (60, 60),
    "address_update": (30, 3600),
    "address_delete": (30, 3600),
    "address_reassign": (30, 3600),
    "custody_sign": (60, 60),
    "team_create": (10, 3600),
    "team_list": (60, 60),
    "team_get": (60, 60),
    "team_member_get": (60, 60),
    "team_delete": (10, 3600),
    "team_rotate": (10, 3600),
    "team_update": (10, 3600),
    "certificate_register": (30, 3600),
    "certificate_list": (60, 60),
    "certificate_revoke": (30, 3600),
    "revocation_list": (60, 60),
}


def _rate_config(bucket: str) -> tuple[int, int]:
    cfg = _BUCKET_DEFAULTS.get(bucket)
    if cfg is None:
        raise ValueError(f"unknown rate limit bucket: {bucket}")
    return cfg


def _extract_client_ip(request: Request) -> str:
    import os
    if os.getenv("AWEB_TRUST_PROXY_HEADERS", "").strip().lower() in ("1", "true", "yes"):
        xff = request.headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[0].strip()
        xrip = request.headers.get("x-real-ip")
        if xrip:
            return xrip.strip()

    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def build_rate_limiter(*, redis=None) -> RateLimiter:
    if os.getenv("AWID_RATE_LIMIT_DISABLED", "").strip().lower() in ("1", "true", "yes"):
        return NoOpRateLimiter()
    backend = os.getenv("AWEB_RATE_LIMIT_BACKEND", "memory")
    if backend == "redis":
        if redis is None:
            raise ValueError("AWEB_RATE_LIMIT_BACKEND=redis requires a Redis client")
        return RedisFixedWindowRateLimiter(redis=redis)
    return MemoryFixedWindowRateLimiter()


def ip_bucket_key(request: Request) -> str:
    return _extract_client_ip(request)


async def get_rate_limiter(request: Request) -> RateLimiter:
    limiter = getattr(request.app.state, "rate_limiter", None)
    if limiter is None:
        raise RuntimeError("rate_limiter not initialized on app.state")
    return limiter


async def enforce_rate_limit(
    request: Request,
    response: Response,
    *,
    bucket: str,
    key: str,
) -> None:
    limiter = await get_rate_limiter(request)
    limit, window = _rate_config(bucket)
    decision = await limiter.hit(
        bucket=bucket,
        key=key,
        limit=limit,
        window_seconds=window,
    )
    for k, v in decision.headers().items():
        response.headers[k] = v

    if decision.allowed:
        return

    retry_after = decision.retry_after_seconds()
    headers = decision.headers()
    headers["Retry-After"] = str(retry_after)
    raise HTTPException(
        status_code=429,
        detail="rate limit exceeded",
        headers=headers,
    )


def rate_limit_dep(
    bucket: str, *, key_extractor: Callable[[Request], str] = ip_bucket_key
) -> Callable[..., Awaitable[None]]:
    async def _dep(
        request: Request,
        response: Response,
        limiter: RateLimiter = Depends(get_rate_limiter),
    ) -> None:
        limit, window = _rate_config(bucket)
        key = key_extractor(request)
        decision = await limiter.hit(
            bucket=bucket, key=key, limit=limit, window_seconds=window
        )
        for k, v in decision.headers().items():
            response.headers[k] = v

        if decision.allowed:
            return

        retry_after = decision.retry_after_seconds()
        headers = decision.headers()
        headers["Retry-After"] = str(retry_after)
        raise HTTPException(
            status_code=429, detail="rate limit exceeded", headers=headers
        )

    return _dep
