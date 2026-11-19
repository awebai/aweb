"""Fixed-window rate limiting for DID endpoints.

Supports in-memory (single-instance) and Redis (multi-instance) backends.
"""

from __future__ import annotations

import asyncio
import logging
import os
import secrets
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import StrEnum

from fastapi import Depends, HTTPException, Request, Response
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import TimeoutError as RedisTimeoutError

from .client_ip import resolve_client_ip

logger = logging.getLogger(__name__)

AWID_SERVICE_TOKEN_HEADER = "X-AWID-Service-Token"
_MIN_SERVICE_TOKEN_BYTES = 32


def normalize_service_token(value: str | None) -> str | None:
    token = (value or "").strip()
    if not token:
        return None
    if len(token.encode("utf-8")) < _MIN_SERVICE_TOKEN_BYTES:
        raise ValueError(
            f"AWID_SERVICE_TOKEN must contain at least {_MIN_SERVICE_TOKEN_BYTES} bytes"
        )
    return token


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
    @property
    def is_degraded(self) -> bool:
        """Whether requests currently rely on a dependency-outage fallback."""
        return False

    @property
    def health_name(self) -> str:
        """The implementation currently enforcing this process's limits."""
        return type(self).__name__

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
                for k, (expires_at, _count) in list(self._counts.items()):
                    if expires_at <= now:
                        del self._counts[k]
                self._last_prune = now

            stored = self._counts.get(map_key)
            if stored is None or stored[0] != reset_epoch:
                count = 0
            else:
                count = stored[1]
            count += 1
            self._counts[map_key] = (reset_epoch, count)

        allowed = count <= limit
        remaining = max(0, limit - count)
        return RateLimitDecision(
            allowed=allowed,
            limit=limit,
            remaining=remaining,
            reset_epoch_seconds=reset_epoch,
        )


class _RedisLimitState(StrEnum):
    SHARED = "shared"
    PROCESS_LOCAL = "process_local"


class RedisFixedWindowRateLimiter(RateLimiter):
    """Shared limits with bounded process-local continuity during Redis outage.

    Antares f9b99e24 / coordinator7afba778 requires limits to remain on.
    Mirroring local hits also preserves the local bound across recovery; a
    failed connection is retried at most once per five seconds per process.
    """

    def __init__(self, *, redis) -> None:
        self._redis = redis
        self._memory = MemoryFixedWindowRateLimiter()
        self._state = _RedisLimitState.SHARED
        self._retry_after = 0.0
        self._lua = (
            "local v = redis.call('INCR', KEYS[1]);"
            "if v == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]); end;"
            "return v;"
        )

    @property
    def is_degraded(self) -> bool:
        return self._state is _RedisLimitState.PROCESS_LOCAL

    @property
    def health_name(self) -> str:
        return self._memory.health_name if self.is_degraded else type(self).__name__

    def _redis_unavailable(self) -> None:
        if self._state is _RedisLimitState.SHARED:
            logger.error(
                "AWID Redis rate limiting is unavailable; using bounded per-process limits. "
                "Restore Redis connectivity to restore shared limits.",
                exc_info=True,
            )
        self._state = _RedisLimitState.PROCESS_LOCAL
        self._retry_after = time.monotonic() + 5.0

    async def hit(
        self, *, bucket: str, key: str, limit: int, window_seconds: int
    ) -> RateLimitDecision:
        local = await self._memory.hit(
            bucket=bucket, key=key, limit=limit, window_seconds=window_seconds
        )
        if self.is_degraded and time.monotonic() < self._retry_after:
            return local
        now = time.time()
        window_id = int(now // window_seconds)
        reset_epoch = int((window_id + 1) * window_seconds)
        redis_key = f"aweb:rl:{bucket}:{key}:{window_id}"
        try:
            count = await self._redis.eval(
                self._lua, 1, redis_key, int(window_seconds) + 2
            )
        except (RedisConnectionError, RedisTimeoutError):
            self._redis_unavailable()
            return local
        if not isinstance(count, int) or isinstance(count, bool) or count < 1:
            raise TypeError("Redis rate-limit counter must be a positive integer")
        if self.is_degraded:
            logger.info("AWID Redis rate limiting restored; shared limits are active.")
        self._state = _RedisLimitState.SHARED
        return RateLimitDecision(
            allowed=count <= limit and local.allowed,
            limit=limit,
            remaining=min(max(0, limit - count), local.remaining),
            reset_epoch_seconds=reset_epoch,
        )


_BUCKET_DEFAULTS: dict[str, tuple[int, int]] = {
    # bucket_name: (limit, window_seconds) — per-IP fixed-window limits
    "did_register": (10, 3600),
    "did_update": (30, 3600),
    "did_key": (60, 60),
    "did_encryption_key_publish": (30, 3600),
    "did_addresses": (60, 60),
    "did_log": (30, 60),
    "did_head": (120, 60),
    "did_full": (30, 60),
    "namespace_register": (10, 3600),
    "namespace_get": (60, 60),
    "namespace_rotate": (30, 3600),
    "namespace_reverify": (10, 3600),
    "namespace_update": (30, 3600),
    "namespace_list": (30, 60),
    "namespace_delete": (10, 3600),
    "address_register": (30, 3600),
    "address_get": (60, 60),
    "address_list": (60, 60),
    "address_update": (30, 3600),
    "address_delete": (30, 3600),
    "address_reassign": (30, 3600),
    "address_atomic_claim": (30, 3600),
    "a2a_delegation_publish": (30, 3600),
    "a2a_publication_publish": (30, 3600),
    "a2a_publication_get": (120, 60),
    "custody_sign": (60, 60),
    "team_create": (10, 3600),
    "team_list": (60, 60),
    "team_get": (60, 60),
    "team_member_get": (60, 60),
    "team_delete": (300, 3600),
    "team_rotate": (10, 3600),
    "team_update": (300, 3600),
    "certificate_register": (30, 3600),
    "id_certificate_register": (300, 3600),
    "id_certificate_revoke": (300, 3600),
    "id_certificate_status": (60, 60),
    "certificate_list": (60, 60),
    "certificate_fetch": (60, 60),
    "certificate_status": (60, 60),
    "team_server_publish": (30, 3600),
    "team_server_get": (120, 60),
    "certificate_revoke": (1000, 3600),
    "revocation_list": (60, 60),
    "attestation_record_publish": (3000, 3600),
    "attestation_record_publish_team": (2500, 3600),
    "attestation_record_get": (60, 60),
    "attestation_record_list": (60, 60),
}


def _rate_config(bucket: str) -> tuple[int, int]:
    cfg = _BUCKET_DEFAULTS.get(bucket)
    if cfg is None:
        raise ValueError(f"unknown rate limit bucket: {bucket}")
    return cfg


def _extract_client_ip(request: Request) -> str:
    return resolve_client_ip(request)


def build_rate_limiter(*, redis=None, backend: str | None = None) -> RateLimiter:
    if os.getenv("AWID_RATE_LIMIT_DISABLED", "").strip().lower() in (
        "1",
        "true",
        "yes",
    ):
        return NoOpRateLimiter()
    if backend is None:
        backend = os.getenv("AWEB_RATE_LIMIT_BACKEND", "memory")
    if backend == "redis":
        if redis is None:
            raise ValueError("rate_limit backend=redis requires a Redis client")
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


def _record_trusted_service_exemption(request: Request, bucket: str) -> None:
    counts = getattr(request.app.state, "awid_service_exempt_counts", None)
    if counts is None:
        counts = {}
        request.app.state.awid_service_exempt_counts = counts
    count = int(counts.get(bucket, 0)) + 1
    counts[bucket] = count
    # Low-cardinality, aggregated positive signal: first exemption for a bucket,
    # then powers of two, avoids per-request log spam while proving the token is
    # actively matching in production.
    if count == 1 or count & (count - 1) == 0:
        logger.info(
            "event=awid_service_exempt metric=awid_service_exempt value=%s bucket=%s",
            count,
            bucket,
        )


def rate_limit_dep(
    bucket: str,
    *,
    key_extractor: Callable[[Request], str] = ip_bucket_key,
    allow_trusted_service: bool = False,
) -> Callable[..., Awaitable[None]]:
    async def _dep(
        request: Request,
        response: Response,
        limiter: RateLimiter = Depends(get_rate_limiter),
    ) -> None:
        if allow_trusted_service:
            expected = getattr(request.app.state, "awid_service_token", None)
            presented = (request.headers.get(AWID_SERVICE_TOKEN_HEADER) or "").strip()
            if trusted_service_token_matches(expected, presented):
                _record_trusted_service_exemption(request, bucket)
                return
            if presented:
                logger.warning(
                    "event=awid_service_credential_rejected "
                    "metric=awid_service_credential_rejected value=1 bucket=%s",
                    bucket,
                )

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


def trusted_service_token_matches(expected: str | None, presented: str | None) -> bool:
    """Constant-time configured token check; an unconfigured token admits none."""
    return bool(
        expected
        and presented
        and secrets.compare_digest(expected.encode("utf-8"), presented.encode("utf-8"))
    )
