"""Post-authority replay admission shared by OSS dependencies and embedding hosts."""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import logging
import math
import time
from typing import Protocol

from fastapi import HTTPException, Request

from aweb.auth_metrics import count_nonce_free_request_auth, count_request_auth_replay
from aweb.team_auth_envelope import TeamAuthEnvelope

logger = logging.getLogger(__name__)


class RequestReplayStore(Protocol):
    async def claim(self, key: str, expires_at: datetime) -> bool:
        """Atomically create until expiry; True only for the first claim."""
        ...


class RedisRequestReplayStore:
    def __init__(self, redis, *, key_prefix: str = 'aweb:request-auth:replay:'):
        self.redis = redis
        self.key_prefix = key_prefix

    async def claim(self, key: str, expires_at: datetime) -> bool:
        return bool(await self.redis.set(self.key_prefix + key, '1', nx=True,
                                        pxat=math.ceil(expires_at.timestamp() * 1000)))


class MemoryRequestReplayStore:
    """Explicit single-process self-hosting only; claims vanish on restart."""
    def __init__(self):
        self._claims: dict[str, float] = {}

    async def claim(self, key: str, expires_at: datetime) -> bool:
        # No await between check and insert: one event loop is the atomic owner.
        now = time.time()
        self._claims = {k: expiry for k, expiry in self._claims.items() if expiry > now}
        if key in self._claims:
            return False
        self._claims[key] = expires_at.timestamp()
        return True


def request_replay_key(did_key: str, signature_b64: str) -> str:
    # Match the verifier's accepted standard/url-safe encodings, then discard the
    # textual representation. A NUL delimiter is unambiguous for a valid did:key.
    signature = base64.urlsafe_b64decode(signature_b64 + '=' * (-len(signature_b64) % 4))
    return hashlib.sha256(did_key.encode('ascii') + b'\0' + signature).hexdigest()


async def admit_verified_request(request: Request, *, envelope: TeamAuthEnvelope,
                                 did_key: str, signature_b64: str, family: str,
                                 store: RequestReplayStore | None = None) -> None:
    """Call only after signature AND current identity/certificate checks succeed.

    Bridge and mounted dependencies must share request.scope['state'] and the
    same replay store. Separate HTTP requests never share this memoization.
    """
    if envelope.version != 2:
        return
    key = request_replay_key(did_key, signature_b64)
    admitted = getattr(request.state, 'request_auth_replay_admitted', None)
    if admitted is not None and key in admitted:
        return
    nonce = envelope.payload.get('nonce')
    if nonce is None:
        count_nonce_free_request_auth(request, family)
    if store is None:
        store = getattr(request.app.state, 'request_auth_replay_store', None)
    if store is None:
        redis = getattr(request.app.state, 'redis', None)
        if redis is not None:
            store = RedisRequestReplayStore(redis)
    try:
        if store is None:
            raise RuntimeError('request replay store is not configured')
        timestamp = datetime.fromisoformat(envelope.payload['timestamp'].replace('Z', '+00:00'))
        first = await store.claim(key, timestamp.astimezone(timezone.utc) + timedelta(seconds=300))
    except Exception as exc:
        if nonce is not None:
            logger.warning('request-auth replay store unavailable', exc_info=True)
            raise HTTPException(status_code=503, detail={'code': 'request_auth_replay_unavailable'}) from exc
        # Compatibility traffic keeps its existing availability. No local store.
        first = True
    if not first:
        count_request_auth_replay(request, family, 'nonce' if nonce is not None else 'nonce_free')
        if nonce is not None:
            raise HTTPException(status_code=401, detail={'code': 'request_replayed'})
    if admitted is None:
        admitted = set()
        request.state.request_auth_replay_admitted = admitted
    admitted.add(key)
