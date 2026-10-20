"""The cache of OAuth2 access tokens the broker obtained (secrets §7.5).

A cached token is a live bearer credential, so the cache's contract is:

- **Where.** In this process's memory (:class:`ProcessTokenCache`), or sealed
  at rest through custody with the key's digest in the bound context. Never
  plaintext in a database, a shared cache or a log.
- **Which token.** secrets derives the key (:class:`TokenKey`) from
  everything that decides which token is valid: the installation, the team,
  the secret and its version, the token endpoint and the scope. A rotated
  secret, a changed endpoint or a changed scope therefore never reuses an old
  token. The key is never taken from a caller as free text.
- **For how long.** A token is never served after the ``expires_at`` it was
  stored with, which the broker sets 60 s before the upstream's expiry.
- **Revocation.** Disabling or destroying a secret evicts every token of that
  secret (:meth:`TokenCache.evict_secret`), in every version.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Protocol

_DIGEST_PREFIX = b"aweb.secrets.token-key/1\n"


@dataclass(frozen=True)
class TokenKey:
    """Which access token one call may use."""

    installation_id: str
    team_id: str
    secret_id: str
    version: int
    token_endpoint: str
    scope: str

    def digest(self) -> str:
        """A stable digest over every field, for storage and sealing context."""
        canonical = json.dumps(asdict(self), sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(_DIGEST_PREFIX + canonical).hexdigest()


class TokenCache(Protocol):
    async def get(self, key: TokenKey) -> str | None:
        """The token stored under ``key``, unless it has expired."""
        ...

    async def put(self, key: TokenKey, token: str, expires_at: datetime) -> None: ...

    async def evict_secret(self, *, installation_id: str, team_id: str, secret_id: str) -> int:
        """Drop every token of one secret, in every version; return how many."""
        ...


@dataclass
class ProcessTokenCache:
    """Tokens in this process's memory only; lost when the process ends."""

    now: Callable[[], datetime] = lambda: datetime.now(UTC)
    _tokens: dict[str, tuple[TokenKey, str, datetime]] = field(default_factory=dict, repr=False)

    async def get(self, key: TokenKey) -> str | None:
        digest = key.digest()
        entry = self._tokens.get(digest)
        if entry is None:
            return None
        if entry[2] <= self.now():
            del self._tokens[digest]
            return None
        return entry[1]

    async def put(self, key: TokenKey, token: str, expires_at: datetime) -> None:
        self._tokens[key.digest()] = (key, token, expires_at)

    async def evict_secret(self, *, installation_id: str, team_id: str, secret_id: str) -> int:
        evicted = [
            digest
            for digest, (key, _, _) in self._tokens.items()
            if (key.installation_id, key.team_id, key.secret_id) == (installation_id, team_id, secret_id)
        ]
        for digest in evicted:
            del self._tokens[digest]
        return len(evicted)
