"""The app's installation authority, read from its team's verified server.

The caller supplies the runtime's shared TeamServerDirectory. No URL comes
from a request: the controller-signed AWID record anchors the server, and the
app signs its own grant read with its registered app-grant-read key. Grant
and installation-status readers share one bounded cache; an expired answer
never grants use, including when its refresh fails.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from dataclasses import dataclass, replace
from datetime import datetime

from aweb_naapp.runtime.app_credentials import APP_GRANT_READ, AppCredentialSigner
from aweb_naapp.runtime.authorization import Grant, GrantUnavailable
from aweb_naapp.runtime.clock import MonotonicClock
from aweb_naapp.runtime.freshness import FreshnessCache, RefreshTimedOut
from aweb_naapp.runtime.team_server import (
    TeamServerDirectory,
    TeamServerReach,
    TeamServerUnavailable,
    TeamServerUnreachable,
)

MAX_ANSWER_BYTES = 1 << 20
MISSING_KEY_MAX_AGE_SECONDS = 5
_AS_OF = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:Z|\+00:00)"
)


@dataclass(frozen=True, kw_only=True)
class AppIdentity:
    """Identity of the exact manifest bytes this app serves."""

    app_id: str
    origin: str
    digest: str
    manifest_digests: tuple[tuple[int, str], ...] = ()


@dataclass(frozen=True, kw_only=True)
class GrantStatus:
    """A fresh installation observation; only active observations grant use.

    An unknown state is preserved and disables use. A missing/revoked caller
    key returns None instead; it is never treated as proof of uninstall.
    """

    team_id: str
    app_id: str
    origin: str
    digest: str
    state: str
    app_version: str
    manifest_version: int
    granted_scopes: frozenset[str]
    installation_id: str | None
    generation: int | None
    origin_verified: bool | None
    installed_at: datetime
    as_of: datetime
    max_age_seconds: int
    fresh_until: int


class TeamGrantSource:
    def __init__(
        self,
        *,
        identity: AppIdentity,
        signer: AppCredentialSigner,
        discovery: TeamServerDirectory,
        reach: TeamServerReach,
        timeout: float = 5.0,
        monotonic: MonotonicClock = time.monotonic_ns,
    ) -> None:
        if signer.purpose != APP_GRANT_READ:
            raise ValueError("grant reads require an app-grant-read signer")
        if signer.app_id != identity.app_id:
            raise ValueError("the signer must name the app's own identity")
        self._identity = identity
        self._signer = signer
        self._directory = discovery
        self._timeout = timeout
        self._reach = reach
        self._monotonic = monotonic
        self._cache: FreshnessCache[tuple[str, ...], GrantStatus | None] = FreshnessCache(
            refresh_timeout=timeout,
            monotonic=monotonic,
        )

    async def grant_for(self, team_id: str, certificate_id: str | None = None) -> Grant | None:
        status = await self.status_for(team_id, certificate_id)
        if status is None or status.state != "active":
            return None
        return Grant(
            team_id=status.team_id,
            scopes=status.granted_scopes,
            fresh_until=status.fresh_until,
            installation_id=status.installation_id,
            generation=status.generation,
        )

    async def status_for(self, team_id: str, certificate_id: str | None = None) -> GrantStatus | None:
        """Fresh status or no registered key; unavailable authority raises GrantUnavailable.

        The total caller deadline includes discovery. Cancellation never
        cancels a shared grant refresh that another caller is waiting on.
        Member calls pass their verified certificate ID for AWID discovery.
        """
        try:
            return await asyncio.wait_for(self._status_for(team_id, certificate_id), self._timeout)
        except TeamServerUnavailable as exc:
            raise GrantUnavailable(exc.code) from exc
        except (TimeoutError, RefreshTimedOut) as exc:
            raise GrantUnavailable("grant_refresh_timeout") from exc
        except TeamServerUnreachable as exc:
            raise GrantUnavailable("grant_server_unreachable") from exc
        except (KeyError, TypeError, ValueError, RecursionError) as exc:
            raise GrantUnavailable("grant_answer_malformed") from exc

    async def _status_for(self, team_id: str, certificate_id: str | None = None) -> GrantStatus | None:
        server = await self._directory.resolve(team_id, certificate_id)
        # A move or controller-key change cannot reuse the old server's answer.
        key = (team_id, server.server_url, server.audience, server.team_did_key)

        async def fetch() -> tuple[GrantStatus | None, int]:
            answer = await self._reach.get(
                server,
                "/v1/apps/self/grant",
                sign=lambda target: self._signer.sign(
                    method="GET", target=target, team_id=team_id
                ).headers,
                max_bytes=MAX_ANSWER_BYTES,
                timeout=self._timeout,
            )
            if answer.truncated:
                raise GrantUnavailable("grant_answer_too_large")
            content = answer.body
            if answer.status != 200:
                if answer.status == 403:
                    try:
                        denial = json.loads(content)
                    except ValueError:
                        denial = None
                    if isinstance(denial, dict):
                        detail = denial.get("detail")
                        code = detail.get("code") if isinstance(detail, dict) else detail
                        if code == "app_key_not_registered":
                            # A denial grants no use and carries no installation identity.
                            # Let a new install become usable promptly on retry.
                            return None, MISSING_KEY_MAX_AGE_SECONDS
                raise GrantUnavailable(f"grant_server_status_{answer.status}")
            body = json.loads(content)
            status = self._parse(body, team_id)
            return status, status.max_age_seconds

        fresh = await self._cache.get(key, fetch)
        if fresh.fresh_until <= self._monotonic():
            raise GrantUnavailable("grant_answer_expired")
        return None if fresh.value is None else replace(fresh.value, fresh_until=fresh.fresh_until)

    def _parse(self, body: object, team_id: str) -> GrantStatus:
        if not isinstance(body, dict):
            raise ValueError("grant answer must be an object")
        identity = self._identity
        expected_digest: str | None = identity.digest
        if identity.manifest_digests:
            version = body.get("manifest_version")
            if type(version) is not int:
                raise ValueError("invalid grant manifest_version")
            expected_digest = dict(identity.manifest_digests).get(version)
        if (
            body["team_id"] != team_id
            or body["app_id"] != identity.app_id
            or body["origin"] != identity.origin
            or expected_digest is None or body["digest"] != expected_digest
        ):
            raise ValueError("grant answer names another team or app identity")
        for field in ("state", "app_version", "as_of"):
            if not isinstance(body[field], str) or not body[field]:
                raise ValueError(f"invalid grant {field}")
        if not _AS_OF.fullmatch(body["as_of"]):
            raise ValueError("invalid grant as_of")
        as_of = datetime.fromisoformat(body["as_of"])
        if not isinstance(body["installed_at"], str) or not _AS_OF.fullmatch(body["installed_at"]):
            raise ValueError("invalid grant installed_at")
        installed_at = datetime.fromisoformat(body["installed_at"])
        scopes = body["granted_scopes"]
        if not isinstance(scopes, list) or not all(isinstance(s, str) and s for s in scopes):
            raise ValueError("invalid granted_scopes")
        installation_id = body["installation_id"]
        if installation_id is not None and (not isinstance(installation_id, str) or not installation_id):
            raise ValueError("invalid installation_id")
        generation = body["generation"]
        if generation is not None and (
            type(generation) is not int or not 1 <= generation <= 9223372036854775807
        ):
            raise ValueError("invalid generation")
        origin_verified = body["origin_verified"]
        if origin_verified is not None and type(origin_verified) is not bool:
            raise ValueError("invalid origin_verified")
        for field in ("max_age_seconds", "manifest_version"):
            if type(body[field]) is not int or body[field] < 1:
                raise ValueError(f"invalid grant {field}")
        return GrantStatus(
            team_id=team_id,
            app_id=identity.app_id,
            origin=identity.origin,
            digest=body["digest"],
            state=body["state"],
            app_version=body["app_version"],
            manifest_version=body["manifest_version"],
            granted_scopes=frozenset(scopes),
            installation_id=installation_id,
            generation=generation,
            origin_verified=origin_verified,
            installed_at=installed_at,
            as_of=as_of,
            max_age_seconds=body["max_age_seconds"],
            fresh_until=0,
        )
