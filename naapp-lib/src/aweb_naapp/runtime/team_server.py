"""Discovery of a team's coordination server from its AWID record.

A team's aweb.team-server/1 record, signed by the team's current key and served
by AWID, names the server an app calls for that team. The team id is only a
lookup key: trust comes from the registry the app's verifier already trusts for
team keys, the team's current key there, and the record's signature under it.
No server, registry or URL is ever taken from a request or an event.

An answer is reused for at most 60 seconds. When it expires and cannot be
refreshed, the result is unavailable; an expired answer is never reused.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import quote

import httpx
from awid.dns_verify import discover_registry_override
from awid.log import canonical_server_origin
from awid.team_ids import parse_team_id
from awid.team_server_record import TeamServerRecordError, verify_team_server_record
from fastapi import HTTPException

from aweb_naapp.egress import (
    Bounds,
    Destination,
    Egress,
    EgressNotSent,
    EgressOutcomeUnknown,
    EgressRefused,
    HeaderRules,
    canonical_url,
)
from aweb_naapp.egress.internal import InternalReach, send_reaching_internal
from aweb_naapp.egress.send import CONNECT_TIMEOUT_SECONDS, TOTAL_TIMEOUT_SECONDS, Response
from aweb_naapp.egress.urls import parse_destination
from aweb_naapp.runtime.app_credentials import AppCredentialSigner
from aweb_naapp.runtime.clock import MonotonicClock, seconds_to_ns
from aweb_naapp.runtime.team_auth import AWIDTeamCache

logger = logging.getLogger(__name__)

MAX_TEAM_SERVER_TTL_SECONDS = 60
TEAM_SERVER_TIMEOUT_SECONDS = 5.0

RegistryOverride = Callable[[str], Awaitable[str | None]]


class TeamServerUnavailable(Exception):
    """The team's server cannot be established; ``code`` says why.

    ``team_server_unpublished``: the team has no record.
    ``team_unknown``: AWID does not know the team, or refuses its certificate status.
    ``team_server_key_mismatch``: the record is not signed by the team's current key.
    ``team_server_record_invalid``: the record is malformed or otherwise refused.
    ``registry_mismatch``: the domain names a registry other than the verifier's.
    ``authority_unavailable``: AWID or DNS could not answer.
    """

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class TeamServer:
    team_id: str
    server_url: str
    audience: str
    team_did_key: str
    expires_at: int


class TeamServerDirectory:
    """Resolves a team id to its verified coordination server."""

    def __init__(
        self,
        *,
        team_cache: AWIDTeamCache,
        transport: httpx.AsyncBaseTransport | None = None,
        registry_override: RegistryOverride = discover_registry_override,
        ttl_seconds: int = MAX_TEAM_SERVER_TTL_SECONDS,
        clock: MonotonicClock = time.monotonic_ns,
    ) -> None:
        self._team_cache = team_cache
        self._transport = transport
        self._registry_override = registry_override
        self._ttl = min(ttl_seconds, MAX_TEAM_SERVER_TTL_SECONDS)
        self._clock = clock
        self._cache: dict[tuple[str, str], TeamServer] = {}

    def _client(self) -> httpx.AsyncClient:
        if self._transport is None:
            return httpx.AsyncClient(timeout=TEAM_SERVER_TIMEOUT_SECONDS, follow_redirects=False)
        return httpx.AsyncClient(
            timeout=TEAM_SERVER_TIMEOUT_SECONDS, follow_redirects=False, transport=self._transport
        )

    async def resolve(self, team_id: str, certificate_id: str | None = None) -> TeamServer:
        """The team's server. ``certificate_id`` is the verified member's
        certificate; it is needed only when the app has no AWID service token."""
        key = (self._team_cache.registry_origin, team_id)
        cached = self._cache.get(key)
        now = self._clock()
        if cached is not None and cached.expires_at > now:
            return cached
        self._cache.pop(key, None)

        domain, name = parse_team_id(team_id)
        await self._require_verifier_registry(domain)
        team_did_key = await self._current_team_key(team_id, certificate_id)
        record, signature = await self._stored_record(domain, name)
        try:
            verified = verify_team_server_record(
                record,
                signature,
                team_id=team_id,
                current_team_did_key=team_did_key,
                now=datetime.now(UTC),
            )
        except TeamServerRecordError as exc:
            logger.warning("Team server record for %s refused: %s", team_id, exc.code)
            if exc.code == "team_server_key_mismatch":
                raise TeamServerUnavailable("team_server_key_mismatch") from exc
            raise TeamServerUnavailable("team_server_record_invalid") from exc
        server = TeamServer(
            team_id=team_id,
            server_url=verified.server_url,
            audience=verified.audience,
            team_did_key=team_did_key,
            expires_at=now + seconds_to_ns(self._ttl),
        )
        self._cache[key] = server
        return server

    async def _require_verifier_registry(self, domain: str) -> None:
        try:
            override = await self._registry_override(domain)
        except Exception as exc:
            logger.warning("AWID registry discovery for %s failed: %s", domain, exc)
            raise TeamServerUnavailable("authority_unavailable") from exc
        if override is None:
            return
        try:
            override_origin = canonical_server_origin(override)
        except ValueError as exc:
            logger.warning("AWID registry statement for %s is malformed", domain)
            raise TeamServerUnavailable("authority_unavailable") from exc
        if override_origin != self._team_cache.registry_origin:
            raise TeamServerUnavailable("registry_mismatch")

    async def _current_team_key(self, team_id: str, certificate_id: str | None) -> str:
        try:
            facts = await self._team_cache.get(team_id, certificate_id)
        except HTTPException as exc:
            if exc.status_code == 401:
                raise TeamServerUnavailable("team_unknown") from exc
            raise TeamServerUnavailable("authority_unavailable") from exc
        return facts.team_did_key

    async def _stored_record(self, domain: str, name: str) -> tuple[object, object]:
        url = (
            f"{self._team_cache.registry_url}/v1/namespaces/{quote(domain, safe='')}"
            f"/teams/{quote(name, safe='')}/server"
        )
        try:
            async with self._client() as client:
                response = await client.get(url)
        except httpx.HTTPError as exc:
            logger.warning("AWID team server read failed: %s", exc)
            raise TeamServerUnavailable("authority_unavailable") from exc
        if response.status_code == 404:
            raise TeamServerUnavailable("team_server_unpublished")
        if response.status_code != 200:
            logger.warning("AWID team server read answered %s", response.status_code)
            raise TeamServerUnavailable("authority_unavailable")
        try:
            body = response.json()
        except ValueError as exc:
            raise TeamServerUnavailable("team_server_record_invalid") from exc
        if not isinstance(body, dict):
            raise TeamServerUnavailable("team_server_record_invalid")
        return body.get("record"), body.get("signature")


class TeamServerRefused(Exception):
    """The team's published server is not a destination this app may reach.

    Nothing was sent. ``server_url`` is the address the team published and
    ``reason`` the egress rule that refused it.
    """

    def __init__(self, *, server_url: str, reason: str) -> None:
        super().__init__(f"{server_url}: {reason}")
        self.server_url = server_url
        self.reason = reason


class TeamServerUnreachable(Exception):
    """The team's server could not be reached, or did not answer in time."""


@dataclass(frozen=True)
class TeamServerAnswer:
    """A team server's answer, cut at the caller's bound (``truncated``)."""

    status: int
    body: bytes
    truncated: bool


class TeamServerReach:
    """How the app sends its reads to a team's coordination server
    (docs/design/app-team-server-api.md §1, trust chain step 4, "Use").

    The server's address comes from the team's own signed record, so the team
    chooses it. Every read goes through the deployment's egress guard: https
    only, every address the name resolves to checked, the connection pinned
    to a checked address, redirects returned rather than followed, no proxy
    from the environment. A server whose exact origin the operator lists as
    its own (``internal``) is reached inside the operator's network by the
    one rule hook deliveries follow (:mod:`aweb_naapp.egress.internal`).
    """

    def __init__(self, *, egress: Egress, internal: InternalReach | None) -> None:
        self._egress = egress
        self._internal = internal

    async def get(
        self,
        server: TeamServer,
        path: str,
        *,
        signer: AppCredentialSigner | None,
        max_bytes: int,
        timeout: float,
    ) -> TeamServerAnswer:
        """GET ``path`` under the server's URL, signed by ``signer`` for the
        server's team over the exact URL sent; ``None`` sends a public read.
        ``timeout`` bounds the read, both attempts together."""
        read = _Read(server=server, signer=signer, max_bytes=max_bytes, timeout=timeout)
        url = f"{server.server_url}{path}"
        deadline = asyncio.get_running_loop().time() + timeout
        try:
            canonical = canonical_url(url)
            headers = list(read.headers(str(canonical)).items())
            entry = {
                "host": canonical.host,
                "port": canonical.port,
                "path": canonical.path,
                "methods": ["GET"],
            }
            public = parse_destination(
                entry, internal_destinations=self._egress.addresses.internal_destinations
            )

            async def send(destination: Destination) -> Response:
                remaining = max(deadline - asyncio.get_running_loop().time(), 0.001)
                return await self._egress.send(
                    "GET",
                    canonical,
                    destination,
                    # Every header is the app credential, injected; the read
                    # sends no caller headers for the credential detector to judge.
                    header_rules=HeaderRules(
                        injected=[name for name, _ in headers],
                        amz_allowed=(),
                        is_credential=lambda value: False,
                    ),
                    injected=headers,
                    bounds=Bounds(
                        connect_timeout=min(remaining, CONNECT_TIMEOUT_SECONDS),
                        total_timeout=min(remaining, TOTAL_TIMEOUT_SECONDS),
                        max_response_bytes=read.max_bytes,
                    ),
                )

            response = await send_reaching_internal(
                self._egress, entry, public, url=url, reach=self._internal, send=send
            )
        except EgressRefused as refused:
            logger.warning(
                "Team server %s for %s refused by egress: %s",
                server.server_url,
                server.team_id,
                refused,
            )
            raise TeamServerRefused(server_url=server.server_url, reason=str(refused)) from refused
        except (EgressNotSent, EgressOutcomeUnknown) as exc:
            raise TeamServerUnreachable(str(exc)) from exc
        return TeamServerAnswer(response.status, response.body, response.truncated)


@dataclass(frozen=True, kw_only=True)
class _Read:
    """One read of a team server: who signs it and how long and large it may be."""

    server: TeamServer
    signer: AppCredentialSigner | None
    max_bytes: int
    timeout: float

    def headers(self, target: str) -> dict[str, str]:
        """The app credential over exactly ``target``, or none for a public read."""
        if self.signer is None:
            return {}
        return self.signer.sign(method="GET", target=target, team_id=self.server.team_id).headers
