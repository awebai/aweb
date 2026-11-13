"""Team-auth v2 request authentication for naapps.

Verifies that a member holding a valid team certificate signed one concrete
HTTP request (docs/team-auth-envelope-v2.md): the DIDKey header, the timestamp
window, the canonical v2 payload bound to audience, method, raw path and query,
team and body, the member's signature, and the certificate against AWID's
current team key and revocation state. A certificate's ``member_did_aw`` is
checked under the relying app's :class:`DidAwProfile`.

A did:aw resolution, current key or unregistered, is reused for at most 60
seconds, so a key just rotated in, or a DID just registered, can be refused for
up to that long. A mismatch is never re-resolved early, so a stolen old key
cannot drive registry calls. Authentication proves who
signed the request, not that the signer may perform it; see
:mod:`aweb_naapp.runtime.authorization`.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import re
import time
from collections.abc import Callable, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, replace
from dataclasses import field as dataclass_field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from urllib.parse import quote, urlsplit

import httpx
from awid.did import did_key_from_signing_key, public_key_from_did, validate_stable_id
from awid.log import canonical_server_origin
from awid.protected_effect import EffectRefused
from awid.protected_membership import (
    TeamProtectionObservation,
    check_retained_subject_record,
    observe_team_protection,
    resolve_registered_membership,
    verify_registered_membership,
)
from awid.registry import RegistryClient
from awid.registry_auth import RegistryRequestAuth
from awid.signing import (
    canonical_json_bytes,
    verify_did_key_signature,
)
from awid.team_certificate import (
    TeamCertificateError,
    check_team_certificate,
    decode_team_certificate,
    refusal_answer,
)
from awid.team_ids import parse_team_id
from fastapi import HTTPException, Request
from pgdbm import AsyncDatabaseManager

from aweb_naapp.runtime.clock import seconds_to_ns

logger = logging.getLogger(__name__)

# At most 20,000 certificate records per refresh; incomplete history is never cached.
MAX_CERTIFICATE_PAGES = 100
CERTIFICATE_PAGE_SIZE = 200

TEAM_AUTH_ENVELOPE_V2 = 2
# The envelope contract allows at most five minutes; a larger configured window is clamped.
MAX_TIMESTAMP_SKEW_SECONDS = 300
# AWID team facts are reused for at most a minute; a longer configured TTL is clamped.
MAX_TEAM_FACTS_TTL_SECONDS = 60
# Unknown certificates may force one full-history refresh per team in this window.
UNKNOWN_CERTIFICATE_REFRESH_SECONDS = 5
_B64URL_NO_PADDING = re.compile(r"^[A-Za-z0-9_-]+$")


class DidAwProfile(StrEnum):
    """How a relying app treats the ``member_did_aw`` a certificate carries.

    The team controller's signature makes that binding team-asserted. Under
    either profile the DID's current key is resolved at the configured registry
    and compared with the signer. ``REQUIRE`` refuses a request whose DID is
    unregistered or has another current key, and refuses with 503 when the
    registry cannot answer. ``OBSERVE`` logs the outcome and admits the request
    anyway, so an app can measure what its released callers send before it
    requires the check. Members without a ``member_did_aw`` are never looked up.
    """

    OBSERVE = "observe"
    REQUIRE = "require"


@dataclass(frozen=True)
class Principal:
    team_id: str
    did_key: str
    did_aw: str | None
    address: str | None
    alias: str
    certificate_id: str
    team_did_key: str
    # True only when the registry named did_aw's current key as this signer.
    # Policies relying on the did:aw check this flag, not did_aw's presence.
    did_aw_registry_verified: bool = False


@dataclass(frozen=True)
class MembershipProof:
    """Checked mint evidence and its original AWID facts' freshness window.

    Both times use time.monotonic_ns(): checked_at is the facts' fetch-start,
    fresh_until their expiry, never renewed by issuing a proof on a cache hit.
    This object is in-process only: never serialize, persist, accept it from a
    request or compare it across processes. Under the link lock, the consumer
    must match all three identity fields to immutable mint evidence and read
    its monotonic clock again to reject an expired proof.
    """

    team_id: str
    certificate_id: str
    team_did_key: str
    checked_at: int
    fresh_until: int
    protection_observation: TeamProtectionObservation | None = None
    principal: str | None = None
    member_alias: str | None = None

    def is_fresh_at(self, now: int) -> bool:
        """Check the original bounded window without extending its deadline."""
        if self.protection_observation is not None:
            try:
                self.protection_observation.require_fresh()
            except EffectRefused:
                return False
        return (
            all(type(value) is int for value in (self.checked_at, self.fresh_until, now))
            and 0 <= self.fresh_until - self.checked_at <= seconds_to_ns(MAX_TEAM_FACTS_TTL_SECONDS)
            and self.checked_at <= now <= self.fresh_until
        )


@dataclass(frozen=True)
class CachedTeamFacts:
    team_did_key: str
    published_certificate_ids: frozenset[str]
    revoked_certificate_ids: frozenset[str]
    fetched_at: int
    expires_at: int
    protection_observation: TeamProtectionObservation | None = None


@dataclass(frozen=True)
class CachedDidKey:
    # None when the registry answered that it has no such DID.
    current_did_key: str | None
    expires_at: int


def _require_active_certificate(facts: CachedTeamFacts, certificate_id: str) -> None:
    if certificate_id not in facts.published_certificate_ids:
        raise HTTPException(status_code=401, detail="Unknown AWID certificate")
    if certificate_id in facts.revoked_certificate_ids:
        raise HTTPException(status_code=401, detail="Team certificate has been revoked")


def _current_member_refusal(status_code: int) -> HTTPException:
    code = "current_member_required" if status_code == 403 else "current_membership_unavailable"
    return HTTPException(status_code=status_code, detail={"code": code})


def _raise_if_private_team_unreadable(response: httpx.Response, team_id: str) -> None:
    if response.status_code != 403:
        return
    try:
        payload = response.json()
    except ValueError:
        return
    detail = payload.get("detail") if isinstance(payload, dict) else None
    if isinstance(detail, dict) and detail.get("code") == "team_private":
        raise HTTPException(
            status_code=403,
            detail={
                "code": "team_private_unreadable",
                "message": (
                    f"App cannot read private AWID team {team_id}; configure "
                    f"awid_member_credentials[{team_id}] with a current member "
                    "certificate of that team, or the AWID service token"
                ),
            },
        )


@dataclass(frozen=True)
class AWIDMemberCredential:
    """An ordinary member certificate the app holds for one team, and its
    signing key: the app path-signs that team's gated AWID reads with it, as
    the CLI does. The certificate must be the key's own."""

    signing_key: bytes = dataclass_field(repr=False)
    certificate: Mapping[str, Any]

    def __post_init__(self) -> None:
        did_key = did_key_from_signing_key(self.signing_key)
        if self.certificate.get("member_did_key") != did_key:
            raise ValueError("an AWID member credential's certificate is not its signing key's")

    @property
    def team_id(self) -> str:
        return str(self.certificate.get("team_id") or "")

    @property
    def certificate_id(self) -> str:
        return str(self.certificate.get("certificate_id") or "")


class AWIDTeamCache:
    """Small in-memory cache of AWID team authentication facts."""

    def __init__(
        self,
        *,
        registry_url: str,
        ttl_seconds: int,
        service_token: str | None = None,
        member_credentials: Mapping[str, AWIDMemberCredential] | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        """Gated reads of a private team use the service token when there is
        one (a hosted deployment), else that team's member credential; any
        other read is a plain one."""
        self.registry_url = registry_url.rstrip("/")
        self.registry_origin = canonical_server_origin(self.registry_url)
        if ttl_seconds > MAX_TEAM_FACTS_TTL_SECONDS:
            raise ValueError(
                f"ttl_seconds is {ttl_seconds}: AWID team facts are cached for at most "
                f"{MAX_TEAM_FACTS_TTL_SECONDS} seconds"
            )
        self.ttl_seconds = ttl_seconds
        self._member_credentials = dict(member_credentials or {})
        for team_id, credential in self._member_credentials.items():
            if credential.team_id != team_id:
                raise ValueError(f"the AWID member credential for {team_id} certifies another team")
        self._request_auth = RegistryRequestAuth(
            service_token=service_token,
            member_signing_keys={
                team_id: credential.signing_key
                for team_id, credential in self._member_credentials.items()
            },
        )
        self._cache: dict[str, CachedTeamFacts] = {}
        self._team_refresh_locks: dict[str, asyncio.Lock] = {}
        self._unknown_refresh_at: dict[str, int] = {}
        self._team_refresh_errors: dict[str, tuple[int, Any]] = {}
        self._certificate_cache: dict[tuple[str, str], CachedTeamFacts] = {}
        self._did_keys: dict[tuple[str, str], CachedDidKey] = {}
        self._transport = transport

    def _read_headers(self, url: str) -> dict[str, str]:
        """The authentication of one AWID read."""
        return self._request_auth.headers("GET", urlsplit(url).path)

    def _reads_team_history(self, team_id: str) -> bool:
        return bool(self._request_auth.service_token) or team_id in self._member_credentials

    def _client(self) -> httpx.AsyncClient:
        if self._transport is None:
            return httpx.AsyncClient(timeout=10.0)
        return httpx.AsyncClient(timeout=10.0, transport=self._transport)

    @asynccontextmanager
    async def registry_reader(self):
        """An authenticated reader of the selected registry, with no stale fallback."""
        registry = RegistryClient(
            registry_url=self.registry_url, transport=self._transport,
            service_token=self._request_auth.service_token,
            member_signing_keys={k: v.signing_key for k, v in self._member_credentials.items()},
        )
        try:
            yield registry
        finally:
            await registry.aclose()

    async def verify_membership_certificate(self, certificate, facts):
        try:
            async with self.registry_reader() as registry:
                await verify_registered_membership(registry, facts.protection_observation, certificate)
        except TeamCertificateError as exc:
            raise _certificate_refusal(exc) from exc
        except EffectRefused as exc:
            raise HTTPException(status_code=503, detail={"code": exc.code}) from exc

    async def require_current_member(
        self, team_id: str, *, certificate_id: str, team_did_key: str,
        certificate: Mapping[str, Any] | None = None,
        principal: str | None = None,
        member_alias: str | None = None,
    ) -> None:
        """Check membership without retaining a proof. May perform network I/O;
        call before opening any transaction. See :meth:`check_current_member`."""
        await self.check_current_member(
            team_id, certificate_id=certificate_id, team_did_key=team_did_key, certificate=certificate, principal=principal, member_alias=member_alias
        )

    async def check_current_member(
        self, team_id: str, *, certificate_id: str, team_did_key: str,
        certificate: Mapping[str, Any] | None = None,
        principal: str | None = None,
        member_alias: str | None = None,
    ) -> MembershipProof:
        """Check mint-time Principal evidence before any transaction or lock.

        The caller supplies its verified team scope and the recorded certificate
        id and signing team key, never an observed-principal row. AWID must still
        publish that certificate as active under the same current team key.
        Facts share request authentication's cache, bounded to 60 seconds.
        Protected callers also supply their original complete certificate or
        literal principal. Subject-only historical references require the
        operator's inventoried baseline; an optional original member_alias is
        compared too, never inferred from the registry. Missing original
        evidence is unavailable. did:aw subjects retain a current key check.

        Incomplete evidence or authority loss raises 403/current_member_required;
        unreadable or unavailable registry facts raise 503/current_membership_unavailable.
        This checks membership only, not the creator's page or installation ACLs.
        The returned proof retains the facts' original monotonic freshness
        window; facts already past their expiry cannot issue a fresh proof.
        """
        if (
            not isinstance(certificate_id, str) or not certificate_id.strip()
            or not isinstance(team_did_key, str) or not team_did_key.strip()
        ):
            raise _current_member_refusal(403)
        try:
            parse_team_id(team_id)
            public_key_from_did(team_did_key)
        except ValueError as exc:
            raise _current_member_refusal(403) from exc
        try:
            facts = await self.get(team_id, certificate_id)
            public_key_from_did(facts.team_did_key)
            _require_active_certificate(facts, certificate_id)
        except HTTPException as exc:
            # A private registry that we cannot read is unavailable evidence,
            # not proof that the recorded member lost their authority.
            raise _current_member_refusal(403 if exc.status_code == 401 else 503) from exc
        except ValueError as exc:
            raise _current_member_refusal(503) from exc
        if facts.protection_observation is None:
            raise HTTPException(status_code=503, detail={"code": "protected_state_unavailable"})
        if facts.protection_observation.protected:
            if certificate is not None:
                if certificate.get("certificate_id") != certificate_id:
                    raise _certificate_refusal(TeamCertificateError("certificate_binding_mismatch"))
                await self.verify_membership_certificate(dict(certificate), facts)
                if ((principal is not None and principal not in {
                    certificate.get("member_did_key"), certificate.get("member_did_aw"),
                }) or (member_alias is not None and member_alias != certificate.get("alias"))):
                    raise _certificate_refusal(TeamCertificateError("certificate_binding_mismatch"))
            elif principal is not None:
                try:
                    async with self.registry_reader() as registry:
                        record = await resolve_registered_membership(registry, facts.protection_observation, certificate_id)
                        check_retained_subject_record(
                            facts.protection_observation, record, certificate_id=certificate_id,
                            controller_did_key=team_did_key, principal=principal,
                        )
                        if member_alias is not None and member_alias != record.alias:
                            raise TeamCertificateError("certificate_binding_mismatch")
                        if principal.startswith("did:aw:"):
                            if await self.current_did_key(principal) != record.member_did_key:
                                raise TeamCertificateError("certificate_binding_mismatch")
                    facts.protection_observation.require_fresh()
                except TeamCertificateError as exc:
                    raise _certificate_refusal(exc) from exc
                except EffectRefused as exc:
                    raise HTTPException(status_code=503, detail={"code": exc.code}) from exc
            else:
                raise HTTPException(status_code=503, detail={"code": "protected_state_unavailable"})
        if team_did_key != facts.team_did_key:
            raise _current_member_refusal(403)
        if time.monotonic_ns() > facts.expires_at:
            raise _current_member_refusal(503)
        return MembershipProof(
            team_id=team_id,
            certificate_id=certificate_id,
            team_did_key=team_did_key,
            checked_at=facts.fetched_at,
            fresh_until=facts.expires_at,
            protection_observation=facts.protection_observation,
            principal=principal,
            member_alias=member_alias,
        )

    async def get(self, team_id: str, certificate_id: str | None = None) -> CachedTeamFacts:
        facts = await self._get_cached(team_id, certificate_id)
        observation = facts.protection_observation
        if observation is not None and not observation.protected:
            try:
                observation.require_fresh()
                return facts
            except EffectRefused:
                pass
        try:
            async with self.registry_reader() as registry:
                observation = await observe_team_protection(registry, team_id, certificate_id=certificate_id)
                observation.require_fresh()
            if observation.controller_did_key != facts.team_did_key:
                raise EffectRefused("protected_state_unavailable")
        except TeamCertificateError as exc:
            raise _certificate_refusal(exc) from exc
        except Exception as exc:
            logger.warning("Current protected membership state unavailable", exc_info=True)
            raise HTTPException(status_code=503, detail={"code": "protected_state_unavailable"}) from exc
        facts = replace(facts, protection_observation=observation)
        if self._reads_team_history(team_id) or certificate_id is None:
            self._cache[team_id] = facts
        else:
            self._certificate_cache[(team_id, certificate_id)] = facts
        return facts

    async def _get_cached(self, team_id: str, certificate_id: str | None = None) -> CachedTeamFacts:
        if certificate_id and not self._reads_team_history(team_id):
            return await self._get_certificate_status(team_id, certificate_id)
        now = time.monotonic_ns()
        cached = self._cache.get(team_id)
        if cached and cached.expires_at > now and (
            certificate_id is None or certificate_id in cached.published_certificate_ids
        ):
            return cached

        lock = self._team_refresh_locks.setdefault(team_id, asyncio.Lock())
        async with lock:
            now = time.monotonic_ns()
            cached = self._cache.get(team_id)
            fresh = cached is not None and cached.expires_at > now
            if cached is not None and fresh and (certificate_id is None or certificate_id in cached.published_certificate_ids):
                return cached
            last_refresh = self._unknown_refresh_at.get(team_id)
            if last_refresh is not None and now - last_refresh < seconds_to_ns(UNKNOWN_CERTIFICATE_REFRESH_SECONDS):
                if cached is not None and fresh:
                    return cached
                failure = self._team_refresh_errors.get(team_id)
                if failure is not None:
                    raise HTTPException(status_code=failure[0], detail=failure[1])

            # Count every attempt before I/O, so cold/expired-cache outages also
            # coalesce. Cached failures never substitute for usable team facts.
            self._unknown_refresh_at[team_id] = now
            try:
                facts = await self._refresh_team_facts(team_id, now)
            except HTTPException as exc:
                if exc.status_code == 401 and exc.detail == "Unknown AWID team":
                    # Do not retain attacker-selected nonexistent teams. Check
                    # identity because another waiter may still own this lock.
                    if self._team_refresh_locks.get(team_id) is lock:
                        self._team_refresh_locks.pop(team_id, None)
                        self._unknown_refresh_at.pop(team_id, None)
                        self._team_refresh_errors.pop(team_id, None)
                else:
                    self._team_refresh_errors[team_id] = (exc.status_code, exc.detail)
                    # A slow failure must not consume its own retry window and
                    # make every waiter repeat the same upstream timeout.
                    self._unknown_refresh_at[team_id] = time.monotonic_ns()
                raise
            self._team_refresh_errors.pop(team_id, None)
            if not fresh and (certificate_id is None or certificate_id in facts.published_certificate_ids):
                # An ordinary successful load does not consume the early-refresh
                # allowance for a certificate published immediately afterwards.
                self._unknown_refresh_at.pop(team_id, None)
            return facts

    async def current_team_did_key(self, team_id: str) -> str | None:
        """The team's current controller key, read fresh (never cached), with
        the team's read authentication; None for a team AWID does not know.
        403 team_private_unreadable or 503 when AWID cannot answer."""
        domain, team_name = parse_team_id(team_id)
        team_url = f"{self.registry_url}/v1/namespaces/{domain}/teams/{team_name}"
        try:
            async with self._client() as client:
                response = await client.get(team_url, headers=self._read_headers(team_url))
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=503, detail="AWID registry unavailable") from exc
        _raise_if_private_team_unreadable(response, team_id)
        if response.status_code == 404:
            return None
        if response.status_code >= 400:
            raise HTTPException(status_code=503, detail="AWID registry unavailable")
        try:
            team_did_key = str(response.json().get("team_did_key") or "").strip()
        except (ValueError, AttributeError) as exc:
            raise HTTPException(status_code=503, detail="AWID registry unavailable") from exc
        if not team_did_key:
            raise HTTPException(status_code=503, detail="AWID team response missing team_did_key")
        return team_did_key

    async def check_member_credentials(self) -> None:
        """Read each configured member credential's team with that credential,
        fresh, and require its certificate to be published, unrevoked and
        signed by the team's current key: the app's startup check. RuntimeError
        names the team and the certificate."""
        for team_id, credential in self._member_credentials.items():
            certificate_id = credential.certificate_id
            try:
                # A check, not a load: requests read their own facts.
                facts = await self._refresh_team_facts(team_id, time.monotonic_ns(), store=False)
                checked = check_team_certificate(
                    base64.b64encode(json.dumps(dict(credential.certificate)).encode()).decode("ascii"),
                    subject_did_key=did_key_from_signing_key(credential.signing_key),
                    team_did_key=facts.team_did_key,
                    revoked_certificate_ids=facts.revoked_certificate_ids,
                    registered_certificate_ids=facts.published_certificate_ids,
                )
                async with self.registry_reader() as registry:
                    observation = await observe_team_protection(registry, team_id)
                    await verify_registered_membership(registry, observation, checked)
            except (HTTPException, TeamCertificateError, EffectRefused) as exc:
                detail = exc.detail if isinstance(exc, HTTPException) else str(exc)
                raise RuntimeError(
                    f"awid_member_credentials[{team_id}]: certificate {certificate_id} "
                    f"cannot read the team's AWID facts ({detail})"
                ) from None

    async def _refresh_team_facts(
        self, team_id: str, now: int, *, store: bool = True
    ) -> CachedTeamFacts:
        domain, team_name = parse_team_id(team_id)
        try:
            async with self._client() as client:
                team_url = f"{self.registry_url}/v1/namespaces/{domain}/teams/{team_name}"
                team_resp = await client.get(team_url, headers=self._read_headers(team_url))
                _raise_if_private_team_unreadable(team_resp, team_id)
                if team_resp.status_code == 404:
                    raise HTTPException(status_code=401, detail="Unknown AWID team")
                if team_resp.status_code >= 400:
                    raise HTTPException(status_code=503, detail="AWID registry unavailable")
                team_payload = team_resp.json()

                team_did_key = str(team_payload.get("team_did_key") or "").strip()
                if not team_did_key:
                    raise HTTPException(status_code=503, detail="AWID team response missing team_did_key")

                published: set[str] = set()
                revoked: set[str] = set()
                cursor: str | None = None
                seen_cursors: set[str] = set()
                for _ in range(MAX_CERTIFICATE_PAGES):
                    params: dict[str, str | int] = {
                        "active_only": "false", "limit": CERTIFICATE_PAGE_SIZE,
                    }
                    if cursor is not None:
                        params["cursor"] = cursor
                    certificates_url = f"{self.registry_url}/v1/namespaces/{domain}/teams/{team_name}/certificates"
                    cert_resp = await client.get(
                        certificates_url, params=params, headers=self._read_headers(certificates_url),
                    )
                    _raise_if_private_team_unreadable(cert_resp, team_id)
                    if cert_resp.status_code >= 400:
                        raise HTTPException(status_code=503, detail="AWID certificate revocation lookup unavailable")
                    cert_payload = cert_resp.json()
                    page = cert_payload.get("certificates")
                    has_more = cert_payload.get("has_more")
                    if (
                        not isinstance(page, list)
                        or len(page) > CERTIFICATE_PAGE_SIZE
                        or not isinstance(has_more, bool)
                        or not all(
                            isinstance(item, dict)
                            and isinstance(item.get("certificate_id"), str)
                            and bool(item["certificate_id"])
                            and "revoked_at" in item
                            for item in page
                        )
                    ):
                        raise HTTPException(status_code=503, detail="AWID certificate revocation response is incomplete")
                    published.update(item["certificate_id"] for item in page)
                    revoked.update(item["certificate_id"] for item in page if item["revoked_at"] is not None)
                    if not has_more:
                        break
                    next_cursor = cert_payload.get("next_cursor")
                    if not isinstance(next_cursor, str) or not next_cursor.strip() or next_cursor in seen_cursors:
                        raise HTTPException(status_code=503, detail="AWID certificate pagination did not advance")
                    seen_cursors.add(next_cursor)
                    cursor = next_cursor
                else:
                    raise HTTPException(status_code=503, detail="AWID certificate pagination limit exceeded")
        except HTTPException as exc:
            logger.warning("AWID team facts refresh failed: %s", exc.detail)
            raise
        except Exception as exc:
            logger.exception("AWID team facts refresh failed")
            raise HTTPException(status_code=503, detail="AWID registry unavailable") from exc

        facts = CachedTeamFacts(
            team_did_key=team_did_key,
            published_certificate_ids=frozenset(published),
            revoked_certificate_ids=frozenset(revoked),
            fetched_at=now,
            expires_at=now + seconds_to_ns(self.ttl_seconds),
        )
        if store:
            self._cache[team_id] = facts
        return facts

    async def _get_certificate_status(
        self, team_id: str, certificate_id: str
    ) -> CachedTeamFacts:
        now = time.monotonic_ns()
        cache_key = (team_id, certificate_id)
        cached = self._certificate_cache.get(cache_key)
        if cached and cached.expires_at > now:
            return cached
        domain, team_name = parse_team_id(team_id)
        try:
            async with self._client() as client:
                response = await client.get(
                    f"{self.registry_url}/v1/namespaces/{quote(domain, safe='')}/teams/"
                    f"{quote(team_name, safe='')}/certificates/{quote(certificate_id, safe='')}/status"
                )
                if response.status_code == 404:
                    # The registry answers one 404 for an unknown team and for a
                    # certificate it never published.
                    raise HTTPException(status_code=401, detail="unregistered")
                response.raise_for_status()
                payload = response.json()
            if (
                not isinstance(payload, dict)
                or set(payload) != {"team_id", "team_did_key", "status", "revoked_at"}
                or payload["team_id"] != team_id
                or payload["status"] not in ("active", "revoked")
                or not isinstance(payload["team_did_key"], str)
            ):
                raise ValueError("Malformed AWID certificate status")
            public_key_from_did(payload["team_did_key"])
            revoked_at = payload["revoked_at"]
            if payload["status"] == "active":
                if revoked_at is not None:
                    raise ValueError("Active certificate has revocation timestamp")
                revoked: frozenset[str] = frozenset()
            else:
                if not isinstance(revoked_at, str):
                    raise ValueError("Revoked certificate missing timestamp")
                timestamp = datetime.fromisoformat(revoked_at.replace("Z", "+00:00"))
                if timestamp.tzinfo is None:
                    raise ValueError("Revocation timestamp missing timezone")
                revoked = frozenset({certificate_id})
        except HTTPException:
            raise
        except Exception as exc:
            logger.warning("AWID certificate status lookup failed", exc_info=True)
            raise HTTPException(
                status_code=503, detail="AWID certificate status unavailable"
            ) from exc
        facts = CachedTeamFacts(
            team_did_key=payload["team_did_key"],
            published_certificate_ids=frozenset({certificate_id}),
            revoked_certificate_ids=revoked,
            fetched_at=now,
            expires_at=now + seconds_to_ns(self.ttl_seconds),
        )
        self._certificate_cache[cache_key] = facts
        return facts

    async def current_did_key(self, did_aw: str) -> str | None:
        """The did:aw's current did:key at this registry, or None when the
        registry has no such DID.

        A resolution is reused for at most the cache TTL and never after it
        expires: a failed refresh raises 503.
        """
        try:
            did_aw = validate_stable_id(did_aw)
        except ValueError:
            return None
        now = time.monotonic_ns()
        cache_key = (self.registry_origin, did_aw)
        cached = self._did_keys.get(cache_key)
        if cached and cached.expires_at > now:
            return cached.current_did_key
        key_url = f"{self.registry_url}/v1/did/{quote(did_aw, safe=':')}/key"
        try:
            async with self._client() as client:
                response = await client.get(key_url, headers=self._read_headers(key_url))
            current_did_key: str | None
            if response.status_code == 404:
                current_did_key = None
            else:
                response.raise_for_status()
                payload = response.json()
                if not isinstance(payload, dict) or payload.get("did_aw") != did_aw:
                    raise ValueError("AWID key resolution names another did:aw")
                current_did_key = payload.get("current_did_key")
                if not isinstance(current_did_key, str):
                    raise ValueError("AWID key resolution missing current_did_key")
                public_key_from_did(current_did_key)
        except Exception as exc:
            logger.warning("AWID did:aw resolution failed for %s", did_aw, exc_info=True)
            raise HTTPException(status_code=503, detail="AWID did:aw resolution unavailable") from exc
        self._did_keys[cache_key] = CachedDidKey(
            current_did_key=current_did_key, expires_at=now + seconds_to_ns(self.ttl_seconds)
        )
        return current_did_key


async def _did_aw_registry_verified(
    team_cache: AWIDTeamCache, *, did_aw: str, did_key: str, profile: DidAwProfile
) -> bool:
    try:
        current_did_key = await team_cache.current_did_key(did_aw)
    except HTTPException:
        outcome = "unavailable"
        if profile is DidAwProfile.REQUIRE:
            raise
    else:
        if current_did_key == did_key:
            outcome = "match"
        elif current_did_key is None:
            outcome = "unregistered"
        else:
            outcome = "key_mismatch"
        if outcome != "match" and profile is DidAwProfile.REQUIRE:
            raise HTTPException(status_code=401, detail="did:aw current key does not match the signer")
    if profile is DidAwProfile.OBSERVE:
        # The measurement before an app requires the check: a stable outcome
        # and the DID, nothing from the request.
        logger.log(
            logging.INFO if outcome == "match" else logging.WARNING,
            "did:aw current-key check %s for %s", outcome, did_aw,
            extra={"did_aw_outcome": outcome, "did_aw": did_aw},
        )
    return outcome == "match"


def _parse_didkey_auth(header: str) -> tuple[str, str]:
    parts = header.strip().split()
    if len(parts) != 3 or parts[0] != "DIDKey":
        raise HTTPException(status_code=401, detail="Invalid Authorization header")
    did_key, signature = parts[1].strip(), parts[2].strip()
    if not did_key.startswith("did:key:") or not signature:
        raise HTTPException(status_code=401, detail="Invalid DIDKey Authorization header")
    return did_key, signature


def _parse_rfc3339_utc(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="Invalid X-AWEB-Timestamp") from exc
    if parsed.tzinfo is None:
        raise HTTPException(status_code=401, detail="X-AWEB-Timestamp must include timezone")
    return parsed.astimezone(UTC)


def _certificate_refusal(error: TeamCertificateError) -> HTTPException:
    """The answer for a certificate the shared check refuses (awid's one table)."""
    status_code, detail = refusal_answer(error)
    return HTTPException(status_code=status_code, detail=detail)


def _certificate_locator(header: str) -> tuple[str, str]:
    """The team and certificate ids a certificate names, to read that team's
    facts at the registry before the certificate is checked against them."""
    try:
        certificate = decode_team_certificate(header)
        for name in ("team_id", "certificate_id"):
            value = certificate.get(name)
            if not isinstance(value, str) or not value.strip():
                raise TeamCertificateError("invalid_field", name)
    except TeamCertificateError as exc:
        raise _certificate_refusal(exc) from exc
    return certificate["team_id"], certificate["certificate_id"]


def _decode_signed_payload_header(value: str) -> bytes:
    text = value.strip()
    if not text:
        raise HTTPException(status_code=401, detail="Missing X-AWEB-Signed-Payload")
    if "=" in text or _B64URL_NO_PADDING.fullmatch(text) is None:
        raise HTTPException(status_code=401, detail="Invalid X-AWEB-Signed-Payload")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Invalid X-AWEB-Signed-Payload") from exc


def signed_payload_bytes(request: Request) -> bytes:
    """The request's team-auth v2 signed-payload bytes, the bytes
    :func:`authenticate_request` verified the signature over."""
    signed_payload_header = request.headers.get("X-AWEB-Signed-Payload") or ""
    return _decode_signed_payload_header(signed_payload_header)


def raw_request_target(request: Request) -> str:
    raw_path_value = request.scope.get("raw_path")
    if isinstance(raw_path_value, bytes):
        try:
            path = raw_path_value.decode("ascii")
        except UnicodeDecodeError as exc:
            raise HTTPException(status_code=400, detail="Request target is not ASCII") from exc
    elif raw_path_value:
        path = str(raw_path_value)
    else:
        path = quote(str(request.scope.get("path") or request.url.path or "/"), safe="/%")

    root_path = str(request.scope.get("root_path") or "")
    if root_path and not path.startswith(root_path):
        encoded_root = quote(root_path.rstrip("/"), safe="/%")
        path = encoded_root + (path if path.startswith("/") else f"/{path}")

    if not path.startswith("/"):
        path = f"/{path}"

    query_string = request.scope.get("query_string") or b""
    if isinstance(query_string, bytes):
        try:
            query = query_string.decode("ascii")
        except UnicodeDecodeError as exc:
            raise HTTPException(status_code=400, detail="Request target is not ASCII") from exc
    else:
        query = str(query_string)
    if query:
        return f"{path}?{query}"
    return path


def _verified_signed_payload(
    request: Request,
    *,
    public_origin: str,
    did_key: str,
    signature: str,
    header_timestamp: str,
    team_id: str,
    body: bytes,
) -> dict[str, Any]:
    canonical = signed_payload_bytes(request)
    try:
        payload = json.loads(canonical)
        # A value that does not encode, such as a lone surrogate, can never be
        # the canonical bytes the member signed.
        recanonical = canonical_json_bytes(payload) if isinstance(payload, dict) else None
    except (ValueError, TypeError, RecursionError) as exc:
        raise HTTPException(status_code=401, detail="Invalid X-AWEB-Signed-Payload") from exc
    if recanonical != canonical:
        raise HTTPException(status_code=401, detail="Invalid X-AWEB-Signed-Payload")

    if payload.get("v") != TEAM_AUTH_ENVELOPE_V2:
        raise HTTPException(status_code=401, detail="Unsupported team-auth envelope version")

    expected = {
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "method": request.method.upper(),
        "path": raw_request_target(request),
        "team_id": team_id,
        "timestamp": header_timestamp.strip(),
    }
    for field, expected_value in expected.items():
        if str(payload.get(field) or "").strip() != expected_value:
            raise HTTPException(status_code=401, detail="Signed request payload does not match request")

    try:
        configured_audience = canonical_server_origin(public_origin)
        signed_audience = canonical_server_origin(str(payload.get("aud") or "").strip())
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Signed request payload audience is invalid") from exc
    if signed_audience != configured_audience:
        raise HTTPException(status_code=401, detail="Signed request payload audience is not allowed")

    try:
        verify_did_key_signature(did_key=did_key, payload=canonical, signature_b64=signature)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="Invalid DIDKey signature") from exc

    return payload


async def require_active_certificate(
    team_cache: AWIDTeamCache, *, team_id: str, certificate_id: str,
) -> CachedTeamFacts:
    """Require controller-published, unrevoked membership through the shared cache.

    This checks current publication, not the certificate signature or the
    caller's request signature. Consumers (including event ingestion) must
    verify those signed artifacts as well. Unknown/revoked membership is 401;
    unavailable authority retains the cache's 503 failure.
    """
    try:
        facts = await team_cache.get(team_id, certificate_id)
    except ValueError as exc:
        raise _certificate_refusal(TeamCertificateError("invalid_field", "team_id")) from exc
    _require_active_certificate(facts, certificate_id)
    return facts


async def authenticate_request(
    request: Request,
    *,
    public_origin: str,
    team_cache: AWIDTeamCache,
    timestamp_skew_seconds: int = MAX_TIMESTAMP_SKEW_SECONDS,
    did_aw_profile: DidAwProfile = DidAwProfile.REQUIRE,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> Principal:
    auth_header = request.headers.get("Authorization") or request.headers.get("authorization") or ""
    did_key, signature = _parse_didkey_auth(auth_header)

    timestamp = request.headers.get("X-AWEB-Timestamp") or request.headers.get("x-aweb-timestamp") or ""
    if not timestamp:
        raise HTTPException(status_code=401, detail="Missing X-AWEB-Timestamp")
    parsed_timestamp = _parse_rfc3339_utc(timestamp)
    skew = abs((now() - parsed_timestamp).total_seconds())
    if skew > min(timestamp_skew_seconds, MAX_TIMESTAMP_SKEW_SECONDS):
        raise HTTPException(status_code=401, detail="X-AWEB-Timestamp outside allowed clock skew")

    cert_header = request.headers.get("X-AWID-Team-Certificate") or request.headers.get("x-awid-team-certificate") or ""
    if not cert_header:
        raise HTTPException(status_code=401, detail="Missing X-AWID-Team-Certificate")
    team_id, certificate_id = _certificate_locator(cert_header)

    body = await request.body()
    request.state.cached_body = body
    request.state.body_sha256 = hashlib.sha256(body).hexdigest()
    _verified_signed_payload(
        request,
        public_origin=public_origin,
        did_key=did_key,
        signature=signature,
        header_timestamp=timestamp,
        team_id=team_id,
        body=body,
    )

    try:
        facts = await team_cache.get(team_id, certificate_id)
    except ValueError as exc:
        raise _certificate_refusal(TeamCertificateError("invalid_field", "team_id")) from exc
    try:
        # The team's key and certificates were read for the certificate's own team_id.
        cert = check_team_certificate(
            cert_header,
            subject_did_key=did_key,
            team_did_key=facts.team_did_key,
            revoked_certificate_ids=facts.revoked_certificate_ids,
            registered_certificate_ids=facts.published_certificate_ids,
        )
    except TeamCertificateError as exc:
        raise _certificate_refusal(exc) from exc
    await team_cache.verify_membership_certificate(cert, facts)
    alias = cert["alias"]

    did_aw = str(cert.get("member_did_aw") or "").strip() or None
    did_aw_registry_verified = did_aw is not None and await _did_aw_registry_verified(
        team_cache, did_aw=did_aw, did_key=did_key, profile=did_aw_profile
    )

    try:
        if facts.protection_observation is None:
            raise EffectRefused("protected_state_unavailable")
        facts.protection_observation.require_fresh()
    except EffectRefused as exc:
        raise HTTPException(status_code=503, detail={"code": exc.code}) from exc
    return Principal(
        team_id=team_id,
        did_key=did_key,
        did_aw=did_aw,
        address=(str(cert.get("member_address") or "").strip() or None),
        alias=alias,
        certificate_id=certificate_id,
        team_did_key=facts.team_did_key,
        did_aw_registry_verified=did_aw_registry_verified,
    )


async def record_observed_principal(db: AsyncDatabaseManager, principal: Principal) -> None:
    await db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, team_did_key)
        VALUES ($1, $2)
        ON CONFLICT (team_id) DO UPDATE
        SET team_did_key = EXCLUDED.team_did_key,
            last_seen_at = NOW()
        """,
        principal.team_id,
        principal.team_did_key,
    )
    await db.execute(
        """
        INSERT INTO {{tables.agents}}
          (team_id, did_key, did_aw, address, alias, latest_certificate_id)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (team_id, did_key, alias) DO UPDATE
        SET did_aw = EXCLUDED.did_aw,
            address = EXCLUDED.address,
            latest_certificate_id = EXCLUDED.latest_certificate_id,
            last_seen_at = NOW()
        """,
        principal.team_id,
        principal.did_key,
        principal.did_aw,
        principal.address,
        principal.alias,
        principal.certificate_id,
    )
