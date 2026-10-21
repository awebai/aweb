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

import base64
import hashlib
import json
import logging
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from urllib.parse import quote

import httpx
from awid.did import public_key_from_did, validate_stable_id
from awid.log import canonical_server_origin
from awid.signing import (
    canonical_json_bytes,
    verify_did_key_signature,
)
from awid.team_certificate import (
    TeamCertificateError,
    decode_team_certificate,
    verify_team_certificate_signature,
)
from awid.team_ids import parse_team_id
from fastapi import HTTPException, Request
from pgdbm import AsyncDatabaseManager

logger = logging.getLogger(__name__)

# At most 20,000 certificate records per refresh; incomplete history is never cached.
MAX_CERTIFICATE_PAGES = 100
CERTIFICATE_PAGE_SIZE = 200

TEAM_AUTH_ENVELOPE_V2 = 2
# The envelope contract allows at most five minutes; a larger configured window is clamped.
MAX_TIMESTAMP_SKEW_SECONDS = 300
# AWID team facts are reused for at most a minute; a longer configured TTL is clamped.
MAX_TEAM_FACTS_TTL_SECONDS = 60
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
class CachedTeamFacts:
    team_did_key: str
    published_certificate_ids: frozenset[str]
    revoked_certificate_ids: frozenset[str]
    expires_at: float


@dataclass(frozen=True)
class CachedDidKey:
    # None when the registry answered that it has no such DID.
    current_did_key: str | None
    expires_at: float


def _raise_if_private_team_unreadable(response: httpx.Response) -> None:
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
                "message": "App cannot read private AWID team facts; configure its AWID service token",
            },
        )


class AWIDTeamCache:
    """Small in-memory cache of AWID team authentication facts."""

    def __init__(
        self,
        *,
        registry_url: str,
        ttl_seconds: int,
        service_token: str | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.registry_url = registry_url.rstrip("/")
        self.registry_origin = canonical_server_origin(self.registry_url)
        self.ttl_seconds = min(ttl_seconds, MAX_TEAM_FACTS_TTL_SECONDS)
        self._headers = (
            {"X-AWID-Service-Token": service_token.strip()}
            if service_token and service_token.strip()
            else {}
        )
        self._cache: dict[str, CachedTeamFacts] = {}
        self._certificate_cache: dict[tuple[str, str], CachedTeamFacts] = {}
        self._did_keys: dict[tuple[str, str], CachedDidKey] = {}
        self._transport = transport

    def _client(self) -> httpx.AsyncClient:
        if self._transport is None:
            return httpx.AsyncClient(timeout=10.0)
        return httpx.AsyncClient(timeout=10.0, transport=self._transport)

    async def get(self, team_id: str, certificate_id: str | None = None) -> CachedTeamFacts:
        if not self._headers:
            if not certificate_id:
                raise HTTPException(status_code=401, detail="Missing AWID certificate id")
            return await self._get_certificate_status(team_id, certificate_id)
        now = time.monotonic()
        cached = self._cache.get(team_id)
        if cached and cached.expires_at > now:
            return cached

        domain, team_name = parse_team_id(team_id)
        try:
            async with self._client() as client:
                team_resp = await client.get(
                    f"{self.registry_url}/v1/namespaces/{domain}/teams/{team_name}",
                    headers=self._headers,
                )
                _raise_if_private_team_unreadable(team_resp)
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
                    cert_resp = await client.get(
                        f"{self.registry_url}/v1/namespaces/{domain}/teams/{team_name}/certificates",
                        params=params, headers=self._headers,
                    )
                    _raise_if_private_team_unreadable(cert_resp)
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
            expires_at=now + self.ttl_seconds,
        )
        self._cache[team_id] = facts
        return facts

    async def _get_certificate_status(
        self, team_id: str, certificate_id: str
    ) -> CachedTeamFacts:
        now = time.monotonic()
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
                    raise HTTPException(status_code=401, detail="Unknown AWID certificate")
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
            expires_at=now + self.ttl_seconds,
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
        now = time.monotonic()
        cache_key = (self.registry_origin, did_aw)
        cached = self._did_keys.get(cache_key)
        if cached and cached.expires_at > now:
            return cached.current_did_key
        try:
            async with self._client() as client:
                response = await client.get(
                    f"{self.registry_url}/v1/did/{quote(did_aw, safe=':')}/key", headers=self._headers
                )
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
            current_did_key=current_did_key, expires_at=now + self.ttl_seconds
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


def _decode_certificate(header: str) -> dict[str, Any]:
    try:
        return decode_team_certificate(header)
    except TeamCertificateError as exc:
        raise HTTPException(status_code=401, detail="Malformed team certificate") from exc


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


_CERTIFICATE_REFUSALS = {
    "malformed": (401, "Malformed team certificate"),
    "missing_signature": (401, "Team certificate missing signature"),
    "invalid_team_key": (503, "Invalid AWID team public key"),
    "bad_signature": (401, "Team certificate signature verification failed"),
}


def _verify_certificate_signature(cert: dict[str, Any], team_did_key: str) -> None:
    try:
        verify_team_certificate_signature(cert, team_did_key)
    except TeamCertificateError as exc:
        status_code, detail = _CERTIFICATE_REFUSALS[exc.reason]
        raise HTTPException(status_code=status_code, detail=detail) from exc


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
        raise HTTPException(status_code=401, detail="Invalid AWID team id") from exc
    if certificate_id not in facts.published_certificate_ids:
        raise HTTPException(status_code=401, detail="Unknown AWID certificate")
    if certificate_id in facts.revoked_certificate_ids:
        raise HTTPException(status_code=401, detail="Team certificate has been revoked")
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
    cert = _decode_certificate(cert_header)

    team_id = str(cert.get("team_id") or "").strip()
    certificate_id = str(cert.get("certificate_id") or "").strip()
    member_did_key = str(cert.get("member_did_key") or "").strip()
    alias = str(cert.get("alias") or "").strip()
    if not team_id or not certificate_id or not member_did_key or not alias:
        raise HTTPException(status_code=401, detail="Team certificate missing required fields")
    if member_did_key != did_key:
        raise HTTPException(status_code=401, detail="Team certificate member_did_key mismatch")

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

    facts = await require_active_certificate(
        team_cache, team_id=team_id, certificate_id=certificate_id,
    )
    _verify_certificate_signature(cert, facts.team_did_key)

    did_aw = str(cert.get("member_did_aw") or "").strip() or None
    did_aw_registry_verified = did_aw is not None and await _did_aw_registry_verified(
        team_cache, did_aw=did_aw, did_key=did_key, profile=did_aw_profile
    )

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
