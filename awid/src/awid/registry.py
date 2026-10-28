"""HTTP client for the external AWID registry."""

from __future__ import annotations

import asyncio
import base64
import fnmatch
import hashlib
import inspect
import ipaddress
import json
import logging
from json import loads as json_loads
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable
from urllib.parse import quote, urlparse

import httpx
from nacl.signing import SigningKey
from redis.asyncio import Redis
from redis.exceptions import RedisError

from awid.contract import normalize_identity_scope
from awid.controller_request import CONTROLLER_REQUEST_TYPE
from awid.did import did_from_public_key, stable_id_from_did_key
from awid.dns_verify import DomainVerifier
from awid.id_certificates import (
    IDCertificateError,
    IDChainEvidence,
    encode_id_chain_header,
    key_response_id_tree,
    status_request,
    verify_ed25519,
)
from awid.log import (
    canonical_server_origin,
    identity_state_hash,
    log_entry_payload,
)
from awid.ratelimit import AWID_SERVICE_TOKEN_HEADER, normalize_service_token
from awid.signing import canonical_json_bytes, sign_message


DomainRegistryResolver = Callable[[str], Awaitable[str]]
# Signs exactly the bytes it is given and answers with its did:key and the raw
# 64-byte signature, directly or awaitably, so a custodial host can finish its
# own checks before answering. No key material crosses this boundary.
PayloadSigner = Callable[[bytes], "tuple[str, bytes] | Awaitable[tuple[str, bytes]]"]

logger = logging.getLogger(__name__)

MAX_REGISTRY_RESPONSE_BYTES = 10 * 1024 * 1024
MAX_REGISTRY_ERROR_BYTES = 64 * 1024


def _safe_error_text(content: bytes) -> str:
    text = content.decode("utf-8", errors="replace")
    sanitized = "".join(" " if not char.isprintable() else char for char in text)
    return " ".join(sanitized.split())


async def _read_bounded_response(response: httpx.Response, max_bytes: int) -> bytes:
    # httpx decompresses each raw chunk before yielding it, so an encoded bomb
    # can allocate past max_bytes before this function can inspect the result.
    content_encoding = response.headers.get("Content-Encoding", "").strip().lower()
    if content_encoding not in {"", "identity"}:
        raise ValueError("unsupported HTTP Content-Encoding")

    if response.is_stream_consumed:
        content = response.content
        if len(content) > max_bytes:
            raise ValueError(f"HTTP response exceeds maximum size of {max_bytes} bytes")
        return content

    content = bytearray()
    async for chunk in response.aiter_raw(chunk_size=64 * 1024):
        if len(content) + len(chunk) > max_bytes:
            raise ValueError(f"HTTP response exceeds maximum size of {max_bytes} bytes")
        content.extend(chunk)
    return bytes(content)


_ADDRESS_CACHE_TTL_SECONDS = 5 * 60
_NAMESPACE_CACHE_TTL_SECONDS = 15 * 60
_DID_KEY_CACHE_TTL_SECONDS = 5 * 60
_TEAM_METADATA_CACHE_TTL_SECONDS = 10 * 60  # 10 minutes
# Revocations get a much shorter bound than other team metadata: since
# aweb-abfn they are load-bearing for membership enforcement on every
# authenticated messaging request, and this TTL is the client half of how fast
# a revocation takes effect (aweb-abfp; the ruling in trust-model.md's
# "Threat-model rulings" accepts bounded client staleness). 60 seconds matches
# the federation authority reuse ceiling. With the stale-while-revalidate
# window below, the hard worst case is 2x this value; the cache lives in Redis
# and survives process restarts, so the TTL is the only bound.
_TEAM_REVOCATIONS_CACHE_TTL_SECONDS = 60
# Team-controller keys share this freshness bound, with synchronous refresh.
# Registry-outage grace adopted for revocations (Juan 2026-08-17; see
# trust-model.md "Registry availability posture"); team-controller keys share
# this same bound (F-19/F-20). When a revocation refresh fails, the
# last-known-good set is served — loudly logged —
# for as long as the data is at most this old; past it the read fails closed
# (503 upstream). This is a constant, not a configuration knob: raising it is a
# trust-model change and belongs next to the rulings in trust-model.md. The
# grace decision is made on the stored fetch timestamp (data age), not on Redis
# expiry; Redis merely retains the entries long enough for the grace to
# be decidable.
_TEAM_REVOCATIONS_OUTAGE_GRACE_SECONDS = 15 * 60
_TEAM_CERTIFICATES_CACHE_TTL_SECONDS = 10 * 60  # 10 minutes
# Keep stale entries for one additional TTL window so callers can get
# stale-while-revalidate behavior instead of taking a hard miss immediately.
_STALE_MULTIPLIER = 2
# Identity-tree status evidence (docs/id-certificates.md R-1) is reused through
# this age inclusive, then refreshed synchronously. The 900-second outage grace
# after a failed refresh is the verifier's: this client reports the age of
# what it serves and whether a refresh failed, and the verifier decides.
_ID_STATUS_FRESH_SECONDS = 60
# A failed attempt stands for every refresh of its domain through this many
# seconds inclusive, so a registry that stalls costs one timeout per window
# rather than one per request. It changes no evidence age.
_ID_STATUS_FAILURE_COOLDOWN_SECONDS = _ID_STATUS_FRESH_SECONDS
# Entries outlive the grace, so evidence past it is reported as expired rather
# than as never observed.
_ID_STATUS_RETENTION_SECONDS = 2 * 15 * 60
_ID_STATUS_PATH = "/v1/id-certificates/status"


def _is_local_registry_origin(registry_url: str) -> bool:
    host = (urlparse(canonical_server_origin(registry_url)).hostname or "").lower()
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_unspecified


@dataclass(frozen=True)
class _RevocationScan:
    """What one page-through of the revocations route actually read."""

    certificate_ids: set[str]
    # Newest revoked_at seen in this scan, or None if the scan read no usable
    # timestamps. This is the high-water mark's raw material.
    newest_revoked_at: datetime | None
    # False if any entry arrived without a parseable revoked_at. Such a scan
    # cannot produce a trustworthy mark, so it must not be used to advance one.
    entries_all_timestamped: bool
    # True if the route answered 404 (team deleted, or never existed).
    team_missing: bool


def _parse_revoked_at(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class DIDKeyEvidence:
    seq: int
    operation: str
    previous_did_key: str | None
    new_did_key: str
    prev_entry_hash: str | None
    entry_hash: str
    state_hash: str
    authorized_by: str
    signature: str
    timestamp: str


@dataclass(frozen=True)
class DIDMapping:
    did_aw: str
    current_did_key: str
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class IDTreeEnrollment:
    """A did:aw's identity-tree enrollment as its registry states it.

    enrolled carries the domain fixed at first enrollment; a revoked ID is
    still enrolled. Not enrolled is proven only by a registry that says so.
    """

    enrolled: bool
    domain: str | None


@dataclass(frozen=True)
class KeyResolution:
    did_aw: str
    current_did_key: str
    log_head: DIDKeyEvidence | None = None
    encryption_key: dict[str, Any] | None = None
    # None is unknown: a registry, or a cache entry, that did not state it.
    id_tree: IDTreeEnrollment | None = None


@dataclass(frozen=True)
class Namespace:
    namespace_id: str
    domain: str
    controller_did: str | None
    verification_status: str
    last_verified_at: str | None
    created_at: str
    default_delivery_origin: str | None = None


@dataclass(frozen=True)
class AddressDelivery:
    origin: str | None
    source: str = "namespace_default"


@dataclass(frozen=True)
class Address:
    address_id: str
    domain: str
    name: str
    did_aw: str
    current_did_key: str
    created_at: str
    # Legacy compatibility only: older callers/tests may still construct or
    # read these fields from older AWID services. Current AWID responses omit
    # them and routing must not consult them.
    reachability: str = ""
    visible_to_team_id: str | None = None
    delivery: AddressDelivery = field(
        default_factory=lambda: AddressDelivery(origin=None),
    )


@dataclass(frozen=True)
class Team:
    team_id: str
    domain: str
    name: str
    display_name: str
    team_did_key: str
    visibility: str
    created_at: str


@dataclass(frozen=True)
class TeamCertificate:
    certificate_id: str
    member_did_key: str
    member_did_aw: str | None
    member_address: str | None
    alias: str
    identity_scope: str
    issued_at: str
    revoked_at: str | None = None

    @property
    def lifetime(self) -> str:
        """Deprecated compatibility alias for older callers."""
        return "persistent" if normalize_identity_scope(self.identity_scope) == "global" else "ephemeral"


class RegistryError(Exception):
    def __init__(
        self, message: str, *, status_code: int, detail: str | None = None, code: str | None = None,
        body: Any = None,
        body_is_json: bool = False,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.detail = detail or message
        # The refusal's machine-readable code, when the registry sent one.
        self.code = code
        # The refusal's parsed JSON body, of whatever type, when body_is_json.
        self.body = body
        self.body_is_json = body_is_json


class DIDKeyNotFoundError(RegistryError):
    """The registry has no key for the did:aw; id_tree says whether it is enrolled.

    id_tree is None (unknown) when the registry did not state it.
    """

    def __init__(self, refused: RegistryError, *, id_tree: IDTreeEnrollment | None) -> None:
        super().__init__(
            str(refused), status_code=refused.status_code, detail=refused.detail, code=refused.code,
            body=refused.body, body_is_json=refused.body_is_json,
        )
        self.id_tree = id_tree


class AlreadyRegisteredError(RegistryError):
    def __init__(self, *, did_aw: str, existing_did_key: str) -> None:
        self.did_aw = did_aw
        self.existing_did_key = existing_did_key
        super().__init__(
            f"DID already registered: {did_aw}",
            status_code=409,
            detail="did_aw already registered",
        )


class MalformedIDStatusError(ValueError):
    """A successful status answer that is not a JSON object within the response bound."""


class DIDRegistrationRequiredError(RegistryError):
    def __init__(self) -> None:
        super().__init__(
            "did_aw must be registered before address assignment",
            status_code=409,
            detail="did_aw must be registered before address assignment",
        )


class DIDCurrentKeyMismatchError(RegistryError):
    def __init__(self) -> None:
        super().__init__(
            "did_aw current key does not match",
            status_code=409,
            detail="did_aw current key does not match",
        )


class AddressAlreadyBoundError(RegistryError):
    def __init__(self) -> None:
        super().__init__(
            "address already bound to a different did_aw",
            status_code=409,
            detail="address already bound to a different did_aw",
        )


@dataclass(frozen=True)
class RegistryClient:
    registry_url: str
    timeout_seconds: float = 5.0
    transport: httpx.AsyncBaseTransport | None = None
    base_url: str | None = None
    domain_registry_resolver: DomainRegistryResolver | None = None
    service_token: str | None = field(default=None, repr=False, compare=False)
    _http_client: httpx.AsyncClient = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "service_token", normalize_service_token(self.service_token))
        object.__setattr__(
            self,
            "_http_client",
            httpx.AsyncClient(
                timeout=self.timeout_seconds,
                transport=self.transport,
                follow_redirects=False,
            ),
        )

    def _resolved_base_url(self, registry_url: str | None = None) -> str:
        target_registry_url = registry_url or self.registry_url
        if registry_url is None and self.base_url:
            return self.base_url.rstrip("/")
        return canonical_server_origin(target_registry_url)

    async def _registry_url_for_domain(self, domain: str) -> str:
        if self.domain_registry_resolver is not None:
            return canonical_server_origin(await self.domain_registry_resolver(domain))
        if self.transport is not None:
            return canonical_server_origin(self.registry_url)
        default_registry_url = canonical_server_origin(self.registry_url)
        if _is_local_registry_origin(default_registry_url):
            return default_registry_url
        from awid.dns_verify import (
            DEFAULT_AWID_REGISTRY_URL,
            DnsVerificationError,
            discover_registry_override,
        )

        if default_registry_url != canonical_server_origin(DEFAULT_AWID_REGISTRY_URL):
            return default_registry_url

        try:
            registry_override = await discover_registry_override(domain)
        except DnsVerificationError:
            logger.debug(
                "AWID registry override lookup failed for %s; using configured registry %s",
                domain,
                default_registry_url,
                exc_info=True,
            )
            return default_registry_url
        if registry_override is None:
            return default_registry_url
        return canonical_server_origin(registry_override)

    async def _request_json(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        json: dict[str, Any] | None = None,
        content: bytes | None = None,
        registry_url: str | None = None,
    ) -> dict[str, Any]:
        request_headers = {
            key: value
            for key, value in (headers or {}).items()
            if key.strip().lower() != "accept-encoding"
        }
        request_headers["Accept-Encoding"] = "identity"
        if self.service_token and (
            registry_url is None
            or canonical_server_origin(registry_url)
            == canonical_server_origin(self.registry_url)
        ):
            request_headers[AWID_SERVICE_TOKEN_HEADER] = self.service_token
        async with asyncio.timeout(self.timeout_seconds):
            async with self._http_client.stream(
                method,
                f"{self._resolved_base_url(registry_url=registry_url)}{path}",
                headers=request_headers,
                json=json,
                content=content,
            ) as response:
                succeeded = 200 <= response.status_code < 300
                max_bytes = MAX_REGISTRY_RESPONSE_BYTES if succeeded else MAX_REGISTRY_ERROR_BYTES
                try:
                    content = await _read_bounded_response(response, max_bytes)
                except ValueError as exc:
                    if succeeded:
                        raise
                    # An unreadable error page is still this refusal.
                    raise RegistryError(
                        f"unreadable HTTP {response.status_code} response",
                        status_code=response.status_code,
                    ) from exc
        if not 200 <= response.status_code < 300:
            detail = None
            code = None
            parsed_error = None
            body_is_json = False
            try:
                parsed_error = json_loads(content)
                body_is_json = True
                if isinstance(parsed_error, dict):
                    raw_detail = parsed_error.get("detail")
                    if raw_detail is not None:
                        detail = _safe_error_text(str(raw_detail).encode("utf-8"))
                    if isinstance(raw_detail, dict) and isinstance(raw_detail.get("code"), str):
                        code = _safe_error_text(raw_detail["code"].encode("utf-8"))
            except Exception:
                detail = None
            response_text = _safe_error_text(content)
            if response.status_code == 409:
                if detail == "did_aw must be registered before address assignment":
                    raise DIDRegistrationRequiredError()
                if detail == "did_aw current key does not match":
                    raise DIDCurrentKeyMismatchError()
                if detail == "address already bound to a different did_aw":
                    raise AddressAlreadyBoundError()
            raise RegistryError(
                detail or response_text,
                status_code=response.status_code,
                detail=detail or response_text,
                code=code,
                body=parsed_error,
                body_is_json=body_is_json,
            )
        if not content:
            return {}
        return json_loads(content)

    async def aclose(self) -> None:
        await self._http_client.aclose()

    async def health(self) -> dict[str, Any]:
        return await self._request_json("GET", "/health")

    async def _request_optional_json(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        json: dict[str, Any] | None = None,
        registry_url: str | None = None,
    ) -> dict[str, Any] | None:
        try:
            return await self._request_json(
                method,
                path,
                headers=headers,
                json=json,
                registry_url=registry_url,
            )
        except RegistryError as exc:
            if exc.status_code == 404:
                return None
            raise

    async def register_id_certificate(
        self,
        bundle: dict[str, Any],
        *,
        signer: PayloadSigner,
        expected_head: str | None,
        invitation_id: str | None,
    ) -> dict[str, Any]:
        """Register ``bundle``'s last certificate, with the bundle as its supporting chain.

        ``signer`` holds the subject's current key; AWID's gate enforces that
        binding. Returns the registration receipt, the original one for an
        exact retry.
        """
        leaf = bundle["certificates"][-1]
        chain_header = encode_id_chain_header(bundle)
        return await self._covering_request(
            "/v1/id-certificates/register",
            domain=leaf["certificate"]["domain"],
            operation="register_id_certificate",
            body={"certificate": leaf, "expected_head": expected_head, "invitation_id": invitation_id},
            signers=[("Authorization", signer, None)],
            extra_headers={"X-AWID-ID-Chain": chain_header},
        )

    async def revoke_id_certificate(
        self,
        domain: str,
        id: str,
        *,
        signer: PayloadSigner,
        expected_head: str | None,
        effective_from: str | None = None,
    ) -> dict[str, Any]:
        """Revoke the registered ``id``; AWID decides whether the signer acts as root, self or parent."""
        return await self._covering_request(
            "/v1/id-certificates/revoke",
            domain=domain,
            operation="revoke_id_certificate",
            body={"domain": domain, "id": id, "expected_head": expected_head, "effective_from": effective_from},
            signers=[("Authorization", signer, None)],
        )

    async def rotate_namespace_with_previous_key(
        self,
        domain: str,
        *,
        from_seq: int,
        previous_did_key: str,
        new_did_key: str,
        previous_signer: PayloadSigner,
        new_signer: PayloadSigner,
    ) -> Namespace:
        """Rotate the namespace controller with the previous key's consent, keeping its ID tree.

        Both keys sign the same request, and each signer must answer with the
        key named for its role. ``from_seq`` is the open epoch being rotated.
        """
        claims = {"from_seq": from_seq, "previous_did_key": previous_did_key, "new_did_key": new_did_key}
        return _namespace_from_json(
            await self._covering_request(
                f"/v1/namespaces/{domain}/rotate",
                domain=domain,
                operation="rotate_namespace_controller",
                body={"domain": domain, "operation": "rotate_namespace_controller", **claims},
                claims=claims,
                signers=[
                    ("Authorization", previous_signer, previous_did_key),
                    ("X-AWEB-New-Key-Authorization", new_signer, new_did_key),
                ],
            )
        )

    async def _covering_request(
        self,
        path: str,
        *,
        domain: str,
        operation: str,
        body: dict[str, Any],
        signers: list[tuple[str, PayloadSigner, str | None]],
        claims: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """POST ``body`` under a covering-v2 envelope that every signer signs.

        Each signer's answer is checked against the exact payload before
        anything is sent; a signer that raises or answers wrongly sends nothing.
        """
        registry_url = await self._registry_url_for_domain(domain)
        raw_body = canonical_json_bytes(body)
        timestamp = _utc_timestamp()
        payload = canonical_json_bytes({
            **(claims or {}),
            "v": 2,
            "type": CONTROLLER_REQUEST_TYPE,
            "aud": canonical_server_origin(registry_url),
            "method": "POST",
            "path": path,
            "body_sha256": hashlib.sha256(raw_body).hexdigest(),
            "timestamp": timestamp,
            "domain": domain,
            "operation": operation,
        })
        headers = {
            "Content-Type": "application/json",
            "X-AWEB-Timestamp": timestamp,
            "X-AWEB-Signed-Payload": base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii"),
            **(extra_headers or {}),
        }
        for header, signer, expected_key in signers:
            did_key, signature = await _payload_signature(signer, payload, expected_key)
            headers[header] = f"DIDKey {did_key} {base64.b64encode(signature).rstrip(b'=').decode('ascii')}"
        return await self._request_json("POST", path, headers=headers, content=raw_body, registry_url=registry_url)

    async def fetch_id_certificate_status(self, domain: str, request: dict[str, Any]) -> dict[str, Any]:
        """POST a status request to the registry ``domain`` routes to.

        Raises RegistryError for a refused answer and MalformedIDStatusError
        for a successful answer that is not a JSON object.
        """
        registry_url = await self._registry_url_for_domain(domain)
        try:
            status = await self._request_json("POST", _ID_STATUS_PATH, json=request, registry_url=registry_url)
        except ValueError as exc:
            raise MalformedIDStatusError(str(exc)) from exc
        if not isinstance(status, dict):
            raise MalformedIDStatusError("status answer is not a JSON object")
        return status

    async def get_mapping(self, did_aw: str, signing_key: bytes) -> DIDMapping:
        path = f"/v1/did/{did_aw}/full"
        return _did_mapping_from_json(
            await self._request_json(
                "GET",
                path,
                headers=self._signed_path_headers("GET", path, signing_key),
            )
        )

    async def register_did(
        self,
        did_key: str,
        signing_key: bytes,
    ) -> DIDMapping:
        signer_did = _did_key_from_signing_key(signing_key)
        if signer_did != did_key:
            raise ValueError("signing_key must match did_key for DID registration")

        did_aw = stable_id_from_did_key(did_key)
        timestamp = _utc_timestamp()
        mapping_state_hash = identity_state_hash(did_aw=did_aw, current_did_key=did_key)
        proof = sign_message(
            signing_key,
            log_entry_payload(
                did_aw=did_aw,
                seq=1,
                operation="register_did",
                previous_did_key=None,
                new_did_key=did_key,
                prev_entry_hash=None,
                state_hash=mapping_state_hash,
                authorized_by=did_key,
                timestamp=timestamp,
            ),
        )
        try:
            await self._request_json(
                "POST",
                "/v1/did",
                json={
                    "did_aw": did_aw,
                    "operation": "register_did",
                    "previous_did_key": None,
                    "new_did_key": did_key,
                    "seq": 1,
                    "prev_entry_hash": None,
                    "state_hash": mapping_state_hash,
                    "authorized_by": did_key,
                    "timestamp": timestamp,
                    "proof": proof,
                },
            )
        except RegistryError as exc:
            if exc.status_code != 409:
                raise
            try:
                existing = await self.resolve_key(did_aw)
            except RegistryError:
                raise exc
            raise AlreadyRegisteredError(did_aw=did_aw, existing_did_key=existing.current_did_key)
        return await self.get_mapping(did_aw, signing_key)

    async def resolve_key(self, did_aw: str) -> KeyResolution:
        try:
            data = await self._request_json("GET", f"/v1/did/{did_aw}/key")
        except RegistryError as refused:
            if refused.status_code == 404:
                # Without a JSON body there is no response to state enrollment; a
                # JSON body is parsed as a response, so a non-object is malformed.
                id_tree = _id_tree_enrollment(refused.body) if refused.body_is_json else None
                raise DIDKeyNotFoundError(refused, id_tree=id_tree) from refused
            raise
        return _key_resolution_from_json(data)

    async def resolve_key_fresh(self, did_aw: str) -> KeyResolution:
        return await self.resolve_key(did_aw)

    async def publish_encryption_key(
        self,
        did_aw: str,
        assertion: dict[str, Any],
    ) -> dict[str, Any]:
        return await self._request_json(
            "POST",
            f"/v1/did/{did_aw}/encryption-key",
            json=assertion,
        )

    async def rotate_key(
        self,
        did_aw: str,
        new_did_key: str,
        old_signing_key: bytes,
        new_signing_key: bytes,
    ) -> DIDMapping:
        old_did_key = _did_key_from_signing_key(old_signing_key)
        if _did_key_from_signing_key(new_signing_key) != new_did_key:
            raise ValueError("new_signing_key must match new_did_key")

        current_mapping = await self.get_mapping(did_aw, old_signing_key)
        if current_mapping.current_did_key != old_did_key:
            raise ValueError("old_signing_key does not match the current did:key")

        key_resolution = await self.resolve_key(did_aw)
        if key_resolution.log_head is None:
            raise ValueError("DID registry response is missing log_head")

        timestamp = _utc_timestamp()
        seq = key_resolution.log_head.seq + 1
        prev_entry_hash = key_resolution.log_head.entry_hash
        next_state_hash = identity_state_hash(did_aw=did_aw, current_did_key=new_did_key)
        signature = sign_message(
            old_signing_key,
            log_entry_payload(
                did_aw=did_aw,
                seq=seq,
                operation="rotate_key",
                previous_did_key=old_did_key,
                new_did_key=new_did_key,
                prev_entry_hash=prev_entry_hash,
                state_hash=next_state_hash,
                authorized_by=old_did_key,
                timestamp=timestamp,
            ),
        )
        await self._request_json(
            "PUT",
            f"/v1/did/{did_aw}",
            json={
                "operation": "rotate_key",
                "new_did_key": new_did_key,
                "seq": seq,
                "prev_entry_hash": prev_entry_hash,
                "state_hash": next_state_hash,
                "authorized_by": old_did_key,
                "timestamp": timestamp,
                "signature": signature,
            },
        )
        return await self.get_mapping(did_aw, new_signing_key)

    async def register_namespace(
        self,
        domain: str,
        controller_did: str,
        controller_signing_key: bytes,
        parent_signing_key: bytes | None = None,
        default_delivery_origin: str | None = None,
    ) -> Namespace:
        registry_url = await self._registry_url_for_domain(domain)
        _assert_signing_key_matches(controller_did, controller_signing_key)
        default_delivery_origin = _canonical_optional_origin(default_delivery_origin)
        extra_payload = (
            {"default_delivery_origin": default_delivery_origin}
            if default_delivery_origin is not None
            else None
        )
        headers = self._signed_namespace_headers(
            domain=domain,
            operation="register",
            signing_key=controller_signing_key,
            extra_payload=extra_payload,
        )
        if parent_signing_key is not None:
            headers.update(
                self._signed_parent_namespace_registration_headers(
                    parent_signing_key=parent_signing_key,
                    child_domain=domain,
                    controller_did=controller_did,
                )
            )
        return _namespace_from_json(
            await self._request_json(
                "POST",
                "/v1/namespaces",
                headers=headers,
                json={
                    "domain": domain,
                    "controller_did": controller_did,
                    **(
                        {}
                        if default_delivery_origin is None
                        else {"default_delivery_origin": default_delivery_origin}
                    ),
                },
                registry_url=registry_url,
            )
        )

    async def get_namespace(self, domain: str) -> Namespace | None:
        data = await self._request_optional_json(
            "GET",
            f"/v1/namespaces/{domain}",
            registry_url=await self._registry_url_for_domain(domain),
        )
        return None if data is None else _namespace_from_json(data)

    async def get_namespace_fresh(self, domain: str) -> Namespace | None:
        """Read current namespace authority without a stale cache result."""
        return await self.get_namespace(domain)

    async def update_namespace_delivery_origin(
        self,
        domain: str,
        controller_signing_key: bytes,
        default_delivery_origin: str | None,
    ) -> Namespace:
        registry_url = await self._registry_url_for_domain(domain)
        default_delivery_origin = _canonical_optional_origin(default_delivery_origin)
        signed_origin = default_delivery_origin or ""
        return _namespace_from_json(
            await self._request_json(
                "PATCH",
                f"/v1/namespaces/{domain}",
                headers=self._signed_namespace_headers(
                    domain=domain,
                    operation="update_namespace",
                    signing_key=controller_signing_key,
                    extra_payload={"default_delivery_origin": signed_origin},
                ),
                json={"default_delivery_origin": default_delivery_origin},
                registry_url=registry_url,
            )
        )

    async def register_team(
        self,
        *,
        domain: str,
        name: str,
        display_name: str,
        team_did_key: str,
        visibility: str,
        namespace_controller_signing_key: bytes,
    ) -> Team:
        registry_url = await self._registry_url_for_domain(domain)
        return _team_from_json(
            await self._request_json(
                "POST",
                f"/v1/namespaces/{domain}/teams",
                headers=self._signed_team_headers(
                    domain=domain,
                    name=name,
                    operation="create_team",
                    signing_key=namespace_controller_signing_key,
                ),
                json={
                    "name": name,
                    "display_name": display_name,
                    "team_did_key": team_did_key,
                    "visibility": visibility,
                },
                registry_url=registry_url,
            )
        )

    async def set_team_visibility(
        self,
        domain: str,
        name: str,
        visibility: str,
        team_controller_signing_key: bytes,
    ) -> Team:
        """Set visibility using the team's controller, not namespace authority."""
        registry_url = await self._registry_url_for_domain(domain)
        return _team_from_json(
            await self._request_json(
                "POST",
                f"/v1/namespaces/{domain}/teams/{name}/visibility",
                headers=self._signed_namespace_headers(
                    domain=domain,
                    operation="set_team_visibility",
                    signing_key=team_controller_signing_key,
                    extra_payload={"team_name": name, "visibility": visibility},
                ),
                json={"visibility": visibility},
                registry_url=registry_url,
            )
        )

    async def delete_team(
        self,
        domain: str,
        name: str,
        namespace_controller_signing_key: bytes,
    ) -> dict[str, Any]:
        """Delete using namespace authority; active certificates must be revoked first."""
        registry_url = await self._registry_url_for_domain(domain)
        return await self._request_json(
            "DELETE",
            f"/v1/namespaces/{domain}/teams/{name}",
            headers=self._signed_namespace_headers(
                domain=domain,
                operation="delete_team",
                signing_key=namespace_controller_signing_key,
                extra_payload={"team_name": name},
            ),
            registry_url=registry_url,
        )

    async def rotate_namespace_controller(
        self,
        domain: str,
        new_controller_did: str,
        new_controller_signing_key: bytes,
        parent_signing_key: bytes | None = None,
    ) -> Namespace:
        registry_url = await self._registry_url_for_domain(domain)
        _assert_signing_key_matches(new_controller_did, new_controller_signing_key)
        headers = self._signed_namespace_headers(
            domain=domain,
            operation="rotate_controller",
            signing_key=new_controller_signing_key,
            extra_payload={"new_controller_did": new_controller_did},
        )
        if parent_signing_key is not None:
            headers.update(
                self._signed_parent_namespace_headers(
                    parent_signing_key=parent_signing_key,
                    child_domain=domain,
                    new_controller_did=new_controller_did,
                )
            )
        return _namespace_from_json(
            await self._request_json(
                "PUT",
                f"/v1/namespaces/{domain}",
                headers=headers,
                json={"new_controller_did": new_controller_did},
                registry_url=registry_url,
            )
        )

    async def register_address(
        self,
        domain: str,
        name: str,
        did_aw: str,
        controller_signing_key: bytes,
        current_did_key: str | None = None,
    ) -> Address:
        registry_url = await self._registry_url_for_domain(domain)
        if current_did_key is None:
            key_resolution = await self.resolve_key(did_aw)
            current_did_key = key_resolution.current_did_key
        return _address_from_json(
            await self._request_json(
                "POST",
                f"/v1/namespaces/{domain}/addresses",
                headers=self._signed_address_headers(
                    domain=domain,
                    name=name,
                    operation="register_address",
                    signing_key=controller_signing_key,
                ),
                json={
                    "name": name,
                    "did_aw": did_aw,
                    "current_did_key": current_did_key,
                },
                registry_url=registry_url,
            )
        )

    async def resolve_address(
        self,
        domain: str,
        name: str,
        *,
        signing_key: bytes | None = None,
        did_key: str | None = None,
    ) -> Address | None:
        data = await self._request_optional_json(
            "GET",
            f"/v1/namespaces/{domain}/addresses/{name}",
            registry_url=await self._registry_url_for_domain(domain),
        )
        return None if data is None else _address_from_json(data)

    async def resolve_address_fresh(
        self,
        domain: str,
        name: str,
        *,
        signing_key: bytes | None = None,
        did_key: str | None = None,
    ) -> Address | None:
        """Read current address authority without a stale cache result."""
        return await self.resolve_address(
            domain,
            name,
            signing_key=signing_key,
            did_key=did_key,
        )

    async def list_addresses(
        self,
        domain: str,
        *,
        signing_key: bytes | None = None,
        did_key: str | None = None,
    ) -> list[Address]:
        data = await self._request_json(
            "GET",
            f"/v1/namespaces/{domain}/addresses",
            registry_url=await self._registry_url_for_domain(domain),
        )
        return [_address_from_json(item) for item in data.get("addresses", [])]

    async def get_team_public_key(self, domain: str, name: str) -> str | None:
        """Fetch the team's public did:key from awid.

        GET /v1/namespaces/{domain}/teams/{name}
        Returns team_did_key or None if team not found.
        """
        team = await self.get_team(domain, name)
        if team is None:
            return None
        return team.team_did_key

    async def get_team_public_key_fresh(self, domain: str, name: str) -> str | None:
        """Read current team authority, without cached or outage-grace data."""
        # Bind to the HTTP implementation: self.get_team() can dispatch to
        # CachedRegistryClient's stale-while-revalidate path.
        team = await RegistryClient.get_team(self, domain, name)
        return team.team_did_key if team is not None else None

    async def get_team(self, domain: str, name: str) -> Team | None:
        """Fetch team metadata from awid."""
        data = await self._request_optional_json(
            "GET",
            f"/v1/namespaces/{domain}/teams/{name}",
            registry_url=await self._registry_url_for_domain(domain),
        )
        if data is None:
            return None
        return _team_from_json(data)

    async def get_team_fresh(self, domain: str, name: str) -> Team | None:
        """Read the team's current metadata, its controller key included,
        without a stale cache result."""
        return await self.get_team(domain, name)

    async def get_team_server_record(self, domain: str, name: str) -> dict[str, Any] | None:
        """Read the signed envelope, or None on 404; the caller verifies current team authority."""
        return await self._request_optional_json(
            "GET",
            f"/v1/namespaces/{domain}/teams/{name}/server",
            registry_url=await self._registry_url_for_domain(domain),
        )

    async def publish_team_server_record(
        self, domain: str, name: str, record: dict[str, Any], signature: str,
    ) -> dict[str, Any]:
        """PUT a team-key-signed envelope; registry refusals raise RegistryError."""
        return await self._request_json(
            "PUT",
            f"/v1/namespaces/{domain}/teams/{name}/server",
            json={"record": record, "signature": signature},
            registry_url=await self._registry_url_for_domain(domain),
        )

    async def get_team_revocations(self, domain: str, name: str) -> set[str]:
        """Fetch the complete set of revoked certificate IDs for a team.

        GET /v1/namespaces/{domain}/teams/{name}/revocations

        Completeness is the contract (aweb-abfo): verifiers treat the returned
        set as the whole revocation state, so this pages with the server's
        cursor until has_more is false. Against an old server that sends no
        has_more (and ignored pagination while truncating at its oldest-first
        hard limit), fall back to timestamp paging with `since` until a page
        adds nothing new — best effort, strictly better than reading one
        truncated page as complete.
        """
        return (await self._scan_team_revocations(domain, name)).certificate_ids

    async def get_team_revocations_fresh(self, domain: str, name: str) -> set[str]:
        """Read the complete live revocation set; propagate any registry failure."""
        return await RegistryClient.get_team_revocations(self, domain, name)

    async def _scan_team_revocations(
        self,
        domain: str,
        name: str,
        *,
        since: str | None = None,
    ) -> _RevocationScan:
        """Page through the revocations route and report what was read.

        With ``since`` this reads only the tail of the list; without it, the
        whole list. Either way the walk is all-or-nothing: any failure other
        than a 404 propagates, so a caller never observes a partial
        page-through and can never mistake one for current data.
        """
        registry_url = await self._registry_url_for_domain(domain)
        base_path = f"/v1/namespaces/{domain}/teams/{name}/revocations"
        revoked: set[str] = set()
        newest: datetime | None = None
        all_timestamped = True
        cursor: str | None = None
        legacy_since: str | None = since
        while True:
            query = "limit=200"
            if cursor is not None:
                query += f"&cursor={quote(cursor, safe='')}"
            elif legacy_since is not None:
                query += f"&since={quote(legacy_since, safe='')}"
            try:
                data = await self._request_json(
                    "GET",
                    f"{base_path}?{query}",
                    registry_url=registry_url,
                )
            except RegistryError as exc:
                if exc.status_code == 404:
                    return _RevocationScan(revoked, newest, all_timestamped, True)
                raise
            entries = data.get("revocations", [])
            before = len(revoked)
            revoked |= {r["certificate_id"] for r in entries}
            page_newest: datetime | None = None
            for entry in entries:
                parsed = _parse_revoked_at(entry.get("revoked_at"))
                if parsed is None:
                    all_timestamped = False
                elif page_newest is None or parsed > page_newest:
                    page_newest = parsed
            if page_newest is not None and (newest is None or page_newest > newest):
                newest = page_newest
            if "has_more" in data:
                if not data.get("has_more") or not data.get("next_cursor"):
                    return _RevocationScan(revoked, newest, all_timestamped, False)
                cursor = data["next_cursor"]
                continue
            # Legacy server: no truncation signal. Its hard limit was 1000
            # oldest-first rows; a shorter page, or a page that added nothing
            # new, is the end. So is a page whose rows carry no usable
            # revoked_at, because there is then nothing to page forward from.
            if len(entries) < 1000 or len(revoked) == before or page_newest is None:
                return _RevocationScan(revoked, newest, all_timestamped, False)
            legacy_since = page_newest.isoformat()
            cursor = None

    async def list_team_certificates(
        self,
        domain: str,
        name: str,
        *,
        active_only: bool = True,
        signing_key: bytes | None = None,
    ) -> list[TeamCertificate]:
        active_only_value = "true" if active_only else "false"
        base_path = f"/v1/namespaces/{domain}/teams/{name}/certificates"
        registry_url = await self._registry_url_for_domain(domain)
        headers = (
            self._signed_path_headers("GET", base_path, signing_key)
            if signing_key is not None
            else None
        )
        certificates: list[TeamCertificate] = []
        cursor: str | None = None
        seen_cursors: set[str] = set()
        while True:
            query = f"active_only={active_only_value}&limit=200"
            if cursor is not None:
                query += f"&cursor={quote(cursor, safe='')}"
            data = await self._request_json(
                "GET",
                f"{base_path}?{query}",
                headers=headers,
                registry_url=registry_url,
            )
            certificates.extend(
                _team_certificate_from_json(item)
                for item in data.get("certificates", [])
            )
            if not data.get("has_more"):
                return certificates
            next_cursor = str(data.get("next_cursor") or "").strip()
            if not next_cursor or next_cursor in seen_cursors:
                raise RegistryError(
                    "AWID certificate pagination did not advance",
                    status_code=502,
                )
            seen_cursors.add(next_cursor)
            cursor = next_cursor

    async def list_team_certificates_fresh(
        self,
        domain: str,
        name: str,
        *,
        active_only: bool = True,
        signing_key: bytes | None = None,
    ) -> list[TeamCertificate]:
        """Read current certificates without stale fallback, on cached clients too."""
        return await RegistryClient.list_team_certificates(
            self, domain, name, active_only=active_only, signing_key=signing_key,
        )

    async def register_team_certificate(
        self,
        domain: str,
        name: str,
        *,
        team_controller_signing_key: bytes,
        certificate_id: str,
        member_did_key: str,
        member_did_aw: str | None,
        member_address: str | None,
        alias: str,
        identity_scope: str | None = None,
        certificate: str | None = None,
        lifetime: str | None = None,
    ) -> None:
        registry_url = await self._registry_url_for_domain(domain)
        scope_input = identity_scope if identity_scope is not None else lifetime
        scope = normalize_identity_scope(scope_input or "global")
        payload: dict[str, Any] = {
            "certificate_id": certificate_id,
            "member_did_key": member_did_key,
            "member_did_aw": member_did_aw,
            "member_address": member_address,
            "alias": alias,
            "identity_scope": scope,
        }
        if certificate is not None:
            payload["certificate"] = certificate
        await self._request_json(
            "POST",
            f"/v1/namespaces/{domain}/teams/{name}/certificates",
            headers=self._signed_namespace_headers(
                domain=domain,
                operation="register_certificate",
                signing_key=team_controller_signing_key,
                extra_payload={
                    "team_name": name,
                    "certificate_id": certificate_id,
                },
            ),
            json=payload,
            registry_url=registry_url,
        )

    async def revoke_team_certificate(
        self,
        domain: str,
        name: str,
        *,
        team_controller_signing_key: bytes,
        certificate_id: str,
    ) -> None:
        registry_url = await self._registry_url_for_domain(domain)
        await self._request_json(
            "POST",
            f"/v1/namespaces/{domain}/teams/{name}/certificates/revoke",
            headers=self._signed_namespace_headers(
                domain=domain,
                operation="revoke_certificate",
                signing_key=team_controller_signing_key,
                extra_payload={
                    "team_name": name,
                    "certificate_id": certificate_id,
                },
            ),
            json={"certificate_id": certificate_id},
            registry_url=registry_url,
        )

    async def invalidate_team_certificate_cache(self, domain: str, name: str) -> None:
        """Drop cached certificate/revocation reads for a team, if this client caches them."""
        return None

    async def update_address(
        self,
        domain: str,
        name: str,
        controller_signing_key: bytes,
    ) -> Address:
        registry_url = await self._registry_url_for_domain(domain)
        return _address_from_json(
            await self._request_json(
                "PUT",
                f"/v1/namespaces/{domain}/addresses/{name}",
                headers=self._signed_address_headers(
                    domain=domain,
                    name=name,
                    operation="update_address",
                    signing_key=controller_signing_key,
                ),
                json={},
                registry_url=registry_url,
            )
        )

    async def delete_address(
        self,
        domain: str,
        name: str,
        controller_signing_key: bytes,
    ) -> None:
        registry_url = await self._registry_url_for_domain(domain)
        await self._request_json(
            "DELETE",
            f"/v1/namespaces/{domain}/addresses/{name}",
            headers=self._signed_address_headers(
                domain=domain,
                name=name,
                operation="delete_address",
                signing_key=controller_signing_key,
            ),
            registry_url=registry_url,
        )

    async def list_did_addresses(self, did_aw: str) -> list[Address]:
        data = await self._request_json("GET", f"/v1/did/{did_aw}/addresses")
        return [_address_from_json(item) for item in data.get("addresses", [])]

    async def reassign_address(
        self,
        domain: str,
        name: str,
        new_did_aw: str,
        controller_signing_key: bytes,
    ) -> Address:
        registry_url = await self._registry_url_for_domain(domain)
        key_resolution = await self.resolve_key(new_did_aw)
        return _address_from_json(
            await self._request_json(
                "POST",
                f"/v1/namespaces/{domain}/addresses/{name}/reassign",
                headers=self._signed_address_headers(
                    domain=domain,
                    name=name,
                    operation="reassign_address",
                    signing_key=controller_signing_key,
                ),
                json={
                    "did_aw": new_did_aw,
                    "current_did_key": key_resolution.current_did_key,
                },
                registry_url=registry_url,
            )
        )

    def _signed_path_headers(self, method: str, path: str, signing_key: bytes) -> dict[str, str]:
        timestamp = _utc_timestamp()
        payload = f"{timestamp}\n{method}\n{path}".encode("utf-8")
        return {
            "Authorization": f"DIDKey {_did_key_from_signing_key(signing_key)} {sign_message(signing_key, payload)}",
            "X-AWEB-Timestamp": timestamp,
        }

    def _signed_namespace_headers(
        self,
        *,
        domain: str,
        operation: str,
        signing_key: bytes,
        extra_payload: dict[str, Any] | None = None,
    ) -> dict[str, str]:
        timestamp = _utc_timestamp()
        payload_dict: dict[str, Any] = {
            "domain": domain,
            "operation": operation,
            "timestamp": timestamp,
        }
        if extra_payload:
            payload_dict.update(extra_payload)
        payload = canonical_json_bytes(payload_dict)
        return {
            "Authorization": f"DIDKey {_did_key_from_signing_key(signing_key)} {sign_message(signing_key, payload)}",
            "X-AWEB-Timestamp": timestamp,
        }

    def _signed_address_headers(
        self,
        *,
        domain: str,
        name: str,
        operation: str,
        signing_key: bytes,
    ) -> dict[str, str]:
        timestamp = _utc_timestamp()
        payload = canonical_json_bytes(
            {
                "domain": domain,
                "name": name,
                "operation": operation,
                "timestamp": timestamp,
            }
        )
        return {
            "Authorization": f"DIDKey {_did_key_from_signing_key(signing_key)} {sign_message(signing_key, payload)}",
            "X-AWEB-Timestamp": timestamp,
        }

    def _signed_team_headers(
        self,
        *,
        domain: str,
        name: str,
        operation: str,
        signing_key: bytes,
    ) -> dict[str, str]:
        timestamp = _utc_timestamp()
        payload = canonical_json_bytes(
            {
                "domain": domain,
                "name": name,
                "operation": operation,
                "timestamp": timestamp,
            }
        )
        return {
            "Authorization": f"DIDKey {_did_key_from_signing_key(signing_key)} {sign_message(signing_key, payload)}",
            "X-AWEB-Timestamp": timestamp,
        }

    def _signed_parent_namespace_headers(
        self,
        *,
        parent_signing_key: bytes,
        child_domain: str,
        new_controller_did: str,
    ) -> dict[str, str]:
        timestamp = _utc_timestamp()
        payload = canonical_json_bytes(
            {
                "domain": child_domain,
                "child_domain": child_domain,
                "new_controller_did": new_controller_did,
                "operation": "authorize_subdomain_rotation",
                "timestamp": timestamp,
            }
        )
        return {
            "X-AWEB-Parent-Authorization": (
                f"DIDKey {_did_key_from_signing_key(parent_signing_key)} "
                f"{sign_message(parent_signing_key, payload)}"
            ),
            "X-AWEB-Parent-Timestamp": timestamp,
        }

    def _signed_parent_namespace_registration_headers(
        self,
        *,
        parent_signing_key: bytes,
        child_domain: str,
        controller_did: str,
    ) -> dict[str, str]:
        timestamp = _utc_timestamp()
        payload = canonical_json_bytes(
            {
                "domain": child_domain,
                "child_domain": child_domain,
                "controller_did": controller_did,
                "operation": "authorize_subdomain_registration",
                "timestamp": timestamp,
            }
        )
        return {
            "X-AWEB-Parent-Authorization": (
                f"DIDKey {_did_key_from_signing_key(parent_signing_key)} "
                f"{sign_message(parent_signing_key, payload)}"
            ),
            "X-AWEB-Parent-Timestamp": timestamp,
        }


class CachedRegistryClient(RegistryClient):
    """Redis-backed caching wrapper for RegistryClient reads."""

    redis_client: Redis
    _refresh_tasks: dict[str, asyncio.Task[None]]
    _domain_verifier: DomainVerifier | None
    _id_status_refreshes: dict[str, asyncio.Task[_IDStatusRefresh]]
    _id_status_failed_at: dict[str, int]

    def __init__(
        self,
        registry_url: str,
        redis_client: Redis,
        *,
        timeout_seconds: float = 5.0,
        transport: httpx.AsyncBaseTransport | None = None,
        base_url: str | None = None,
        domain_registry_resolver: DomainRegistryResolver | None = None,
        service_token: str | None = None,
        domain_verifier: DomainVerifier | None = None,
    ) -> None:
        super().__init__(
            registry_url=registry_url,
            timeout_seconds=timeout_seconds,
            transport=transport,
            base_url=base_url,
            domain_registry_resolver=domain_registry_resolver,
            service_token=service_token,
        )
        object.__setattr__(self, "redis_client", redis_client)
        object.__setattr__(self, "_refresh_tasks", {})
        object.__setattr__(self, "_domain_verifier", domain_verifier)
        object.__setattr__(self, "_id_status_refreshes", {})
        object.__setattr__(self, "_id_status_failed_at", {})

    async def id_chain_evidence(
        self, bundle: dict[str, Any] | None, subject: dict[str, Any], *, domain: str,
    ) -> IDChainEvidence:
        """Trusted identity-tree evidence for verifying ``subject``'s chain in ``domain``.

        A stored entry is aged on the Redis server's clock, the one clock
        every process sharing it reads. Evidence aged 60 seconds or less is
        served with no DNS or HTTP work. Older evidence waits for one refresh
        shared by every caller of the same request; when that attempt fails,
        the last-known-good evidence is returned with its age and
        refresh_failed set, and with none it is returned without an age.
        Fetch failures never raise.
        """
        try:
            request = status_request(bundle, subject, domain=domain)
        except IDCertificateError:
            request = None
        if request is None:
            # The verifier refuses this request before it reads any evidence.
            return IDChainEvidence(status={}, namespace_authority={}, age_seconds=None)
        cache_key = self._id_status_cache_key(request)
        read_at = _cache_now()
        redis_now, cached = await self._read_id_status_entry(cache_key)
        if cached is not None and redis_now < cached["fetched_at"]:
            # Stamped ahead of the Redis clock (it stepped back): its age is
            # unknown, so it is neither fresh nor last-known-good.
            cached = None
        if cached is not None and redis_now - cached["fetched_at"] <= _ID_STATUS_FRESH_SECONDS:
            return _id_status_evidence(cached, age=redis_now - cached["fetched_at"], refresh_failed=False)
        refresh = await self._coalesced_id_status_refresh(cache_key, request)
        if refresh.entry is not None:
            return _id_status_evidence(refresh.entry, age=refresh.age, refresh_failed=False)
        if refresh.failed and cached is not None:
            # Aged through the wait for the failed attempt, on this process's clock.
            age = redis_now - cached["fetched_at"] + (_cache_now() - read_at)
            return _id_status_evidence(cached, age=age, refresh_failed=True)
        return IDChainEvidence(status={}, namespace_authority={}, age_seconds=None, refresh_failed=refresh.failed)

    async def _coalesced_id_status_refresh(self, cache_key: str, request: dict[str, Any]) -> _IDStatusRefresh:
        task = self._id_status_refreshes.get(cache_key)
        if task is None:
            failed_at = self._id_status_failed_at.get(request["domain"])
            if failed_at is not None and 0 <= _cache_now() - failed_at <= _ID_STATUS_FAILURE_COOLDOWN_SECONDS:
                return _IDStatusRefresh(entry=None, failed=True, age=None)
            task = asyncio.create_task(self._refresh_id_status(cache_key, request))
            self._id_status_refreshes[cache_key] = task
            task.add_done_callback(lambda _task, key=cache_key: self._id_status_refreshes.pop(key, None))
        # A cancelled caller leaves the shared attempt running for the others.
        return await asyncio.shield(task)

    async def _refresh_id_status(self, cache_key: str, request: dict[str, Any]) -> _IDStatusRefresh:
        """One attempt, with DNS authority, routing and HTTP under one timeout.

        The status and the authority it is checked against are stored as one
        entry, stamped with the Redis clock when the attempt began; the
        evidence returned now is aged by this process from that same moment.
        A malformed successful answer is not an outage: it removes the entry,
        so no older tree outlives it.
        """
        domain = request["domain"]
        started = _cache_now()
        verify_domain = self._domain_verifier
        if verify_domain is None:
            from awid.dns_verify import verify_domain
        try:
            async with asyncio.timeout(self.timeout_seconds):
                fetched_at = await self._redis_time()
                authority = await verify_domain(domain)
                status = await self.fetch_id_certificate_status(domain, request)
        except MalformedIDStatusError:
            logger.warning("AWID identity-tree status for %s is malformed; no evidence is served", domain)
            self._id_status_failed_at.pop(domain, None)
            await self._invalidate_keys(cache_key)
            return _IDStatusRefresh(entry=None, failed=False, age=None)
        except Exception as exc:
            logger.warning("AWID identity-tree status refresh failed for %s: %r", domain, exc)
            self._id_status_failed_at[domain] = _cache_now()
            return _IDStatusRefresh(entry=None, failed=True, age=None)
        self._id_status_failed_at.pop(domain, None)
        entry = {
            "fetched_at": fetched_at,
            "status": status,
            "namespace_authority": {
                "domain": domain,
                "dns_name": authority.dns_name,
                "inherited": authority.inherited,
                "controller_key": authority.controller_did,
            },
        }
        if fetched_at is not None:
            await self._redis_set(
                cache_key, json.dumps(entry, separators=(",", ":"), sort_keys=True), ex=_ID_STATUS_RETENTION_SECONDS,
            )
        return _IDStatusRefresh(entry=entry, failed=False, age=_cache_now() - started)

    async def _redis_time(self) -> int | None:
        """The Redis server clock in whole seconds, or None when Redis is unavailable."""
        try:
            seconds, _microseconds = await self.redis_client.time()
        except (RedisError, OSError):
            logger.debug("AWID cache clock read skipped because Redis is unavailable", exc_info=True)
            return None
        return int(seconds)

    async def _read_id_status_entry(self, cache_key: str) -> tuple[int, dict[str, Any] | None]:
        """The Redis clock and the stored entry, read in one round trip."""
        try:
            async with self.redis_client.pipeline(transaction=False) as pipe:
                pipe.time()
                pipe.get(cache_key)
                (seconds, _microseconds), raw = await pipe.execute()
        except (RedisError, OSError):
            logger.debug("AWID cache read skipped because Redis is unavailable", exc_info=True)
            return 0, None
        redis_now = int(seconds)
        if raw is None:
            return redis_now, None
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        try:
            entry = json.loads(raw)
            if (
                type(entry["fetched_at"]) is not int
                or not isinstance(entry["status"], dict)
                or not isinstance(entry["namespace_authority"], dict)
            ):
                raise ValueError("invalid identity-tree status entry")
        except Exception:
            logger.warning("Invalid AWID cache payload for %s; dropping entry", cache_key)
            await self._invalidate_keys(cache_key)
            return redis_now, None
        return redis_now, entry

    async def resolve_key(self, did_aw: str) -> KeyResolution:
        return await self._cached_read(
            cache_key=self._did_key_cache_key(did_aw),
            ttl_seconds=_DID_KEY_CACHE_TTL_SECONDS,
            fetcher=lambda: super(CachedRegistryClient, self).resolve_key(did_aw),
            encode=lambda value: _key_resolution_to_json(value),
            decode=lambda payload: _key_resolution_from_json(payload),
            # A resolution that does not state enrollment is never served from the cache.
            reusable=lambda value: value.id_tree is not None,
        )

    async def resolve_key_fresh(self, did_aw: str) -> KeyResolution:
        cache_key = self._did_key_cache_key(did_aw)
        await self._invalidate_keys(cache_key)
        value = await super().resolve_key(did_aw)
        await self._write_cache_entry(
            cache_key,
            value=value,
            ttl_seconds=_DID_KEY_CACHE_TTL_SECONDS,
            encode=lambda payload: _key_resolution_to_json(payload),
        )
        return value

    async def get_namespace(self, domain: str) -> Namespace | None:
        registry_url = await self._registry_url_for_domain(domain)
        return await self._cached_read(
            cache_key=self._namespace_cache_key(domain, registry_url=registry_url),
            ttl_seconds=_NAMESPACE_CACHE_TTL_SECONDS,
            fetcher=lambda: super(CachedRegistryClient, self).get_namespace(domain),
            encode=lambda value: None if value is None else _namespace_to_json(value),
            decode=lambda payload: None if payload is None else _namespace_from_json(payload),
        )

    async def get_namespace_fresh(self, domain: str) -> Namespace | None:
        registry_url = await self._registry_url_for_domain(domain)
        cache_key = self._namespace_cache_key(domain, registry_url=registry_url)
        await self._invalidate_keys(cache_key)
        value = await super().get_namespace(domain)
        await self._write_cache_entry(
            cache_key,
            value=value,
            ttl_seconds=_NAMESPACE_CACHE_TTL_SECONDS,
            encode=lambda payload: (
                None if payload is None else _namespace_to_json(payload)
            ),
        )
        return value

    async def list_addresses(
        self,
        domain: str,
        *,
        signing_key: bytes | None = None,
        did_key: str | None = None,
    ) -> list[Address]:
        registry_url = await self._registry_url_for_domain(domain)
        caller_did_key = None
        return await self._cached_read(
            cache_key=self._domain_addresses_cache_key(domain, registry_url=registry_url, caller_did_key=caller_did_key),
            ttl_seconds=_ADDRESS_CACHE_TTL_SECONDS,
            fetcher=lambda: super(CachedRegistryClient, self).list_addresses(
                domain,
                signing_key=signing_key,
                did_key=caller_did_key,
            ),
            encode=lambda value: [_address_to_json(item) for item in value],
            decode=lambda payload: [_address_from_json(item) for item in payload],
        )

    async def resolve_address(
        self,
        domain: str,
        name: str,
        *,
        signing_key: bytes | None = None,
        did_key: str | None = None,
    ) -> Address | None:
        registry_url = await self._registry_url_for_domain(domain)
        caller_did_key = None
        return await self._cached_read(
            cache_key=self._address_cache_key(domain, name, registry_url=registry_url, caller_did_key=caller_did_key),
            ttl_seconds=_ADDRESS_CACHE_TTL_SECONDS,
            fetcher=lambda: super(CachedRegistryClient, self).resolve_address(
                domain,
                name,
                signing_key=signing_key,
                did_key=caller_did_key,
            ),
            encode=lambda value: None if value is None else _address_to_json(value),
            decode=lambda payload: None if payload is None else _address_from_json(payload),
        )

    async def resolve_address_fresh(
        self,
        domain: str,
        name: str,
        *,
        signing_key: bytes | None = None,
        did_key: str | None = None,
    ) -> Address | None:
        registry_url = await self._registry_url_for_domain(domain)
        cache_key = self._address_cache_key(
            domain,
            name,
            registry_url=registry_url,
            caller_did_key=None,
        )
        await self._invalidate_keys(cache_key)
        value = await super().resolve_address(
            domain,
            name,
            signing_key=signing_key,
            did_key=None,
        )
        await self._write_cache_entry(
            cache_key,
            value=value,
            ttl_seconds=_ADDRESS_CACHE_TTL_SECONDS,
            encode=lambda payload: (
                None if payload is None else _address_to_json(payload)
            ),
        )
        return value

    async def list_did_addresses(self, did_aw: str) -> list[Address]:
        return await self._cached_read(
            cache_key=self._did_addresses_cache_key(did_aw),
            ttl_seconds=_ADDRESS_CACHE_TTL_SECONDS,
            fetcher=lambda: super(CachedRegistryClient, self).list_did_addresses(did_aw),
            encode=lambda value: [_address_to_json(item) for item in value],
            decode=lambda payload: [_address_from_json(item) for item in payload],
        )

    async def get_team_public_key(self, domain: str, name: str) -> str | None:
        """Read controller authority with the revocation freshness/grace bounds.

        Refresh synchronously after freshness expires. Team metadata's longer
        TTL and stale-while-revalidate path must never authorize a controller.
        """
        cache_key = self._team_public_key_cache_key(domain, name)
        ttl_seconds = _TEAM_REVOCATIONS_CACHE_TTL_SECONDS
        grace_seconds = _TEAM_REVOCATIONS_OUTAGE_GRACE_SECONDS
        cached = await self._read_cache_entry(cache_key, decode=lambda value: value)
        fetched_at = _cache_entry_fetched_at(cached, ttl_seconds) if cached is not None else None
        if (
            cached is not None and fetched_at is not None
            and max(0, _cache_now() - fetched_at) < ttl_seconds
        ):
            return cached["value"]
        try:
            # Bind to HTTP, bypassing get_team's metadata cache entirely.
            team = await RegistryClient.get_team(self, domain, name)
        except Exception as exc:
            age = max(0, _cache_now() - fetched_at) if fetched_at is not None else None
            if cached is not None and age is not None and age <= grace_seconds:
                logger.warning(
                    "AWID team key refresh failed for team %s/%s; "
                    "serving last-known-good team key aged %ds "
                    "(outage grace bound %ds): %s",
                    domain, name, age, grace_seconds, exc,
                )
                return cached["value"]
            raise
        key = team.team_did_key if team is not None else None
        if not key:
            # A successful not-found read replaces prior authority; it is not
            # an outage and must not let that old key reappear during grace.
            await self._invalidate_keys(cache_key)
            return None
        await self._write_cache_entry(
            cache_key, value=key, ttl_seconds=ttl_seconds,
            encode=lambda value: value,
            retention_seconds=ttl_seconds + grace_seconds,
        )
        return key

    async def get_team(self, domain: str, name: str) -> Team | None:
        return await self._cached_read(
            cache_key=self._team_metadata_cache_key(domain, name),
            ttl_seconds=_TEAM_METADATA_CACHE_TTL_SECONDS,
            fetcher=lambda: super(CachedRegistryClient, self).get_team(domain, name),
            encode=lambda value: None if value is None else _team_to_json(value),
            decode=lambda payload: None if payload is None else _team_from_json(payload),
        )

    async def get_team_fresh(self, domain: str, name: str) -> Team | None:
        cache_key = self._team_metadata_cache_key(domain, name)
        await self._invalidate_keys(cache_key)
        value = await super().get_team(domain, name)
        await self._write_cache_entry(
            cache_key,
            value=value,
            ttl_seconds=_TEAM_METADATA_CACHE_TTL_SECONDS,
            encode=lambda payload: None if payload is None else _team_to_json(payload),
        )
        return value

    async def get_team_revocations(self, domain: str, name: str) -> set[str]:
        # Revocations get a dedicated read path rather than _cached_read: they
        # and controller keys have an outage grace (see
        # _TEAM_REVOCATIONS_OUTAGE_GRACE_SECONDS). Freshness, staleness, and
        # grace are all decided on the age of the cached data (its stored fetch
        # timestamp), never on Redis expiry alone.
        cache_key = self._team_revocations_cache_key(domain, name)
        ttl_seconds = _TEAM_REVOCATIONS_CACHE_TTL_SECONDS
        retention_seconds = ttl_seconds + _TEAM_REVOCATIONS_OUTAGE_GRACE_SECONDS

        cached = await self._read_cache_entry(cache_key, decode=lambda payload: set(payload))
        # Refresh the complete paginated set. A timestamp-only high-water mark
        # cannot safely order commits: PostgreSQL NOW() is transaction-start
        # time, so a revocation that waited on a row lock can commit after our
        # read with an older timestamp and be missed by an incremental `since`.
        fetcher = lambda: super(CachedRegistryClient, self).get_team_revocations(
            domain, name
        )
        encode = lambda value: sorted(value)
        cached_age: int | None = None
        if cached is not None:
            fetched_at = _cache_entry_fetched_at(cached, ttl_seconds)
            cached_age = max(0, _cache_now() - fetched_at)
            if cached["fresh"]:
                return cached["value"]
            if cached_age <= ttl_seconds * _STALE_MULTIPLIER:
                # Stale-while-revalidate, as before — but a failed background
                # refresh is now loud instead of a swallowed debug line.
                def _on_refresh_failure(exc: BaseException) -> None:
                    logger.warning(
                        "AWID revocation refresh failed for team %s/%s; "
                        "serving last-known-good revocation set aged %ds "
                        "(outage grace bound %ds): %s",
                        domain,
                        name,
                        max(0, _cache_now() - fetched_at),
                        _TEAM_REVOCATIONS_OUTAGE_GRACE_SECONDS,
                        exc,
                    )

                if self._schedule_refresh(
                    cache_key=cache_key,
                    ttl_seconds=ttl_seconds,
                    fetcher=fetcher,
                    encode=encode,
                    retention_seconds=retention_seconds,
                    on_failure=_on_refresh_failure,
                ):
                    return cached["value"]

        try:
            fresh_value = await fetcher()
        except Exception as exc:
            if (
                cached is not None
                and cached_age is not None
                and cached_age <= _TEAM_REVOCATIONS_OUTAGE_GRACE_SECONDS
            ):
                logger.warning(
                    "AWID revocation refresh failed for team %s/%s; "
                    "serving last-known-good revocation set aged %ds "
                    "(outage grace bound %ds): %s",
                    domain,
                    name,
                    cached_age,
                    _TEAM_REVOCATIONS_OUTAGE_GRACE_SECONDS,
                    exc,
                )
                return cached["value"]
            # Beyond the grace (or nothing cached): fail closed, exactly as
            # before the grace existed — the enforcement path sees the failure.
            raise
        # Reached only when the refresh completed: a scan is all-or-nothing, so
        # fetched_at is stamped here only for data that is genuinely current as
        # of now. A refresh that failed part-way raised above and left the
        # entry — and therefore its age — untouched.
        await self._write_cache_entry(
            cache_key,
            value=fresh_value,
            ttl_seconds=ttl_seconds,
            encode=encode,
            retention_seconds=retention_seconds,
        )
        return set(fresh_value)

    async def list_team_certificates(
        self,
        domain: str,
        name: str,
        *,
        active_only: bool = True,
        signing_key: bytes | None = None,
    ) -> list[TeamCertificate]:
        # This tier is security-relevant: the server's staged existence check
        # (AWEB_REQUIRE_REGISTERED_CERTIFICATES) reads through it on every
        # authenticated request, so a failed background refresh degrades
        # enforcement input exactly as a failed revocation refresh does, and is
        # logged as loudly. Retention is unchanged: no grace, no widened TTL —
        # this is a logging-parity change only.
        def _on_refresh_failure(exc: BaseException, age_seconds: int) -> None:
            logger.warning(
                "AWID team-certificate refresh failed for team %s/%s; "
                "serving last-known-good certificate list aged %ds "
                "(stale-serve bound %ds): %s",
                domain,
                name,
                age_seconds,
                _TEAM_CERTIFICATES_CACHE_TTL_SECONDS * _STALE_MULTIPLIER,
                exc,
            )

        return await self._cached_read(
            cache_key=self._team_certificates_cache_key(
                domain,
                name,
                active_only=active_only,
                signing_key=signing_key,
            ),
            ttl_seconds=_TEAM_CERTIFICATES_CACHE_TTL_SECONDS,
            fetcher=lambda: super(CachedRegistryClient, self).list_team_certificates(
                domain,
                name,
                active_only=active_only,
                signing_key=signing_key,
            ),
            encode=lambda value: [_team_certificate_to_json(item) for item in value],
            decode=lambda payload: [_team_certificate_from_json(item) for item in payload],
            on_refresh_failure=_on_refresh_failure,
        )

    async def register_team_certificate(
        self,
        domain: str,
        name: str,
        *,
        team_controller_signing_key: bytes,
        certificate_id: str,
        member_did_key: str,
        member_did_aw: str | None,
        member_address: str | None,
        alias: str,
        identity_scope: str | None = None,
        certificate: str | None = None,
        lifetime: str | None = None,
    ) -> None:
        await self._invalidate_team_certificate_cache_keys(
            domain,
            name,
            tolerate_unavailable=True,
        )
        await super().register_team_certificate(
            domain,
            name,
            team_controller_signing_key=team_controller_signing_key,
            certificate_id=certificate_id,
            member_did_key=member_did_key,
            member_did_aw=member_did_aw,
            member_address=member_address,
            alias=alias,
            identity_scope=identity_scope,
            certificate=certificate,
            lifetime=lifetime,
        )
        await self._invalidate_team_certificate_cache_keys(
            domain,
            name,
            tolerate_unavailable=True,
        )

    async def revoke_team_certificate(
        self,
        domain: str,
        name: str,
        *,
        team_controller_signing_key: bytes,
        certificate_id: str,
    ) -> None:
        certificate_cache_keys = await self._team_certificate_cache_keys(
            domain,
            name,
            tolerate_unavailable=True,
        )
        await self._invalidate_keys(
            *certificate_cache_keys,
            self._team_revocations_cache_key(domain, name),
        )
        await super().revoke_team_certificate(
            domain,
            name,
            team_controller_signing_key=team_controller_signing_key,
            certificate_id=certificate_id,
        )
        await self._invalidate_team_certificate_cache_keys(
            domain,
            name,
            tolerate_unavailable=True,
        )
        await self._invalidate_keys(self._team_revocations_cache_key(domain, name))

    async def invalidate_team_certificate_cache(self, domain: str, name: str) -> None:
        try:
            await self._invalidate_team_certificate_cache_keys(domain, name)
        finally:
            await self._invalidate_keys(
                self._team_revocations_cache_key(domain, name),
                self._team_public_key_cache_key(domain, name),
            )

    async def register_did(
        self,
        did_key: str,
        signing_key: bytes,
    ) -> DIDMapping:
        did_aw = stable_id_from_did_key(did_key)
        await self._invalidate_keys(self._did_key_cache_key(did_aw))
        mapping = await super().register_did(did_key, signing_key)
        await self._invalidate_keys(self._did_key_cache_key(mapping.did_aw))
        return mapping

    async def rotate_key(
        self,
        did_aw: str,
        new_did_key: str,
        old_signing_key: bytes,
        new_signing_key: bytes,
    ) -> DIDMapping:
        await self._invalidate_keys(self._did_key_cache_key(did_aw))
        mapping = await super().rotate_key(did_aw, new_did_key, old_signing_key, new_signing_key)
        await self._invalidate_keys(self._did_key_cache_key(did_aw))
        return mapping

    async def register_namespace(
        self,
        domain: str,
        controller_did: str,
        controller_signing_key: bytes,
        parent_signing_key: bytes | None = None,
        default_delivery_origin: str | None = None,
    ) -> Namespace:
        await self._invalidate_namespace_cache(domain)
        namespace = await super().register_namespace(
            domain,
            controller_did,
            controller_signing_key,
            parent_signing_key,
            default_delivery_origin,
        )
        await self._invalidate_namespace_cache(domain)
        return namespace

    async def update_namespace_delivery_origin(
        self,
        domain: str,
        controller_signing_key: bytes,
        default_delivery_origin: str | None,
    ) -> Namespace:
        await self._invalidate_namespace_cache(domain)
        namespace = await super().update_namespace_delivery_origin(
            domain,
            controller_signing_key,
            default_delivery_origin,
        )
        await self._invalidate_namespace_cache(domain)
        return namespace

    async def register_team(
        self,
        *,
        domain: str,
        name: str,
        display_name: str,
        team_did_key: str,
        visibility: str,
        namespace_controller_signing_key: bytes,
    ) -> Team:
        await self._invalidate_keys(
            self._team_metadata_cache_key(domain, name),
            self._team_revocations_cache_key(domain, name),
        )
        team = await super().register_team(
            domain=domain,
            name=name,
            display_name=display_name,
            team_did_key=team_did_key,
            visibility=visibility,
            namespace_controller_signing_key=namespace_controller_signing_key,
        )
        await self._invalidate_keys(
            self._team_metadata_cache_key(domain, name),
            self._team_revocations_cache_key(domain, name),
        )
        return team

    async def set_team_visibility(
        self,
        domain: str,
        name: str,
        visibility: str,
        team_controller_signing_key: bytes,
    ) -> Team:
        cache_key = self._team_metadata_cache_key(domain, name)
        await self._invalidate_keys(cache_key)
        team = await super().set_team_visibility(domain, name, visibility, team_controller_signing_key)
        await self._invalidate_keys(cache_key)
        return team

    async def delete_team(
        self,
        domain: str,
        name: str,
        namespace_controller_signing_key: bytes,
    ) -> dict[str, Any]:
        await self._invalidate_team_cache(domain, name)
        result = await super().delete_team(domain, name, namespace_controller_signing_key)
        await self._invalidate_team_cache(domain, name)
        return result

    async def rotate_namespace_controller(
        self,
        domain: str,
        new_controller_did: str,
        new_controller_signing_key: bytes,
        parent_signing_key: bytes | None = None,
    ) -> Namespace:
        await self._invalidate_namespace_cache(domain)
        namespace = await super().rotate_namespace_controller(
            domain,
            new_controller_did,
            new_controller_signing_key,
            parent_signing_key,
        )
        await self._invalidate_namespace_cache(domain)
        return namespace

    async def rotate_namespace_with_previous_key(
        self,
        domain: str,
        *,
        from_seq: int,
        previous_did_key: str,
        new_did_key: str,
        previous_signer: PayloadSigner,
        new_signer: PayloadSigner,
    ) -> Namespace:
        await self._invalidate_namespace_cache(domain)
        namespace = await super().rotate_namespace_with_previous_key(
            domain,
            from_seq=from_seq,
            previous_did_key=previous_did_key,
            new_did_key=new_did_key,
            previous_signer=previous_signer,
            new_signer=new_signer,
        )
        await self._invalidate_namespace_cache(domain)
        return namespace

    async def register_address(
        self,
        domain: str,
        name: str,
        did_aw: str,
        controller_signing_key: bytes,
        current_did_key: str | None = None,
    ) -> Address:
        await self._invalidate_keys(self._did_key_cache_key(did_aw))
        await self._invalidate_address_cache(domain=domain, name=name, did_aws=[])
        address = await super().register_address(
            domain,
            name,
            did_aw,
            controller_signing_key,
            current_did_key,
        )
        await self._invalidate_address_cache(domain=domain, name=name, did_aws=[address.did_aw])
        return address

    async def update_address(
        self,
        domain: str,
        name: str,
        controller_signing_key: bytes,
    ) -> Address:
        await self._invalidate_address_cache(domain=domain, name=name, did_aws=[])
        address = await super().update_address(
            domain,
            name,
            controller_signing_key,
        )
        await self._invalidate_address_cache(domain=domain, name=name, did_aws=[address.did_aw])
        return address

    async def delete_address(
        self,
        domain: str,
        name: str,
        controller_signing_key: bytes,
    ) -> None:
        registry_url = await self._registry_url_for_domain(domain)
        previous = await super().resolve_address(domain, name)
        if previous is None:
            previous = await self._peek_cached_address(
                self._address_cache_key(domain, name, registry_url=registry_url, caller_did_key=None)
            )
        await super().delete_address(domain, name, controller_signing_key)
        did_aws = [previous.did_aw] if previous is not None else []
        await self._invalidate_address_cache(domain=domain, name=name, did_aws=did_aws)

    async def reassign_address(
        self,
        domain: str,
        name: str,
        new_did_aw: str,
        controller_signing_key: bytes,
    ) -> Address:
        await self._invalidate_keys(self._did_key_cache_key(new_did_aw))
        previous = await super().resolve_address(domain, name)
        address = await super().reassign_address(domain, name, new_did_aw, controller_signing_key)
        did_aws = [address.did_aw]
        if previous is not None and previous.did_aw != address.did_aw:
            did_aws.append(previous.did_aw)
        await self._invalidate_address_cache(domain=domain, name=name, did_aws=did_aws)
        return address

    async def _cached_read(
        self,
        *,
        cache_key: str,
        ttl_seconds: int,
        fetcher: Callable[[], Awaitable[Any]],
        encode: Callable[[Any], Any],
        decode: Callable[[Any], Any],
        on_refresh_failure: Callable[[BaseException, int], None] | None = None,
        reusable: Callable[[Any], bool] | None = None,
    ) -> Any:
        # on_refresh_failure is opt-in: a tier that passes nothing keeps the
        # silent debug line _refresh_cache_entry falls back to. When given, it
        # is called with the exception and the age of the data still being
        # served, measured from the entry's stored fetch timestamp.
        # reusable, when given, decides whether a cached value may be served at
        # all; one it rejects is fetched fresh as though nothing were cached.
        cached_payload = await self._read_cache_entry(cache_key, decode=decode)
        if cached_payload is not None and reusable is not None and not reusable(cached_payload["value"]):
            cached_payload = None
        if cached_payload is not None:
            if cached_payload["fresh"]:
                return cached_payload["value"]
            on_failure: Callable[[BaseException], None] | None = None
            if on_refresh_failure is not None:
                fetched_at = _cache_entry_fetched_at(cached_payload, ttl_seconds)
                report = on_refresh_failure

                def report_refresh_failure(exc: BaseException) -> None:
                    report(exc, max(0, _cache_now() - fetched_at))

                on_failure = report_refresh_failure
            if self._schedule_refresh(
                cache_key=cache_key,
                ttl_seconds=ttl_seconds,
                fetcher=fetcher,
                encode=encode,
                on_failure=on_failure,
            ):
                return cached_payload["value"]

        fresh_value = await fetcher()
        await self._write_cache_entry(
            cache_key,
            value=fresh_value,
            ttl_seconds=ttl_seconds,
            encode=encode,
        )
        return fresh_value

    async def _read_cache_entry(
        self,
        cache_key: str,
        *,
        decode: Callable[[Any], Any],
    ) -> dict[str, Any] | None:
        raw = await self._redis_get(cache_key)
        if raw is None:
            return None
        try:
            payload = json.loads(raw)
            value = decode(payload["value"])
            return {
                "fresh": payload["fresh_until"] > _cache_now(),
                "fresh_until": payload["fresh_until"],
                "fetched_at": payload.get("fetched_at"),
                "value": value,
                # The raw payload, so a tier that stores its own bookkeeping
                # beside "value" can read it back. Tiers that store none simply
                # never look.
                "payload": payload,
            }
        except Exception:
            logger.warning("Invalid AWID cache payload for %s; dropping entry", cache_key)
            await self._invalidate_keys(cache_key)
            return None

    async def _write_cache_entry(
        self,
        cache_key: str,
        *,
        value: Any,
        ttl_seconds: int,
        encode: Callable[[Any], Any],
        retention_seconds: int | None = None,
        extra_from_value: Callable[[Any], dict[str, Any]] | None = None,
    ) -> None:
        now = _cache_now()
        entry: dict[str, Any] = {}
        if extra_from_value is not None:
            entry.update(extra_from_value(value) or {})
        # The core fields are written last so a tier's extra bookkeeping can
        # never displace them.
        entry.update(
            {
                "fetched_at": now,
                "fresh_until": now + ttl_seconds,
                "value": encode(value),
            }
        )
        payload = json.dumps(entry, separators=(",", ":"), sort_keys=True)
        if retention_seconds is None:
            retention_seconds = ttl_seconds * _STALE_MULTIPLIER
        await self._redis_set(cache_key, payload, ex=retention_seconds)

    def _schedule_refresh(
        self,
        *,
        cache_key: str,
        ttl_seconds: int,
        fetcher: Callable[[], Awaitable[Any]],
        encode: Callable[[Any], Any],
        retention_seconds: int | None = None,
        on_failure: Callable[[BaseException], None] | None = None,
        extra_from_value: Callable[[Any], dict[str, Any]] | None = None,
    ) -> bool:
        existing = self._refresh_tasks.get(cache_key)
        if existing is not None and not existing.done():
            return True
        try:
            task = asyncio.create_task(
                self._refresh_cache_entry(
                    cache_key=cache_key,
                    ttl_seconds=ttl_seconds,
                    fetcher=fetcher,
                    encode=encode,
                    retention_seconds=retention_seconds,
                    on_failure=on_failure,
                    extra_from_value=extra_from_value,
                )
            )
        except RuntimeError:
            return False
        self._refresh_tasks[cache_key] = task
        task.add_done_callback(lambda _task, key=cache_key: self._refresh_tasks.pop(key, None))
        return True

    async def _refresh_cache_entry(
        self,
        *,
        cache_key: str,
        ttl_seconds: int,
        fetcher: Callable[[], Awaitable[Any]],
        encode: Callable[[Any], Any],
        retention_seconds: int | None = None,
        on_failure: Callable[[BaseException], None] | None = None,
        extra_from_value: Callable[[Any], dict[str, Any]] | None = None,
    ) -> None:
        try:
            fresh_value = await fetcher()
            await self._write_cache_entry(
                cache_key,
                value=fresh_value,
                ttl_seconds=ttl_seconds,
                encode=encode,
                retention_seconds=retention_seconds,
                extra_from_value=extra_from_value,
            )
        except Exception as exc:
            if on_failure is not None:
                on_failure(exc)
            else:
                logger.debug("AWID cache refresh failed for %s", cache_key, exc_info=True)

    async def _peek_cached_address(self, cache_key: str) -> Address | None:
        cached_payload = await self._read_cache_entry(
            cache_key,
            decode=lambda payload: None if payload is None else _address_from_json(payload),
        )
        if cached_payload is None:
            return None
        return cached_payload["value"]

    async def _invalidate_team_cache(self, domain: str, name: str) -> None:
        certificate_keys = await self._team_certificate_cache_keys(
            domain, name, tolerate_unavailable=True,
        )
        await self._invalidate_keys(
            self._team_metadata_cache_key(domain, name),
            self._team_public_key_cache_key(domain, name),
            self._team_revocations_cache_key(domain, name),
            *certificate_keys,
        )

    async def _invalidate_namespace_cache(self, domain: str) -> None:
        registry_url = await self._registry_url_for_domain(domain)
        await self._invalidate_keys(self._namespace_cache_key(domain, registry_url=registry_url))

    async def _invalidate_address_cache(self, *, domain: str, name: str, did_aws: list[str]) -> None:
        registry_url = await self._registry_url_for_domain(domain)
        keys = [
            self._address_cache_key(domain, name, registry_url=registry_url, caller_did_key=None),
            self._domain_addresses_cache_key(domain, registry_url=registry_url, caller_did_key=None),
        ]
        keys.extend(self._did_addresses_cache_key(did_aw) for did_aw in did_aws)
        keys.extend(await self._matching_cache_keys(f"{self._address_cache_key_prefix(domain, name, registry_url=registry_url)}:*"))
        keys.extend(await self._matching_cache_keys(f"{self._domain_addresses_cache_key_prefix(domain, registry_url=registry_url)}:*"))
        await self._invalidate_keys(*keys)

    async def _invalidate_keys(self, *keys: str) -> None:
        unique_keys = tuple(dict.fromkeys(key for key in keys if key))
        if not unique_keys:
            return
        try:
            await self.redis_client.delete(*unique_keys)
        except (RedisError, OSError):
            logger.debug("AWID cache invalidation skipped because Redis is unavailable", exc_info=True)

    async def _team_certificate_cache_keys(
        self,
        domain: str,
        name: str,
        *,
        tolerate_unavailable: bool = False,
    ) -> list[str]:
        try:
            return await self._matching_cache_keys(
                f"{self._team_certificates_cache_key_prefix(domain, name)}:*"
            )
        except (RedisError, OSError):
            logger.debug(
                "AWID certificate cache key discovery failed because Redis is unavailable",
                exc_info=True,
            )
            if tolerate_unavailable:
                return []
            raise

    async def _invalidate_team_certificate_cache_keys(
        self,
        domain: str,
        name: str,
        *,
        tolerate_unavailable: bool = False,
    ) -> None:
        await self._invalidate_keys(
            *await self._team_certificate_cache_keys(
                domain,
                name,
                tolerate_unavailable=tolerate_unavailable,
            )
        )

    async def _redis_get(self, key: str) -> str | None:
        try:
            value = await self.redis_client.get(key)
        except (RedisError, OSError):
            logger.debug("AWID cache read skipped because Redis is unavailable", exc_info=True)
            return None
        if value is None:
            return None
        if isinstance(value, bytes):
            return value.decode("utf-8")
        return str(value)

    async def _redis_set(self, key: str, value: str, *, ex: int) -> None:
        try:
            await self.redis_client.set(key, value, ex=ex)
        except (RedisError, OSError):
            logger.debug("AWID cache write skipped because Redis is unavailable", exc_info=True)

    def _id_status_cache_key(self, request: dict[str, Any]) -> str:
        digest = hashlib.sha256(canonical_json_bytes(request)).hexdigest()
        return f"awid:registry_cache:v1:id_status:{request['domain']}:{digest}"

    def _did_key_cache_key(self, did_aw: str) -> str:
        return f"awid:registry_cache:v1:did_key:{self.registry_url}:{did_aw}"

    def _did_addresses_cache_key(self, did_aw: str) -> str:
        return f"awid:registry_cache:v1:did_addresses:{self.registry_url}:{did_aw}"

    def _namespace_cache_key(self, domain: str, *, registry_url: str) -> str:
        return f"awid:registry_cache:v1:namespace:{registry_url}:{domain}"

    async def _matching_cache_keys(self, pattern: str) -> list[str]:
        scan_iter = getattr(self.redis_client, "scan_iter", None)
        if scan_iter is not None:
            keys: list[str] = []
            async for key in scan_iter(match=pattern):
                if isinstance(key, bytes):
                    keys.append(key.decode("utf-8"))
                else:
                    keys.append(str(key))
            return keys
        values = getattr(self.redis_client, "values", None)
        if isinstance(values, dict):
            return [str(key) for key in values if fnmatch.fnmatch(str(key), pattern)]
        return []

    def _domain_addresses_cache_key(self, domain: str, *, registry_url: str, caller_did_key: str | None) -> str:
        return f"{self._domain_addresses_cache_key_prefix(domain, registry_url=registry_url)}:{_lookup_cache_scope(caller_did_key)}"

    def _domain_addresses_cache_key_prefix(self, domain: str, *, registry_url: str) -> str:
        return f"awid:registry_cache:v2:domain_addresses:{registry_url}:{domain}"

    def _address_cache_key(self, domain: str, name: str, *, registry_url: str, caller_did_key: str | None) -> str:
        return f"{self._address_cache_key_prefix(domain, name, registry_url=registry_url)}:{_lookup_cache_scope(caller_did_key)}"

    def _address_cache_key_prefix(self, domain: str, name: str, *, registry_url: str) -> str:
        return f"awid:registry_cache:v2:address:{registry_url}:{domain}:{name}"

    def _team_metadata_cache_key(self, domain: str, name: str) -> str:
        return f"awid:registry_cache:v2:team:{self.registry_url}:{domain}/{name}"

    def _team_revocations_cache_key(self, domain: str, name: str) -> str:
        return f"awid:registry_cache:v1:team_revocations:{self.registry_url}:{domain}/{name}"

    def _team_public_key_cache_key(self, domain: str, name: str) -> str:
        return f"awid:registry_cache:v1:team_public_key:{self.registry_url}:{domain}/{name}"

    def _team_certificates_cache_key(
        self,
        domain: str,
        name: str,
        *,
        active_only: bool,
        signing_key: bytes | None = None,
    ) -> str:
        suffix = "active" if active_only else "all"
        return (
            f"{self._team_certificates_cache_key_prefix(domain, name)}:"
            f"{suffix}:{self._team_certificates_cache_scope(signing_key)}"
        )

    def _team_certificates_cache_key_prefix(self, domain: str, name: str) -> str:
        return f"awid:registry_cache:v2:team_certificates:{self.registry_url}:{domain}/{name}"

    def _team_certificates_cache_scope(self, signing_key: bytes | None) -> str:
        if signing_key is not None:
            return _did_key_from_signing_key(signing_key)
        if self.service_token is not None:
            token_digest = hashlib.sha256(self.service_token.encode("utf-8")).hexdigest()
            return f"service-sha256:{token_digest}"
        return "anon"


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _lookup_cache_scope(caller_did_key: str | None) -> str:
    normalized = (caller_did_key or "").strip()
    return normalized or "anon"


def _cache_now() -> int:
    return int(time.time())


@dataclass(frozen=True)
class _IDStatusRefresh:
    """One status refresh: the entry and its age now, or why there is none."""

    entry: dict[str, Any] | None
    failed: bool
    age: int | None


async def _payload_signature(signer: PayloadSigner, payload: bytes, expected_key: str | None) -> tuple[str, bytes]:
    """The signer's (did:key, signature) for ``payload``, verified with the strict ID profile."""
    answer = signer(payload)
    if inspect.isawaitable(answer):
        answer = await answer
    if type(answer) is not tuple or len(answer) != 2:
        raise ValueError("signer must answer (did_key, signature)")
    did_key, signature = answer
    if expected_key is not None and did_key != expected_key:
        raise ValueError("signer answered with a key other than the one named for its role")
    try:
        verify_ed25519(did_key, payload, signature)
    except IDCertificateError as exc:
        raise ValueError(f"signer answer refused: {exc.code}") from exc
    return did_key, signature


def _id_status_evidence(entry: dict[str, Any], *, age: int, refresh_failed: bool) -> IDChainEvidence:
    # The age is never clamped: a negative one is unavailable evidence to the verifier.
    return IDChainEvidence(
        status=entry["status"],
        namespace_authority=entry["namespace_authority"],
        age_seconds=age,
        refresh_failed=refresh_failed,
    )


def _cache_entry_fetched_at(entry: dict[str, Any], ttl_seconds: int) -> int:
    """When the data in a cache entry was fetched.

    Entries written before age accounting existed carry no ``fetched_at``; their
    freshness horizon implies the fetch time. Single mechanism, so every tier
    that reports the age of what it is serving reports the same quantity.
    """
    fetched_at = entry.get("fetched_at")
    if fetched_at is None:
        return entry["fresh_until"] - ttl_seconds
    return fetched_at


def _did_key_from_signing_key(signing_key: bytes) -> str:
    key = SigningKey(signing_key)
    return did_from_public_key(bytes(key.verify_key))


def _assert_signing_key_matches(expected_did: str, signing_key: bytes) -> None:
    actual_did = _did_key_from_signing_key(signing_key)
    if actual_did != expected_did:
        raise ValueError("signing_key does not match the supplied controller_did")


def _canonical_optional_origin(origin: str | None) -> str | None:
    if origin is None:
        return None
    return canonical_server_origin(origin)


def _did_key_evidence_from_json(data: dict[str, Any] | None) -> DIDKeyEvidence | None:
    if data is None:
        return None
    return DIDKeyEvidence(
        seq=data["seq"],
        operation=data["operation"],
        previous_did_key=data.get("previous_did_key"),
        new_did_key=data["new_did_key"],
        prev_entry_hash=data.get("prev_entry_hash"),
        entry_hash=data["entry_hash"],
        state_hash=data["state_hash"],
        authorized_by=data["authorized_by"],
        signature=data["signature"],
        timestamp=data["timestamp"],
    )


def _did_mapping_from_json(data: dict[str, Any]) -> DIDMapping:
    return DIDMapping(
        did_aw=data["did_aw"],
        current_did_key=data["current_did_key"],
        created_at=data["created_at"],
        updated_at=data["updated_at"],
    )


def _key_resolution_from_json(data: dict[str, Any]) -> KeyResolution:
    return KeyResolution(
        did_aw=data["did_aw"],
        current_did_key=data["current_did_key"],
        log_head=_did_key_evidence_from_json(data.get("log_head")),
        encryption_key=data.get("encryption_key"),
        id_tree=_id_tree_enrollment(data),
    )


def _id_tree_enrollment(data: Any) -> IDTreeEnrollment | None:
    """The key resolution's stated enrollment, None when unstated; a malformed one rejects it."""
    parsed = key_response_id_tree(data)
    if parsed["state"] == "malformed":
        raise ValueError("malformed identity-tree enrollment in key resolution")
    if parsed["state"] == "unknown":
        return None
    return IDTreeEnrollment(enrolled=parsed["state"] == "enrolled", domain=parsed["domain"])


def _id_tree_enrollment_to_json(value: IDTreeEnrollment) -> dict[str, Any]:
    return {"enrolled": True, "domain": value.domain} if value.enrolled else {"enrolled": False}


def _namespace_from_json(data: dict[str, Any]) -> Namespace:
    return Namespace(
        namespace_id=data["namespace_id"],
        domain=data["domain"],
        controller_did=data.get("controller_did"),
        verification_status=data["verification_status"],
        last_verified_at=data.get("last_verified_at"),
        created_at=data["created_at"],
        default_delivery_origin=data.get("default_delivery_origin"),
    )


def _address_delivery_from_json(data: dict[str, Any] | None) -> AddressDelivery:
    if data is None:
        return AddressDelivery(origin=None)
    return AddressDelivery(
        origin=data.get("origin"),
        source=data.get("source", "namespace_default"),
    )


def _address_from_json(data: dict[str, Any]) -> Address:
    return Address(
        address_id=data["address_id"],
        domain=data["domain"],
        name=data["name"],
        did_aw=data["did_aw"],
        current_did_key=data["current_did_key"],
        created_at=data["created_at"],
        reachability=data.get("reachability", ""),
        visible_to_team_id=data.get("visible_to_team_id"),
        delivery=_address_delivery_from_json(data.get("delivery")),
    )


def _team_from_json(data: dict[str, Any]) -> Team:
    return Team(
        team_id=data["team_id"],
        domain=data["domain"],
        name=data["name"],
        display_name=data.get("display_name", ""),
        team_did_key=data["team_did_key"],
        visibility=data.get("visibility", "private"),
        created_at=data["created_at"],
    )


def _key_resolution_to_json(value: KeyResolution) -> dict[str, Any]:
    return {
        "did_aw": value.did_aw,
        "current_did_key": value.current_did_key,
        "log_head": None if value.log_head is None else asdict(value.log_head),
        # Unknown enrollment is stored as absent, exactly as a registry that did not state it.
        **({} if value.id_tree is None else {"id_tree": _id_tree_enrollment_to_json(value.id_tree)}),
    }


def _namespace_to_json(value: Namespace) -> dict[str, Any]:
    return asdict(value)


def _address_to_json(value: Address) -> dict[str, Any]:
    return asdict(value)


def _team_to_json(value: Team) -> dict[str, Any]:
    return asdict(value)


def _team_certificate_from_json(data: dict[str, Any]) -> TeamCertificate:
    return TeamCertificate(
        certificate_id=data["certificate_id"],
        member_did_key=data["member_did_key"],
        member_did_aw=data.get("member_did_aw"),
        member_address=data.get("member_address"),
        alias=data["alias"],
        identity_scope=normalize_identity_scope(data.get("identity_scope") or data.get("lifetime")),
        issued_at=data["issued_at"],
        revoked_at=data.get("revoked_at"),
    )


def _team_certificate_to_json(value: TeamCertificate) -> dict[str, Any]:
    return asdict(value)
