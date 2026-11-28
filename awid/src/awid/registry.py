"""HTTP client for the external AWID registry."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import inspect
import json
import logging
import time
from collections.abc import Mapping
from dataclasses import InitVar, asdict, dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from enum import StrEnum
from functools import partial
from json import loads as json_loads
from types import MappingProxyType
from typing import Any, Awaitable, Callable, Literal, TypedDict, cast
from urllib.parse import quote
from uuid import UUID, uuid4

import httpx
from redis.asyncio import Redis
from redis.exceptions import RedisError

from awid import revocation_cache
from awid.contract import normalize_identity_scope
from awid.controller_signing import (
    ControllerDescriptor,
    ControllerRequest,
    ControllerRequestUncertain,
    ControllerSigningContext,
    ControllerSigningError,
    atomic_claim_body,
    checked_controller_signature,
    controller_http_plan,
    parse_controller_request,
    signature_roles,
)
from awid.did import did_key_from_signing_key, validate_did
from awid.dns_verify import (
    DEFAULT_AWID_REGISTRY_URL,
    DnsLookupError,
    DnsVerificationError,
    DomainVerifier,
)
from awid.dns_verify import verify_domain as dns_verify_domain
from awid.external_authority import OriginContext
from awid.id_certificates import (
    IDCertificateError,
    IDChainEvidence,
    encode_id_chain_header,
    key_response_id_tree,
    status_request,
    verify_ed25519,
)
from awid.id_tree_requests import (
    REGISTER_OPERATION,
    REGISTER_PATH,
    REVOKE_OPERATION,
    REVOKE_PATH,
    ROTATE_OPERATION,
    covering_payload,
    register_body,
    revoke_body,
    rotate_body,
    rotate_claims,
    rotate_path,
)
from awid.log import (
    canonical_server_origin,
    identity_state_hash,
    initial_registration_entry,
    log_entry_payload,
)
from awid.ratelimit import normalize_service_token
from awid.registry_auth import RegistryRequestAuth, path_signature_headers
from awid.registry_paths import address_segment
from awid.registry_transport import RegistryOverrideTransport
from awid.registry_types import (
    DIDKeyNotFoundError as DIDKeyNotFoundError,
)
from awid.registry_types import (
    IDTreeEnrollment as IDTreeEnrollment,
)
from awid.registry_types import (
    RegistryError as RegistryError,
)
from awid.registry_types import (
    RegistryThrottled as RegistryThrottled,
)
from awid.registry_types import (
    is_address_not_found,
    is_team_not_found,
)
from awid.signature_wire import sign_bytes
from awid.signing import canonical_json_bytes, sign_message, verify_did_key_signature
from awid.team_certificate import TeamCertificateStanding as TeamCertificateStanding
from awid.team_certificate import evaluate_team_certificate_standing
from awid.team_ids import build_team_id
from awid.utc_timestamps import parse_utc_seconds

DomainRegistryResolver = Callable[[str], Awaitable[str]]
# Signs exactly the bytes it is given and answers with its did:key and the raw
# 64-byte signature, directly or awaitably, so a custodial host can finish its
# own checks before answering. No key material crosses this boundary.
PayloadSigner = Callable[[bytes], "tuple[str, bytes] | Awaitable[tuple[str, bytes]]"]

logger = logging.getLogger(__name__)

MAX_REGISTRY_RESPONSE_BYTES = 10 * 1024 * 1024
MAX_REGISTRY_ERROR_BYTES = 64 * 1024
MAX_REGISTRY_PAGES = 500


# One original timeout covers network reads and waits. Keep these aliases
# independently controllable in no-I/O tests; production uses the real clocks
# and cancellable asyncio sleep, never a blocking retry loop.
_read_retry_now = time.monotonic
_read_retry_sleep = asyncio.sleep
_READ_ATTEMPTS = 3


class _ControllerWriteInputs(TypedDict):
    """One exact request target/body reused by child and parent signatures."""

    registry_url: str
    method: str
    path: str
    body: bytes
    domain: str


def _retry_after_seconds(
    value: str | None, *, now: datetime | None = None
) -> float | None:
    """HTTP Retry-After seconds/date, finite and nonnegative, or no hint."""
    if value is None:
        return None
    value = value.strip()
    if value.isascii() and value.isdecimal():
        # Arbitrarily large valid delta-seconds must exhaust a finite budget,
        # not be misread as an absent hint and retried early.
        return min(float(value), 1e300)
    if len(value) > 128:
        return None
    try:
        stamp = parsedate_to_datetime(value)
        if stamp.tzinfo is None:
            return None
        return max(0.0, (stamp - (now or datetime.now(timezone.utc))).total_seconds())
    except (TypeError, ValueError, OverflowError):
        return None


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

    buffered_content = bytearray()
    async for chunk in response.aiter_raw(chunk_size=64 * 1024):
        if len(buffered_content) + len(chunk) > max_bytes:
            raise ValueError(f"HTTP response exceeds maximum size of {max_bytes} bytes")
        buffered_content.extend(chunk)
    return bytes(buffered_content)


_ADDRESS_CACHE_TTL_SECONDS = 5 * 60
_NAMESPACE_CACHE_TTL_SECONDS = 15 * 60
_DID_KEY_CACHE_TTL_SECONDS = 5 * 60
_TEAM_METADATA_CACHE_TTL_SECONDS = 10 * 60  # 10 minutes
# Revocations enforce membership on every authenticated messaging request.
# trust-model.md "Threat-model rulings" permits bounded client staleness;
# this TTL bounds how quickly a revocation takes effect. 60 seconds matches
# the federation authority reuse ceiling. With the stale-while-revalidate
# window below, the hard worst case is 2x this value; the cache lives in Redis
# and survives process restarts, so the TTL is the only bound.
_TEAM_REVOCATIONS_CACHE_TTL_SECONDS = 60
_TEAM_KEY_SIGNATURE_REFRESH_COOLDOWN_SECONDS = 5
_TEAM_CERTIFICATES_MISS_WINDOW_SECONDS = 5
_TEAM_CERTIFICATES_POINT_LIMIT = 16
_TEAM_CERTIFICATES_POINT_TTL_SECONDS = 60
_TEAM_CERTIFICATES_NEGATIVE_TTL_SECONDS = 2

# The existing per-team lease also holds the number of point reads. Claiming
# a list window and spending a point slot are serialized across workers.
_TEAM_CERTIFICATE_READ_ADMISSION = """
local used = redis.call('GET', KEYS[1])
if not used then
    redis.call('SET', KEYS[1], 0, 'EX', ARGV[1])
    return -1
end
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 0 then
    return redis.error_reply('certificate refresh window has no expiry')
end
if ARGV[3] == '1' and tonumber(used) < tonumber(ARGV[2]) then
    redis.call('INCR', KEYS[1])
    return 0
end
return ttl + 1
"""

# Team-controller keys share this freshness bound, with synchronous refresh.
# Registry-outage grace adopted for revocations (Juan 2026-08-17; see
# trust-model.md "Registry availability posture"); team-controller keys share
# this same bound. When a revocation refresh fails, the
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
# this age inclusive, then refreshed synchronously; older evidence is never
# presented, so an entry is kept only this long.
_ID_STATUS_FRESH_SECONDS = 60
_ID_STATUS_PATH = "/v1/id-certificates/status"
# Longer than any evidence retained behind a generation (team lists: 1200s).
_CACHE_GENERATION_TTL_SECONDS = 3600
# Entries are stamped in whole seconds of the Redis clock and aged against its
# microseconds.
_MICROSECONDS = 1_000_000


@dataclass(frozen=True)
class _TeamCertificateObservation:
    started_us: int
    revoked_by_id: dict[str, bool]

    def standing(self, certificate_id: str) -> TeamCertificateStanding:
        revoked = self.revoked_by_id.get(certificate_id)
        return evaluate_team_certificate_standing(
            revoked=revoked is True,
            registered=revoked is not None,
        )


@dataclass(frozen=True)
class _TeamCertificateMissRefresh:
    task: asyncio.Task[_TeamCertificateObservation]
    waits_for_window: bool


@dataclass
class _TeamCertificateMissState:
    observation_key: str
    readers: int = 0
    refresh: _TeamCertificateMissRefresh | None = None

    @property
    def completed_refresh(self) -> _TeamCertificateMissRefresh | None:
        refresh = self.refresh
        return refresh if refresh is not None and refresh.task.done() else None


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


def _revocation_page_entries(data: object, *, team_id: str) -> list[dict[str, Any]]:
    """Validate CRL rows and pagination together (docs/awid-sot.md:1411-1423)."""
    entries = None
    valid_pagination = False
    if isinstance(data, dict):
        entries = data.get("revocations")
        has_more = data.get("has_more")
        next_cursor = data.get("next_cursor")
        valid_pagination = (
            ("has_more" not in data and "next_cursor" not in data)
            or (has_more is False and next_cursor is None)
            or (
                has_more is True
                and isinstance(next_cursor, str)
                and bool(next_cursor.strip())
            )
        )
    if (
        not isinstance(entries, list)
        or not all(
            isinstance(entry, dict)
            and isinstance(entry.get("certificate_id"), str)
            and bool(entry["certificate_id"].strip())
            for entry in entries
        )
        or not valid_pagination
    ):
        raise RegistryError(
            f"AWID revocation response is malformed for {team_id}. "
            "Retry against a registry that returns a complete revocations list.",
            status_code=502,
        )
    return entries


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
    # Released address inputs remain accepted: callers may construct or
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
        return (
            "persistent"
            if normalize_identity_scope(self.identity_scope) == "global"
            else "ephemeral"
        )


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


class MalformedTeamKeyError(ValueError):
    """A successful team read did not provide usable controller evidence."""


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


# The registry's three address conflicts are identified by exact string detail.
_ADDRESS_CONFLICT_ERRORS = {
    "did_aw must be registered before address assignment": DIDRegistrationRequiredError,
    "did_aw current key does not match": DIDCurrentKeyMismatchError,
    "address already bound to a different did_aw": AddressAlreadyBoundError,
}


def _raise_registry_response_error(*, status_code: int, content: bytes) -> None:
    """Decode bounded registry errors without interpreting malformed JSON as absence."""
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
    except (json.JSONDecodeError, UnicodeDecodeError, UnicodeEncodeError):
        # Malformed JSON or non-encodable detail/code remains the original
        # HTTP failure, with a bounded textual fallback and no inferred code.
        detail = None
        code = None
    response_text = _safe_error_text(content)
    if status_code == 409 and detail is not None:
        conflict = _ADDRESS_CONFLICT_ERRORS.get(detail)
        if conflict is not None:
            raise conflict()
    raise RegistryError(
        detail or response_text,
        status_code=status_code,
        detail=detail or response_text,
        code=code,
        body=parsed_error,
        body_is_json=body_is_json,
    )


class _RegistryRequestKind(StrEnum):
    READ = "read"
    MUTATION = "mutation"


class _ReadFailure(StrEnum):
    ATTEMPT_BUDGET = "attempt_budget"
    NOT_REPLAYABLE = "not_replayable"
    ELAPSED_BUDGET = "elapsed_budget"


@dataclass(frozen=True)
class _RegistryHTTPResponse:
    status_code: int
    retry_after: str | None
    content: bytes


async def _stream_registry_request(
    *,
    client: httpx.AsyncClient,
    method: str,
    url: str,
    headers: dict[str, str],
    json: dict[str, Any] | None,
    content: bytes | None,
    request_kind: _RegistryRequestKind,
) -> _RegistryHTTPResponse:
    """Close one bounded response before any retry wait; never read a throttled read body."""
    async with client.stream(
        method, url, headers=headers, json=json, content=content
    ) as response:
        if response.status_code == 429 and request_kind is _RegistryRequestKind.READ:
            response_content = b""
        else:
            succeeded = 200 <= response.status_code < 300
            max_bytes = (
                MAX_REGISTRY_RESPONSE_BYTES if succeeded else MAX_REGISTRY_ERROR_BYTES
            )
            try:
                response_content = await _read_bounded_response(response, max_bytes)
            except ValueError as exc:
                if succeeded:
                    raise
                raise RegistryError(
                    f"unreadable HTTP {response.status_code} response",
                    status_code=response.status_code,
                ) from exc
        return _RegistryHTTPResponse(
            response.status_code, response.headers.get("Retry-After"), response_content
        )


@dataclass(frozen=True)
class RegistryClient:
    """One registry client with a bounded original budget for each request.

    Bodyless GET/HEAD reads may retry a 429 up to three total attempts within
    timeout_seconds, honoring Retry-After. SDK-owned read signatures refresh;
    caller-supplied proofs and all mutations are never automatically replayed.
    """

    registry_url: str
    timeout_seconds: float = 5.0
    transport: httpx.AsyncBaseTransport | None = None
    base_url: str | None = None
    domain_registry_resolver: DomainRegistryResolver | None = None
    service_token: str | None = field(default=None, repr=False, compare=False)
    domain_verifier: InitVar[DomainVerifier | None] = field(default=None, kw_only=True)
    # DNS-selected routes stay public-only unless a caller explicitly supplies
    # the federation contract's isolated-development context. Never read env.
    registry_origin_context: OriginContext | None = field(default=None, kw_only=True)
    _domain_verifier: DomainVerifier | None = field(
        init=False, repr=False, compare=False
    )
    member_signing_keys: Mapping[str, bytes] = field(
        default=MappingProxyType({}), repr=False, compare=False
    )
    _request_auth: RegistryRequestAuth = field(init=False, repr=False, compare=False)
    _http_client: httpx.AsyncClient = field(init=False, repr=False, compare=False)
    _override_http_client: httpx.AsyncClient | None = field(
        init=False, repr=False, compare=False
    )

    def __post_init__(self, domain_verifier: DomainVerifier | None = None) -> None:
        object.__setattr__(self, "_domain_verifier", domain_verifier)
        object.__setattr__(
            self, "service_token", normalize_service_token(self.service_token)
        )
        object.__setattr__(
            self,
            "_request_auth",
            RegistryRequestAuth(
                service_token=self.service_token,
                member_signing_keys=self.member_signing_keys,
            ),
        )
        # One immutable key map: the keys that sign are the keys the cache
        # namespaces reads under.
        object.__setattr__(
            self, "member_signing_keys", self._request_auth.member_signing_keys
        )
        object.__setattr__(
            self,
            "_http_client",
            httpx.AsyncClient(
                timeout=self.timeout_seconds,
                # AWID's server closes idle connections after five seconds.
                # The client's idle clock starts later, after consuming the
                # response: an equal expiry can race that close on reuse.
                # Keep a margin, without replaying ambiguous failed writes.
                limits=httpx.Limits(
                    max_connections=100,
                    max_keepalive_connections=20,
                    keepalive_expiry=1.0,
                ),
                transport=self.transport,
                follow_redirects=False,
            ),
        )

        object.__setattr__(
            self,
            "_override_http_client",
            httpx.AsyncClient(
                timeout=self.timeout_seconds,
                transport=RegistryOverrideTransport(
                    origin_context=self.registry_origin_context
                ),
                follow_redirects=False,
                trust_env=False,
            )
            if self.transport is None
            else None,
        )

    def _resolved_base_url(self, registry_url: str | None = None) -> str:
        target_registry_url = registry_url or self.registry_url
        if registry_url is None and self.base_url:
            return self.base_url.rstrip("/")
        return canonical_server_origin(target_registry_url)

    async def registry_audience(self, domain: str) -> str:
        """The domain-selected read origin; administrative writes keep the configured pin.

        docs/identity-messaging-contract.md:241-248 separates these authorities.
        """
        return canonical_server_origin(await self._registry_url_for_domain(domain))

    async def id_chain_evidence(
        self,
        bundle: dict[str, Any] | None,
        subject: dict[str, Any],
        *,
        domain: str,
        refresh: bool = True,
    ) -> IDChainEvidence:
        """Acquire current namespace authority and routed status without a cache.

        Age starts before acquisition and rounds upward, under the same bounded
        attempt as the cached client. Failures return unavailable evidence;
        cancellation propagates. With refresh disabled this uncached client
        reports unavailable evidence.
        Capability-detecting callers now discover this method and perform live
        DNS authority and status reads instead of treating evidence as unavailable.
        """
        try:
            request = status_request(bundle, subject, domain=domain)
        except IDCertificateError:
            request = None
        if request is None or not refresh:
            return IDChainEvidence(status={}, namespace_authority={}, age_seconds=None)
        started_ns = _monotonic_ns()
        try:
            async with asyncio.timeout(self.timeout_seconds):
                entry = await self._acquire_id_status(request)
        except Exception as exc:
            logger.warning(
                "AWID live identity-tree evidence failed for %s: %r", domain, exc
            )
            return IDChainEvidence(status={}, namespace_authority={}, age_seconds=None)
        return _id_status_evidence(
            entry, age=_whole_seconds_up(_monotonic_ns() - started_ns)
        )

    async def _acquire_id_status(
        self, request: dict[str, Any], *, registry_origin: str | None = None
    ) -> dict[str, Any]:
        """One live producer, called inside the owner's timeout and age window.

        MalformedIDStatusError remains distinct for cached-entry invalidation.
        Neither the registry URL nor status alone supplies namespace authority.
        """
        domain = request["domain"]
        verify_domain = self._domain_verifier
        if verify_domain is None:
            verify_domain = dns_verify_domain
        authority = await verify_domain(domain)
        status = await self.fetch_id_certificate_status(
            domain, request, registry_origin=registry_origin
        )
        return {
            "status": status,
            "namespace_authority": {
                "domain": domain,
                "dns_name": authority.dns_name,
                "inherited": authority.inherited,
                "controller_key": authority.controller_did,
            },
        }

    def _uses_dns_registry_discovery(self) -> bool:
        return (
            self.domain_registry_resolver is None
            and self.transport is None
            and canonical_server_origin(self.registry_url) == DEFAULT_AWID_REGISTRY_URL
        )

    async def _registry_url_for_domain(
        self, domain: str, *, fallback_on_dns_error: bool = True
    ) -> str:
        if self.domain_registry_resolver is not None:
            return canonical_server_origin(await self.domain_registry_resolver(domain))
        default_registry_url = canonical_server_origin(self.registry_url)
        if not self._uses_dns_registry_discovery():
            return default_registry_url
        from awid.dns_verify import discover_registry_override

        try:
            registry_override = await discover_registry_override(domain)
        except DnsLookupError as exc:
            if not fallback_on_dns_error:
                raise RegistryError(
                    "AWID registry discovery is unavailable",
                    status_code=503,
                    code="unavailable",
                ) from exc
            logger.debug(
                "AWID registry override lookup failed for %s; using configured registry %s",
                domain,
                default_registry_url,
                exc_info=True,
            )
            return default_registry_url
        except DnsVerificationError as exc:
            logger.warning("AWID registry discovery refused for %s: %r", domain, exc)
            raise RegistryError(
                f"AWID registry discovery is invalid for {domain}. "
                "Correct the domain's _awid TXT record and retry.",
                status_code=502,
            ) from exc
        if registry_override is None:
            return default_registry_url
        return canonical_server_origin(registry_override)

    async def _request_all_pages(
        self,
        path: str,
        items_key: str,
        *,
        headers: dict[str, str] | None = None,
        registry_url: str | None = None,
    ) -> list[dict[str, Any]]:
        """Read every page of a cursor-paginated list route.

        Follows next_cursor until has_more is false, so the result is the
        complete list or a RegistryError, never one page of it.
        """
        separator = "&" if "?" in path else "?"
        items: list[dict[str, Any]] = []
        cursor: str | None = None
        seen_cursors: set[str] = set()
        for _page in range(MAX_REGISTRY_PAGES):
            query = "limit=200"
            if cursor is not None:
                query += f"&cursor={quote(cursor, safe='')}"
            data = await self._request_json(
                "GET",
                f"{path}{separator}{query}",
                headers=headers,
                registry_url=registry_url,
            )
            items.extend(data.get(items_key, []))
            if not data.get("has_more"):
                return items
            next_cursor = str(data.get("next_cursor") or "").strip()
            if not next_cursor or next_cursor in seen_cursors:
                raise RegistryError(
                    f"AWID {items_key} pagination did not advance",
                    status_code=502,
                )
            seen_cursors.add(next_cursor)
            cursor = next_cursor
        raise RegistryError(
            f"AWID {items_key} pagination exceeded {MAX_REGISTRY_PAGES} pages",
            status_code=502,
        )

    async def _request_json(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        json: dict[str, Any] | None = None,
        content: bytes | None = None,
        registry_url: str | None = None,
        retry_throttled: bool = True,
    ) -> dict[str, Any]:
        method = method.upper()
        supplied_headers = {
            key: value
            for key, value in (headers or {}).items()
            if key.strip().lower() != "accept-encoding"
        }
        # The SDK can refresh its own member path signatures. A signature
        # supplied by a caller has no signing capability here: do not replay
        # such a request with an aging proof. Mutations and reads that have
        # spent a certificate point slot are one attempt.
        caller_proof = any(
            name.lower()
            in {"authorization", "x-aweb-signed-payload", "x-aweb-timestamp"}
            for name in supplied_headers
        )
        read_request = method in {"GET", "HEAD"} and json is None and not content
        replayable = read_request and not caller_proof and retry_throttled
        home_registry = registry_url is None or canonical_server_origin(
            registry_url
        ) == canonical_server_origin(self.registry_url)
        http_client = self._http_client
        if not home_registry and self._override_http_client is not None:
            http_client = self._override_http_client
        request_kind = (
            _RegistryRequestKind.READ if read_request else _RegistryRequestKind.MUTATION
        )
        deadline = _read_retry_now() + self.timeout_seconds
        throttled = None
        response_content = b""
        try:
            async with asyncio.timeout(self.timeout_seconds):
                for attempt in range(1, _READ_ATTEMPTS + 1):
                    if throttled is not None and _read_retry_now() >= deadline:
                        raise RegistryThrottled(
                            retry_after_seconds=throttled.retry_after_seconds,
                            attempts=throttled.attempts,
                            reason=_ReadFailure.ELAPSED_BUDGET,
                        )
                    request_headers = {
                        **supplied_headers,
                        "Accept-Encoding": "identity",
                    }
                    if home_registry:
                        # Build inside the loop: no previous attempt's timestamp
                        # or signature is carried over a backoff wait.
                        request_headers.update(
                            self._request_auth.headers(
                                method,
                                path,
                                signed_by_caller=caller_proof,
                            )
                        )
                    response = await _stream_registry_request(
                        client=http_client,
                        method=method,
                        url=f"{self._resolved_base_url(registry_url=registry_url)}{path}",
                        headers=request_headers,
                        json=json,
                        content=content,
                        request_kind=request_kind,
                    )
                    response_content = response.content
                    if response.status_code != 429 or not read_request:
                        break
                    hint = _retry_after_seconds(response.retry_after)
                    reason = (
                        _ReadFailure.ATTEMPT_BUDGET
                        if replayable
                        else _ReadFailure.NOT_REPLAYABLE
                    )
                    throttled = RegistryThrottled(
                        retry_after_seconds=hint, attempts=attempt, reason=reason
                    )
                    if not replayable or attempt == _READ_ATTEMPTS:
                        raise throttled
                    # Invalid/absent hints get finite exponential backoff. Zero
                    # and past-date hints still yield, instead of busy looping.
                    delay = (
                        max(0.05, hint)
                        if hint is not None
                        else min(0.25 * 2 ** (attempt - 1), 2.0)
                    )
                    if delay >= deadline - _read_retry_now():
                        raise RegistryThrottled(
                            retry_after_seconds=hint,
                            attempts=attempt,
                            reason=_ReadFailure.ELAPSED_BUDGET,
                        )
                    # Response context is closed before sleeping: no connection
                    # or response-body stream is held over the wait.
                    await _read_retry_sleep(delay)
        except (httpx.TransportError, TimeoutError) as exc:
            if isinstance(exc, TimeoutError) and throttled is not None:
                raise RegistryThrottled(
                    retry_after_seconds=throttled.retry_after_seconds,
                    attempts=throttled.attempts,
                    reason=_ReadFailure.ELAPSED_BUDGET,
                ) from exc
            # Transport errors are not replayed: a write may already have run.
            unavailable = f"AWID registry unavailable ({type(exc).__name__})"
            raise RegistryError(
                unavailable, status_code=503, code="unavailable"
            ) from exc
        if not 200 <= response.status_code < 300:
            _raise_registry_response_error(
                status_code=response.status_code, content=response_content
            )
        parsed = json_loads(response_content) if response_content else {}
        # Cancellation is delivered at awaits. Also enforce the same original
        # budget after synchronous JSON decoding, before returning authority.
        if _read_retry_now() >= deadline:
            if throttled is not None:
                raise RegistryThrottled(
                    retry_after_seconds=throttled.retry_after_seconds,
                    attempts=throttled.attempts,
                    reason=_ReadFailure.ELAPSED_BUDGET,
                )
            raise RegistryError(
                "AWID registry unavailable (TimeoutError)",
                status_code=503,
                code="unavailable",
            )
        return parsed

    async def aclose(self) -> None:
        """Close the owned HTTP transports; the injected Redis client remains caller-owned."""
        await self._http_client.aclose()
        if self._override_http_client is not None:
            await self._override_http_client.aclose()

    async def health(self) -> dict[str, Any]:
        """Read the configured registry health endpoint within the request budget."""
        return await self._request_json("GET", "/health")

    async def controller_request(
        self, request, *, controllers, signer
    ) -> dict[str, Any]:
        """Execute one typed controller operation inside the custody owner.

        Destination is this client's configured registry, without discovery.
        Returns the registry's public JSON result, never reusable credentials.
        A write without a parsed success or a registry 4xx refusal raises
        ControllerRequestUncertain, including a gateway error or late success;
        the holder reconciles it through current reads and its durable journal.
        """

        if type(request) is not ControllerRequest:
            raise ControllerSigningError("operation_invalid")
        roles = signature_roles(request)
        if not isinstance(controllers, Mapping) or set(controllers) != set(roles):
            raise ControllerSigningError("controller_role")
        # Snapshot the role map before any await. Neither a network callback nor
        # the original caller can swap the second role during the first one.
        selected = dict(controllers)
        pin = canonical_server_origin(self.registry_url)
        timestamp = _utc_timestamp()
        plan = controller_http_plan(request)
        contexts = [
            ControllerSigningContext(request, selected[role], role, timestamp, pin)
            for role in roles
        ]
        for context in contexts:
            context.signing_bytes()  # validate every role before any signing
        headers = {"Content-Type": "application/json"}
        if plan.format != "object":
            headers["X-AWEB-Timestamp"] = timestamp
        body = plan.body
        for context in contexts:
            signature = await checked_controller_signature(context, signer)
            encoded = base64.b64encode(signature).rstrip(b"=").decode()
            if plan.format == "object":
                body = (
                    atomic_claim_body(request, pin, encoded)
                    if request.operation == "address_claim"
                    else canonical_json_bytes(
                        {"record": request.parameters["record"], "signature": encoded}
                    )
                )
            else:
                header = {
                    "controller": "Authorization",
                    "parent": "X-AWEB-Parent-Authorization",
                    "new_controller": "X-AWEB-New-Key-Authorization",
                }[context.role]
                headers[header] = f"DIDKey {context.controller.did_key} {encoded}"
                if context.role == "parent":
                    headers["X-AWEB-Parent-Timestamp"] = timestamp
                if plan.format == "covering":
                    signed = (
                        "X-AWEB-Parent-Signed-Payload"
                        if context.role == "parent"
                        else "X-AWEB-Signed-Payload"
                    )
                    headers[signed] = (
                        base64.urlsafe_b64encode(context.signing_bytes())
                        .rstrip(b"=")
                        .decode()
                    )
        mutation = plan.method != "GET"
        if mutation:
            await self._invalidate_controller_request(request, pin)
        try:
            return await self._request_json(
                plan.method, plan.path, headers=headers, content=body, registry_url=pin
            )
        except RegistryError as exc:
            if mutation and not 400 <= exc.status_code < 500:
                raise ControllerRequestUncertain(request) from exc
            raise
        except (ValueError, UnicodeError) as exc:
            # A successful write with an unreadable answer can already have
            # committed. The caller's journal must reconcile that ambiguity too.
            if mutation:
                raise ControllerRequestUncertain(request) from exc
            raise
        finally:
            if mutation:
                await self._invalidate_controller_request(request, pin)

    async def _invalidate_controller_request(
        self, request, registry_origin: str
    ) -> None:
        """No cache in this client; the cached adapter invalidates affected rows."""
        return None

    async def delete_namespace(
        self, domain: str, controller_signing_key: bytes, *, reason: str | None = None
    ) -> dict[str, Any]:
        """Delete explicitly; this is never a failed-rotation recovery path."""

        descriptor = ControllerDescriptor(
            "namespace",
            domain,
            did_key_from_signing_key(controller_signing_key),
            "local",
            0,
        )
        request = parse_controller_request(
            {"operation": "namespace_delete", "domain": domain, "reason": reason}
        )

        def local(context):
            return descriptor.did_key, sign_bytes(
                key=controller_signing_key, payload=context.signing_bytes()
            )

        return await self.controller_request(
            request, controllers={"controller": descriptor}, signer=local
        )

    async def rotate_team_key(
        self,
        domain: str,
        name: str,
        *,
        new_team_did_key: str,
        namespace_controller_signing_key: bytes,
        resigned_records: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Submit the registry's existing atomic team-key/re-signed-record act."""

        descriptor = ControllerDescriptor(
            "namespace",
            domain,
            did_key_from_signing_key(namespace_controller_signing_key),
            "local",
            0,
        )
        request = parse_controller_request(
            {
                "operation": "team_rotate",
                "domain": domain,
                "name": name,
                "new_team_did_key": new_team_did_key,
                "resigned_records": resigned_records,
            }
        )

        def local(context):
            return descriptor.did_key, sign_bytes(
                key=namespace_controller_signing_key,
                payload=context.signing_bytes(),
            )

        return await self.controller_request(
            request, controllers={"controller": descriptor}, signer=local
        )

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
            REGISTER_PATH,
            domain=leaf["certificate"]["domain"],
            operation=REGISTER_OPERATION,
            body=register_body(
                leaf, expected_head=expected_head, invitation_id=invitation_id
            ),
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
            REVOKE_PATH,
            domain=domain,
            operation=REVOKE_OPERATION,
            body=revoke_body(
                domain, id, expected_head=expected_head, effective_from=effective_from
            ),
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
        claims = rotate_claims(
            from_seq=from_seq,
            previous_did_key=previous_did_key,
            new_did_key=new_did_key,
        )
        return _namespace_from_json(
            await self._covering_request(
                rotate_path(domain),
                domain=domain,
                operation=ROTATE_OPERATION,
                body=rotate_body(domain, claims),
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
        body: bytes,
        signers: list[tuple[str, PayloadSigner, str | None]],
        claims: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """POST ``body`` under a covering-v2 envelope that every signer signs.

        Each signer's answer is checked against the exact payload before
        anything is sent; a signer that raises or answers wrongly sends nothing.
        """
        registry_url = canonical_server_origin(self.registry_url)
        timestamp = _utc_timestamp()
        payload = covering_payload(
            aud=canonical_server_origin(registry_url),
            path=path,
            domain=domain,
            operation=operation,
            body=body,
            timestamp=timestamp,
            claims=claims,
        )
        headers = {
            "Content-Type": "application/json",
            "X-AWEB-Timestamp": timestamp,
            "X-AWEB-Signed-Payload": base64.urlsafe_b64encode(payload)
            .rstrip(b"=")
            .decode("ascii"),
            **(extra_headers or {}),
        }
        for header, signer, expected_key in signers:
            did_key, signature = await _payload_signature(signer, payload, expected_key)
            headers[header] = (
                f"DIDKey {did_key} {base64.b64encode(signature).rstrip(b'=').decode('ascii')}"
            )
        return await self._request_json(
            "POST", path, headers=headers, content=body, registry_url=registry_url
        )

    async def fetch_id_certificate_status(
        self,
        domain: str,
        request: dict[str, Any],
        *,
        registry_origin: str | None = None,
    ) -> dict[str, Any]:
        """POST a status request to the registry ``domain`` routes to.

        Raises RegistryError for a refused answer and MalformedIDStatusError
        for a successful answer that is not a JSON object.
        An operator-selected registry_origin pins this one read, bypassing
        domain discovery; ordinary callers retain their existing routing.
        """
        registry_url = (
            canonical_server_origin(registry_origin)
            if registry_origin is not None
            else await self._registry_url_for_domain(domain)
        )
        try:
            status = await self._request_json(
                "POST", _ID_STATUS_PATH, json=request, registry_url=registry_url
            )
        except ValueError as exc:
            raise MalformedIDStatusError(str(exc)) from exc
        if not isinstance(status, dict):
            raise MalformedIDStatusError("status answer is not a JSON object")
        return status

    async def get_mapping(self, did_aw: str, signing_key: bytes) -> DIDMapping:
        """Read the full stable-identity mapping using a path proof from its signing key."""
        path = f"/v1/did/{quote(did_aw, safe=':')}/full"
        return _did_mapping_from_json(
            await self._request_json(
                "GET",
                path,
                headers=path_signature_headers("GET", path, signing_key),
            )
        )

    async def register_did(
        self,
        did_key: str,
        signing_key: bytes,
    ) -> DIDMapping:
        """Register the stable identity derived from the matching key, then read its full mapping."""
        signer_did = did_key_from_signing_key(signing_key)
        if signer_did != did_key:
            raise ValueError("signing_key must match did_key for DID registration")

        def signer(payload: bytes) -> tuple[str, bytes]:
            return did_key, sign_bytes(key=signing_key, payload=payload)

        entry = initial_registration_entry(did_key, timestamp=_utc_timestamp())
        await self._register_initial_did(entry, signer)
        return await self.get_mapping(entry["did_aw"], signing_key)

    async def register_did_with_signer(
        self,
        did_key: str,
        *,
        signer: PayloadSigner,
        timestamp: str | None = None,
    ) -> dict[str, Any]:
        """Register the did:aw that ``did_key`` derives, its key signing through ``signer``.

        ``signer`` is asked for exactly one signature, over
        ``log_entry_payload(**initial_registration_entry(did_key, timestamp=...))``,
        and its answer is checked before anything is sent. ``timestamp`` is the
        intended operation's; None is now. Returns AWID's receipt
        ``{registered, did_aw, current_did_key}``. A did:aw already registered
        with another key raises AlreadyRegisteredError.
        """
        entry = initial_registration_entry(
            did_key, timestamp=timestamp or _utc_timestamp()
        )
        receipt = await self._register_initial_did(entry, signer)
        if (
            not isinstance(receipt, dict)
            or receipt.get("registered") is not True
            or receipt.get("did_aw") != entry["did_aw"]
            or receipt.get("current_did_key") != did_key
        ):
            raise ValueError(
                "registry receipt does not register this did:aw with this key"
            )
        return receipt

    async def _register_initial_did(
        self, entry: dict[str, Any], signer: PayloadSigner
    ) -> Any:
        """POST ``entry`` signed through ``signer``; returns AWID's answer as sent."""
        _, signature = await _payload_signature(
            signer, log_entry_payload(**entry), entry["new_did_key"]
        )
        did_aw = entry["did_aw"]
        try:
            return await self._request_json(
                "POST",
                "/v1/did",
                json={
                    **entry,
                    "proof": base64.b64encode(signature).rstrip(b"=").decode("ascii"),
                },
            )
        except RegistryError as exc:
            if exc.status_code != 409:
                raise
            try:
                existing = await self.resolve_key(did_aw)
            except RegistryError:
                raise exc
            raise AlreadyRegisteredError(
                did_aw=did_aw, existing_did_key=existing.current_did_key
            )

    async def resolve_key(self, did_aw: str) -> KeyResolution:
        """Read the current key and enrollment evidence; a missing DID raises DIDKeyNotFoundError."""
        try:
            data = await self._request_json(
                "GET", f"/v1/did/{quote(did_aw, safe=':')}/key"
            )
        except RegistryError as refused:
            if refused.status_code == 404:
                # Without a JSON body there is no response to state enrollment; a
                # JSON body is parsed as a response, so a non-object is malformed.
                id_tree = (
                    _id_tree_enrollment(refused.body) if refused.body_is_json else None
                )
                raise DIDKeyNotFoundError(refused, id_tree=id_tree) from refused
            raise
        return _key_resolution_from_json(data)

    async def resolve_key_fresh(self, did_aw: str) -> KeyResolution:
        """Read current key and enrollment evidence without reusing a cached answer."""
        return await self.resolve_key(did_aw)

    async def publish_encryption_key(
        self,
        did_aw: str,
        assertion: dict[str, Any],
    ) -> dict[str, Any]:
        """Publish the signed encryption-key assertion for the named stable identity."""
        return await self._request_json(
            "POST",
            f"/v1/did/{quote(did_aw, safe=':')}/encryption-key",
            json=assertion,
        )

    async def rotate_key(
        self,
        did_aw: str,
        new_did_key: str,
        old_signing_key: bytes,
        new_signing_key: bytes,
    ) -> DIDMapping:
        """Append a key rotation authorized by the current key, then read the mapping with the new key."""
        old_did_key = did_key_from_signing_key(old_signing_key)
        if did_key_from_signing_key(new_signing_key) != new_did_key:
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
        next_state_hash = identity_state_hash(
            did_aw=did_aw, current_did_key=new_did_key
        )
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
            f"/v1/did/{quote(did_aw, safe=':')}",
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
        registry_url = canonical_server_origin(self.registry_url)
        _assert_signing_key_matches(controller_did, controller_signing_key)
        default_delivery_origin = _canonical_optional_origin(default_delivery_origin)
        extra_payload = (
            {"default_delivery_origin": default_delivery_origin}
            if default_delivery_origin is not None
            else None
        )
        parent = None
        if parent_signing_key is not None:
            parent = (
                parent_signing_key,
                "authorize_subdomain_registration",
                {"child_domain": domain, "controller_did": controller_did},
            )
        return _namespace_from_json(
            await self._controller_write(
                "POST",
                "/v1/namespaces",
                registry_url=registry_url,
                domain=domain,
                operation="register",
                signing_key=controller_signing_key,
                claims=extra_payload,
                body={
                    "domain": domain,
                    "controller_did": controller_did,
                    **(
                        {}
                        if default_delivery_origin is None
                        else {"default_delivery_origin": default_delivery_origin}
                    ),
                },
                parent=parent,
            )
        )

    async def get_namespace(self, domain: str) -> Namespace | None:
        return await self._get_namespace_at_origin(
            domain=domain, registry_url=await self._registry_url_for_domain(domain)
        )

    async def _get_namespace_at_origin(
        self, *, domain: str, registry_url: str
    ) -> Namespace | None:
        """Read only the selected namespace origin (docs/awid-sot.md)."""
        data = await self._request_optional_json(
            "GET", f"/v1/namespaces/{domain}", registry_url=registry_url
        )
        return None if data is None else _namespace_from_json(data)

    async def get_namespace_fresh(
        self,
        domain: str,
        *,
        registry_origin: str | None = None,
    ) -> Namespace | None:
        """Read current namespace authority at an optional trusted-host pin."""
        if registry_origin is not None:
            data = await self._request_optional_json(
                "GET",
                f"/v1/namespaces/{domain}",
                registry_url=canonical_server_origin(registry_origin),
            )
            return _namespace_from_json(data) if data is not None else None
        return await self.get_namespace(domain)

    async def update_namespace_delivery_origin(
        self,
        domain: str,
        controller_signing_key: bytes,
        default_delivery_origin: str | None,
    ) -> Namespace:
        registry_url = canonical_server_origin(self.registry_url)
        default_delivery_origin = _canonical_optional_origin(default_delivery_origin)
        signed_origin = default_delivery_origin or ""
        return _namespace_from_json(
            await self._controller_write(
                "PATCH",
                f"/v1/namespaces/{domain}",
                registry_url=registry_url,
                domain=domain,
                operation="update_namespace",
                signing_key=controller_signing_key,
                claims={"default_delivery_origin": signed_origin},
                body={"default_delivery_origin": default_delivery_origin},
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
        registry_url = canonical_server_origin(self.registry_url)
        return _team_from_json(
            await self._controller_write(
                "POST",
                f"/v1/namespaces/{domain}/teams",
                registry_url=registry_url,
                domain=domain,
                operation="create_team",
                signing_key=namespace_controller_signing_key,
                claims={"name": name},
                body={
                    "name": name,
                    "display_name": display_name,
                    "team_did_key": team_did_key,
                    "visibility": visibility,
                },
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
        registry_url = canonical_server_origin(self.registry_url)
        return _team_from_json(
            await self._controller_write(
                "POST",
                f"/v1/namespaces/{domain}/teams/{name}/visibility",
                registry_url=registry_url,
                domain=domain,
                operation="set_team_visibility",
                signing_key=team_controller_signing_key,
                claims={"team_name": name, "visibility": visibility},
                body={"visibility": visibility},
            )
        )

    async def delete_team(
        self,
        domain: str,
        name: str,
        namespace_controller_signing_key: bytes,
    ) -> dict[str, Any]:
        """Delete using namespace authority; active certificates must be revoked first."""
        registry_url = canonical_server_origin(self.registry_url)
        return await self._controller_write(
            "DELETE",
            f"/v1/namespaces/{domain}/teams/{name}",
            registry_url=registry_url,
            domain=domain,
            operation="delete_team",
            signing_key=namespace_controller_signing_key,
            claims={"team_name": name},
        )

    async def rotate_namespace_controller(
        self,
        domain: str,
        new_controller_did: str,
        new_controller_signing_key: bytes,
        parent_signing_key: bytes | None = None,
    ) -> Namespace:
        registry_url = canonical_server_origin(self.registry_url)
        _assert_signing_key_matches(new_controller_did, new_controller_signing_key)
        parent = None
        if parent_signing_key is not None:
            parent = (
                parent_signing_key,
                "authorize_subdomain_rotation",
                {"child_domain": domain, "new_controller_did": new_controller_did},
            )
        return _namespace_from_json(
            await self._controller_write(
                "PUT",
                f"/v1/namespaces/{domain}",
                registry_url=registry_url,
                domain=domain,
                operation="rotate_controller",
                signing_key=new_controller_signing_key,
                claims={"new_controller_did": new_controller_did},
                body={"new_controller_did": new_controller_did},
                parent=parent,
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
        registry_url = canonical_server_origin(self.registry_url)
        if current_did_key is None:
            key_resolution = await self.resolve_key(did_aw)
            current_did_key = key_resolution.current_did_key
        return _address_from_json(
            await self._controller_write(
                "POST",
                f"/v1/namespaces/{domain}/addresses",
                registry_url=registry_url,
                domain=domain,
                operation="register_address",
                signing_key=controller_signing_key,
                claims={"name": name},
                body={
                    "name": name,
                    "did_aw": did_aw,
                    "current_did_key": current_did_key,
                },
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
        """None means coded address absence or the exact released legacy body."""
        return await self._resolve_address_at_origin(
            domain=domain,
            name=name,
            registry_url=await self._registry_url_for_domain(domain),
        )

    async def _resolve_address_at_origin(
        self, *, domain: str, name: str, registry_url: str
    ) -> Address | None:
        """Keep address data on its selected origin (docs/identity-messaging-contract.md:241-248)."""
        try:
            data = await self._request_json(
                "GET",
                f"/v1/namespaces/{domain}/addresses/{address_segment(name)}",
                registry_url=registry_url,
            )
        except RegistryError as exc:
            if is_address_not_found(exc.status_code, exc.body):
                return None
            raise
        return _address_from_json(data)

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
        return await self._list_addresses_at_origin(
            domain=domain, registry_url=await self._registry_url_for_domain(domain)
        )

    async def _list_addresses_at_origin(
        self, *, domain: str, registry_url: str
    ) -> list[Address]:
        """Pin every page to the address cache's selected origin (docs/awid-sot.md)."""
        items = await self._request_all_pages(
            f"/v1/namespaces/{domain}/addresses",
            "addresses",
            registry_url=registry_url,
        )
        return [_address_from_json(item) for item in items]

    async def get_team_public_key(self, domain: str, name: str) -> str | None:
        """Fetch the team's public did:key from awid.

        GET /v1/namespaces/{domain}/teams/{name}
        Returns team_did_key or None if team not found.
        """
        return await self.get_team_public_key_fresh(domain, name)

    async def get_team_public_key_fresh(
        self,
        domain: str,
        name: str,
        *,
        registry_origin: str | None = None,
    ) -> str | None:
        """Read current team authority, without cached or outage-grace data.

        registry_origin is an optional trusted-host pin, never caller wire
        authority. Without a pin, require successful registry selection.
        An absent team returns None. A successful answer without a usable
        controller key raises MalformedTeamKeyError.
        """
        registry_url = (
            canonical_server_origin(registry_origin)
            if registry_origin is not None
            else await self._registry_url_for_domain(
                domain, fallback_on_dns_error=False
            )
        )
        try:
            team = await self._get_team_at_origin(
                domain=domain, name=name, registry_url=registry_url
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise MalformedTeamKeyError("AWID team response is invalid") from exc
        if team is None:
            return None
        key = team.team_did_key
        if not isinstance(key, str) or not validate_did(key):
            raise MalformedTeamKeyError(
                "AWID team response has no usable controller key"
            )
        return key

    async def get_team(self, domain: str, name: str) -> Team | None:
        """Fetch team metadata from awid."""
        return await self._get_team_at_origin(
            domain=domain,
            name=name,
            registry_url=await self._registry_url_for_domain(domain),
        )

    async def _get_team_at_origin(
        self, *, domain: str, name: str, registry_url: str
    ) -> Team | None:
        """Keep the answering origin identical to the cache partition (docs/awid-sot.md)."""
        data = await self._request_optional_json(
            "GET", f"/v1/namespaces/{domain}/teams/{name}", registry_url=registry_url
        )
        return None if data is None else _team_from_json(data)

    async def get_team_fresh(self, domain: str, name: str) -> Team | None:
        """Read the team's current metadata, its controller key included,
        without a stale cache result."""
        return await self.get_team(domain, name)

    async def get_team_server_record(
        self, domain: str, name: str
    ) -> dict[str, Any] | None:
        """Read the signed envelope, or None on 404; the caller verifies current team authority."""
        return await self._request_optional_json(
            "GET",
            f"/v1/namespaces/{domain}/teams/{name}/server",
            registry_url=await self._registry_url_for_domain(domain),
        )

    async def get_team_key_act(self, domain: str, name: str) -> dict[str, Any] | None:
        """Read the namespace controller's act naming the team's current key,
        or None on 404. Never cached: the caller verifies it with
        ``awid.team_key_acts.verify_team_key_change``."""
        return await self._request_optional_json(
            "GET",
            f"/v1/namespaces/{domain}/teams/{name}/key-act",
            registry_url=await self._registry_url_for_domain(domain),
        )

    async def publish_team_server_record(
        self,
        domain: str,
        name: str,
        record: dict[str, Any],
        signature: str,
    ) -> dict[str, Any]:
        """PUT a team-key-signed envelope; registry refusals raise RegistryError."""
        return await self._request_json(
            "PUT",
            f"/v1/namespaces/{domain}/teams/{name}/server",
            json={"record": record, "signature": signature},
            registry_url=canonical_server_origin(self.registry_url),
        )

    async def get_team_revocations(self, domain: str, name: str) -> set[str]:
        """Fetch the complete set of revoked certificate IDs for a team.

        GET /v1/namespaces/{domain}/teams/{name}/revocations

        Completeness is the contract: verifiers treat the returned
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

    async def get_team_revocations_for_certificates(
        self,
        domain: str,
        name: str,
        certificate_ids: list[str],
        *,
        fresh: bool = False,
    ) -> set[str]:
        """Select IDs from the COMPLETE CRL; never make per-ID registry queries."""
        revoked = (
            await self.get_team_revocations_fresh(domain, name)
            if fresh
            else await self.get_team_revocations(domain, name)
        )
        return revoked.intersection(certificate_ids)

    async def _scan_team_revocations(
        self,
        domain: str,
        name: str,
        *,
        since: str | None = None,
        registry_url: str | None = None,
    ) -> _RevocationScan:
        """Page through the revocations route and report what was read.

        With ``since`` this reads only the tail of the list; without it, the
        whole list. The exact released first-page missing-team answer returns
        an empty set; every other failure propagates, so a caller never observes a partial page-through and
        can never mistake one for current data.
        """
        registry_url = registry_url or await self._registry_url_for_domain(
            domain, fallback_on_dns_error=False
        )
        base_path = f"/v1/namespaces/{domain}/teams/{name}/revocations"
        revoked: set[str] = set()
        newest: datetime | None = None
        all_timestamped = True
        cursor: str | None = None
        timestamp_cursor: str | None = since
        for _page in range(MAX_REGISTRY_PAGES):
            query = "limit=200"
            if cursor is not None:
                query += f"&cursor={quote(cursor, safe='')}"
            elif timestamp_cursor is not None:
                query += f"&since={quote(timestamp_cursor, safe='')}"
            try:
                data = await self._request_json(
                    "GET",
                    f"{base_path}?{query}",
                    registry_url=registry_url,
                )
            except RegistryError as exc:
                if _page == 0 and is_team_not_found(exc.status_code, exc.body):
                    # Released SDK/Cloud callers interpret this as no team;
                    # their independent key read must still establish authority.
                    return _RevocationScan(set(), None, True)
                raise
            entries = _revocation_page_entries(
                data, team_id=build_team_id(domain, name)
            )
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
                    return _RevocationScan(revoked, newest, all_timestamped)
                cursor = data["next_cursor"]
                continue
            # A server without a truncation signal has a 1000-row hard limit
            # oldest-first rows; a shorter page, or a page that added nothing
            # new, is the end. So is a page whose rows carry no usable
            # revoked_at, because there is then nothing to page forward from.
            if len(entries) < 1000 or len(revoked) == before or page_newest is None:
                return _RevocationScan(revoked, newest, all_timestamped)
            timestamp_cursor = page_newest.isoformat()
            cursor = None
        raise RegistryError(
            f"AWID revocations pagination exceeded {MAX_REGISTRY_PAGES} pages",
            status_code=502,
        )

    async def get_team_certificate_status_fresh(
        self,
        domain: str,
        name: str,
        certificate_id: str,
        *,
        registry_url: str | None = None,
        budgeted: bool = False,
    ) -> dict[str, Any] | None:
        """Uncached public exact-certificate status, including private teams."""
        path = f"/v1/namespaces/{quote(domain, safe='')}/teams/{quote(name, safe='')}/certificates/{quote(certificate_id, safe='')}/status"
        try:
            return await self._request_json(
                "GET",
                path,
                registry_url=registry_url
                or await self._registry_url_for_domain(domain),
                retry_throttled=not budgeted,
            )
        except RegistryError as exc:
            if exc.status_code == 404 and (
                not budgeted or exc.body == {"detail": "Certificate not found"}
            ):
                return None
            raise

    async def list_team_certificates(
        self,
        domain: str,
        name: str,
        *,
        active_only: bool = True,
        signing_key: bytes | None = None,
    ) -> list[TeamCertificate]:
        """Read all certificate pages under the supplied read authority and active-only selection."""
        return await self._list_team_certificates_at_origin(
            domain,
            name,
            active_only=active_only,
            signing_key=signing_key,
            registry_url=await self._registry_url_for_domain(domain),
        )

    async def _list_team_certificates_at_origin(
        self,
        domain: str,
        name: str,
        *,
        active_only: bool,
        signing_key: bytes | None,
        registry_url: str,
    ) -> list[TeamCertificate]:
        active_only_value = "true" if active_only else "false"
        base_path = f"/v1/namespaces/{domain}/teams/{name}/certificates"
        headers = (
            path_signature_headers("GET", base_path, signing_key)
            if signing_key is not None
            else None
        )
        items = await self._request_all_pages(
            f"{base_path}?active_only={active_only_value}",
            "certificates",
            headers=headers,
            registry_url=registry_url,
        )
        return [_team_certificate_from_json(item) for item in items]

    async def list_team_certificates_fresh(
        self,
        domain: str,
        name: str,
        *,
        active_only: bool = True,
        signing_key: bytes | None = None,
        registry_url: str | None = None,
    ) -> list[TeamCertificate]:
        """Read current certificates without stale fallback, on cached clients too."""
        return await self._list_team_certificates_at_origin(
            domain,
            name,
            active_only=active_only,
            signing_key=signing_key,
            registry_url=registry_url or await self._registry_url_for_domain(domain),
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
        registry_url = canonical_server_origin(self.registry_url)
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
        await self._controller_write(
            "POST",
            f"/v1/namespaces/{domain}/teams/{name}/certificates",
            registry_url=registry_url,
            domain=domain,
            operation="register_certificate",
            signing_key=team_controller_signing_key,
            claims={"team_name": name, "certificate_id": certificate_id},
            body=payload,
        )

    async def revoke_team_certificate(
        self,
        domain: str,
        name: str,
        *,
        team_controller_signing_key: bytes,
        certificate_id: str,
    ) -> None:
        registry_url = canonical_server_origin(self.registry_url)
        await self._controller_write(
            "POST",
            f"/v1/namespaces/{domain}/teams/{name}/certificates/revoke",
            registry_url=registry_url,
            domain=domain,
            operation="revoke_certificate",
            signing_key=team_controller_signing_key,
            claims={"team_name": name, "certificate_id": certificate_id},
            body={"certificate_id": certificate_id},
        )

    async def revoke_team_certificate_with_proof(
        self,
        domain: str,
        name: str,
        *,
        certificate_id: str,
        controller_did: str,
        signing: bytes,
        signature: bytes,
    ) -> None:
        """Deliver one already-prepared, exact covering-v2 certificate revoke.

        No key is accepted, signing is not repeated, and mutations remain one
        attempt. A caller reconciles an ambiguous answer through fresh registry
        reads. This cannot select another route, operation, target or body.
        """
        if (
            type(domain) is not str
            or type(name) is not str
            or build_team_id(domain, name) != f"{name}:{domain}"
            or any(char in domain + name for char in "/%?#\\")
            or type(certificate_id) is not str
            or str(UUID(certificate_id)) != certificate_id
            or type(signing) is not bytes
            or type(signature) is not bytes
            or len(signature) != 64
        ):
            raise ValueError("invalid prepared certificate revocation")
        fields = json_loads(signing)
        if not isinstance(fields, dict):
            raise ValueError("invalid prepared certificate revocation")
        timestamp = fields.get("timestamp")
        if not isinstance(timestamp, str):
            raise ValueError("invalid prepared certificate revocation")
        parse_utc_seconds(timestamp)
        registry_url = canonical_server_origin(self.registry_url)
        path = f"/v1/namespaces/{domain}/teams/{name}/certificates/revoke"
        body = canonical_json_bytes({"certificate_id": certificate_id})
        expected = covering_payload(
            aud=registry_url,
            path=path,
            domain=domain,
            operation="revoke_certificate",
            body=body,
            timestamp=timestamp,
            claims={"team_name": name, "certificate_id": certificate_id},
        )
        if signing != expected:
            raise ValueError("invalid prepared certificate revocation")
        signature_b64 = base64.b64encode(signature).rstrip(b"=").decode()
        verify_did_key_signature(
            did_key=controller_did, payload=expected, signature_b64=signature_b64
        )
        headers = {
            "Authorization": f"DIDKey {controller_did} {signature_b64}",
            "X-AWEB-Timestamp": timestamp,
            "X-AWEB-Signed-Payload": base64.urlsafe_b64encode(expected)
            .rstrip(b"=")
            .decode(),
            "Content-Type": "application/json",
        }
        await self._invalidate_prepared_revocation_cache(domain, name)
        try:
            await self._request_json(
                "POST", path, headers=headers, content=body, registry_url=registry_url
            )
        finally:
            # A lost reply can follow an applied revocation; try invalidation
            # again without replacing the registry's outcome with a cache fault.
            await self._invalidate_prepared_revocation_cache(domain, name)

    async def _invalidate_prepared_revocation_cache(
        self, domain: str, name: str
    ) -> None:
        """Cache availability cannot prevent a controller revoke (docs/awid-sot.md)."""
        try:
            await self.invalidate_team_certificate_cache(domain, name)
        except (RedisError, OSError):
            logger.warning(
                "AWID revocation cache invalidation unavailable for team %s/%s; "
                "use fresh registry reads to reconcile the revocation result",
                domain,
                name,
                exc_info=True,
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
        registry_url = canonical_server_origin(self.registry_url)
        return _address_from_json(
            await self._controller_write(
                "PUT",
                f"/v1/namespaces/{domain}/addresses/{address_segment(name)}",
                registry_url=registry_url,
                domain=domain,
                operation="update_address",
                signing_key=controller_signing_key,
                claims={"name": name},
                body={},
            )
        )

    async def delete_address(
        self,
        domain: str,
        name: str,
        controller_signing_key: bytes,
    ) -> None:
        registry_url = canonical_server_origin(self.registry_url)
        await self._controller_write(
            "DELETE",
            f"/v1/namespaces/{domain}/addresses/{address_segment(name)}",
            registry_url=registry_url,
            domain=domain,
            operation="delete_address",
            signing_key=controller_signing_key,
            claims={"name": name},
        )

    async def list_did_addresses(self, did_aw: str) -> list[Address]:
        """Read all address bindings for the stable identity."""
        items = await self._request_all_pages(
            f"/v1/did/{quote(did_aw, safe=':')}/addresses", "addresses"
        )
        return [_address_from_json(item) for item in items]

    async def reassign_address(
        self,
        domain: str,
        name: str,
        new_did_aw: str,
        controller_signing_key: bytes,
    ) -> Address:
        registry_url = canonical_server_origin(self.registry_url)
        key_resolution = await self.resolve_key(new_did_aw)
        return _address_from_json(
            await self._controller_write(
                "POST",
                f"/v1/namespaces/{domain}/addresses/{address_segment(name)}/reassign",
                registry_url=registry_url,
                domain=domain,
                operation="reassign_address",
                signing_key=controller_signing_key,
                claims={"name": name},
                body={
                    "did_aw": new_did_aw,
                    "current_did_key": key_resolution.current_did_key,
                },
            )
        )

    def _controller_headers(
        self,
        signing_key: bytes,
        *,
        registry_url: str,
        method: str,
        path: str,
        body: bytes,
        domain: str,
        operation: str,
        claims: dict[str, Any] | None = None,
        parent: bool = False,
    ) -> dict[str, str]:
        """The covering-v2 signature of one controller write: it covers the
        destination registry, the method, the path and ``body``, the exact
        bytes sent. A parent's signature authorizes a child namespace's
        controller over the same request, in the parent headers."""
        timestamp = _utc_timestamp()
        payload = covering_payload(
            aud=canonical_server_origin(registry_url),
            method=method,
            path=path,
            domain=domain,
            operation=operation,
            body=body,
            timestamp=timestamp,
            claims=claims,
        )
        prefix = "X-AWEB-Parent-" if parent else "X-AWEB-"
        return {
            "X-AWEB-Parent-Authorization" if parent else "Authorization": (
                f"DIDKey {did_key_from_signing_key(signing_key)} {sign_message(signing_key, payload)}"
            ),
            f"{prefix}Timestamp": timestamp,
            f"{prefix}Signed-Payload": base64.urlsafe_b64encode(payload)
            .rstrip(b"=")
            .decode(),
        }

    async def _controller_write(
        self,
        method: str,
        path: str,
        *,
        registry_url: str,
        domain: str,
        operation: str,
        signing_key: bytes,
        claims: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
        parent: tuple[bytes, str, dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Send one controller write. ``body`` (None for none) is serialized
        once, and those bytes are both the ones signed and the ones sent.
        ``parent`` is the parent's (signing key, operation, claims)."""
        content = canonical_json_bytes(body) if body is not None else b""
        signed: _ControllerWriteInputs = {
            "registry_url": registry_url,
            "method": method,
            "path": path,
            "body": content,
            "domain": domain,
        }
        headers = self._controller_headers(
            signing_key, operation=operation, claims=claims, **signed
        )
        if parent is not None:
            parent_key, parent_operation, parent_claims = parent
            headers.update(
                self._controller_headers(
                    parent_key,
                    operation=parent_operation,
                    claims=parent_claims,
                    parent=True,
                    **signed,
                )
            )
        if content:
            headers["Content-Type"] = "application/json"
        return await self._request_json(
            method,
            path,
            headers=headers,
            content=content or None,
            registry_url=registry_url,
        )


# Claiming a DNS confirmation and publishing its later HTTP answer share
# one Redis locator. A move clears the usable route while the new answer
# is pending. A slow answer can only publish under its own confirmation.
_UPDATE_REGISTRY_ROUTE = """
local action, discovery_id, value, ttl = unpack(ARGV)
local route = {}
local raw = redis.call('GET', KEYS[1])
if raw then
    local ok, decoded = pcall(cjson.decode, raw)
    if ok and type(decoded) == 'table' then
        route = decoded
    end
end
if action == 'confirm' then
    if route.registry_url ~= value then
        route = {}
    end
    route.discovery_id = discovery_id
    value = cjson.encode(route)
elseif route.discovery_id ~= discovery_id then
    return 0
end
redis.call('SET', KEYS[1], value, 'EX', ttl)
return 1
"""


@dataclass(frozen=True, kw_only=True)
class _RegistryCacheRoute:
    """A bounded locator; only the answering origin's entry supplies evidence."""

    registry_url: str
    fetched_at: int


@dataclass(frozen=True, kw_only=True)
class _TeamReadOrigin:
    registry_url: str
    lookup_error: RegistryError | None = None
    discovered_at: int | None = None
    discovery_id: str | None = None


class CachedRegistryClient(RegistryClient):
    """Redis-backed caching wrapper for RegistryClient reads."""

    redis_client: Redis
    _refresh_tasks: dict[str, asyncio.Task[None]]
    _domain_verifier: DomainVerifier | None
    _id_status_refreshes: dict[str, asyncio.Task[_IDStatusRefresh]]
    _team_key_signature_refreshes: dict[str, asyncio.Task[str | None]]
    _team_certificate_miss_states: dict[str, _TeamCertificateMissState]

    async def _invalidate_controller_request(
        self, request, registry_origin: str
    ) -> None:
        op, domain, parameters = request.operation, request.domain, request.parameters
        if op.startswith("namespace_"):
            await self._invalidate_keys(
                self._namespace_cache_key(domain, registry_url=registry_origin)
            )
            await self._invalidate_id_status_cache(domain)
        elif op == "id_revoke":
            await self._invalidate_id_status_cache(domain)
        elif op.startswith("address_"):
            name = parameters.get("name", parameters.get("address_name"))
            address_key = await self._generation_cache_key(
                self._address_cache_key(
                    domain, name, registry_url=registry_origin, caller_did_key=None
                ),
                self._address_generation_key(domain, registry_origin),
            )
            previous = await self._peek_cached_address(address_key)
            dids = {parameters.get("did_aw"), previous.did_aw if previous else None}
            await self._invalidate_address_cache(
                domain=domain,
                name=name,
                did_aws=[did for did in dids if did],
                registry_url=registry_origin,
            )
        else:
            await self._invalidate_team_cache(domain, parameters["name"])

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
        member_signing_keys: dict[str, bytes] | None = None,
        domain_verifier: DomainVerifier | None = None,
        registry_origin_context: OriginContext | None = None,
    ) -> None:
        super().__init__(
            registry_url=registry_url,
            timeout_seconds=timeout_seconds,
            transport=transport,
            base_url=base_url,
            domain_registry_resolver=domain_registry_resolver,
            service_token=service_token,
            domain_verifier=domain_verifier,
            registry_origin_context=registry_origin_context,
            member_signing_keys=dict(member_signing_keys or {}),
        )
        object.__setattr__(self, "redis_client", redis_client)
        object.__setattr__(self, "_refresh_tasks", {})
        object.__setattr__(self, "_id_status_refreshes", {})
        object.__setattr__(self, "_team_key_signature_refreshes", {})
        object.__setattr__(self, "_team_certificate_miss_states", {})

    async def id_chain_evidence(
        self,
        bundle: dict[str, Any] | None,
        subject: dict[str, Any],
        *,
        domain: str,
        refresh: bool = True,
    ) -> IDChainEvidence:
        """Trusted identity-tree evidence for verifying ``subject``'s chain in ``domain``.

        A stored entry is aged on the Redis server's clock, the one clock
        every process sharing it reads. Evidence aged 60 seconds or less is
        served with no DNS or HTTP work. Older evidence waits for one refresh
        shared by every caller of the same request, unless refresh is disabled.
        A failed read returns unavailable evidence without an age. A malformed
        successful response raises MalformedIDStatusError.
        """
        try:
            request = status_request(bundle, subject, domain=domain)
        except IDCertificateError:
            request = None
        if request is None:
            # The verifier refuses this request before it reads any evidence.
            return IDChainEvidence(status={}, namespace_authority={}, age_seconds=None)
        # The locator is fenced by the configured registry's write generation.
        # It preserves the no-DNS fresh-hit rule without mixing answering origins.
        route_generation_key = self._id_status_generation_key(domain)
        route_generation = await self._read_cache_generation(route_generation_key)
        route_key = self._cache_key_at_generation(
            self._id_status_route_key(request), route_generation
        )
        route_now, route = await self._read_registry_cache_route(route_key)
        if route is not None and route_now >= route.fetched_at * _MICROSECONDS:
            route_age = _whole_seconds_up(
                (route_now - route.fetched_at * _MICROSECONDS) * 1_000
            )
            if route_age <= _ID_STATUS_FRESH_SECONDS:
                status_generation_key = self._id_status_generation_key(
                    domain, registry_url=route.registry_url
                )
                # One observation selects both keys when their generation is shared.
                status_generation = (
                    route_generation
                    if status_generation_key == route_generation_key
                    else await self._read_cache_generation(status_generation_key)
                )
                cache_key = self._cache_key_at_generation(
                    self._id_status_cache_key(request, registry_url=route.registry_url),
                    status_generation,
                )
                redis_now_us, cached = await self._read_id_status_entry(cache_key)
                if (
                    cached is not None
                    and redis_now_us >= cached["fetched_at"] * _MICROSECONDS
                ):
                    age = _whole_seconds_up(
                        (redis_now_us - cached["fetched_at"] * _MICROSECONDS) * 1_000
                    )
                    if age <= _ID_STATUS_FRESH_SECONDS:
                        return _id_status_evidence(cached, age=age)
        if refresh:
            acquired = await self._coalesced_id_status_refresh(route_key, request)
            if acquired.entry is not None:
                return _id_status_evidence(acquired.entry, age=acquired.age)
        return IDChainEvidence(status={}, namespace_authority={}, age_seconds=None)

    async def _coalesced_id_status_refresh(
        self, route_key: str, request: dict[str, Any]
    ) -> _IDStatusRefresh:
        task = self._id_status_refreshes.get(route_key)
        if task is None:
            task = asyncio.create_task(self._refresh_id_status(route_key, request))
            self._id_status_refreshes[route_key] = task

            def discard_completed_refresh(
                done: asyncio.Task[_IDStatusRefresh],
            ) -> None:
                self._id_status_refreshes.pop(route_key, None)
                if not done.cancelled():
                    done.exception()  # Observe failures after every waiter was cancelled.

            task.add_done_callback(discard_completed_refresh)
        # A cancelled caller leaves the shared attempt running for the others.
        return await asyncio.shield(task)

    async def _refresh_id_status(
        self, route_key: str, request: dict[str, Any]
    ) -> _IDStatusRefresh:
        """Pin one answering origin inside the original acquisition timeout.

        docs/awid-sot.md:1341-1375 and coordinator a5fc12c0 permit a fresh hit
        to reuse its recorded origin through 60s, without another DNS lookup.
        An origin locator contains no authority and never extends evidence age.
        """
        domain = request["domain"]
        started_ns = _monotonic_ns()
        cache_key = None
        try:
            async with asyncio.timeout(self.timeout_seconds):
                fetched_at = await self._redis_time()
                registry_url = await self._registry_url_for_domain(domain)
                cache_key = await self._generation_cache_key(
                    self._id_status_cache_key(request, registry_url=registry_url),
                    self._id_status_generation_key(domain, registry_url=registry_url),
                )
                acquired = await self._acquire_id_status(
                    request, registry_origin=registry_url
                )
        except MalformedIDStatusError:
            logger.warning(
                "AWID identity-tree status for %s is malformed; no evidence is served",
                domain,
            )
            await self._invalidate_keys(route_key, cache_key or "")
            raise
        except (
            DnsVerificationError,
            RegistryError,
            ValueError,
            OSError,
            TimeoutError,
        ) as exc:
            logger.warning(
                "AWID identity-tree status refresh failed for %s: %r", domain, exc
            )
            return _IDStatusRefresh(entry=None, age=None)
        entry = {"fetched_at": fetched_at, **acquired}
        if fetched_at is not None:
            await self._redis_set(
                cache_key,
                json.dumps(entry, separators=(",", ":"), sort_keys=True),
                ex=_ID_STATUS_FRESH_SECONDS,
            )
            await self._write_registry_cache_route(
                route_key,
                registry_url,
                fetched_at=fetched_at,
                retention_seconds=_ID_STATUS_FRESH_SECONDS,
            )
        return _IDStatusRefresh(
            entry=entry, age=_whole_seconds_up(_monotonic_ns() - started_ns)
        )

    async def _redis_time(self) -> int | None:
        """The Redis server clock in whole seconds, or None when Redis is unavailable."""
        try:
            seconds, _microseconds = await self.redis_client.time()
        except (RedisError, OSError):
            logger.debug(
                "AWID cache clock read skipped because Redis is unavailable",
                exc_info=True,
            )
            return None
        return int(seconds)

    async def _read_registry_cache_payload(
        self, cache_key: str
    ) -> tuple[int, dict[str, Any] | None]:
        """Read a JSON object and Redis clock in one pipelined round trip."""
        try:
            async with self.redis_client.pipeline(transaction=False) as pipe:
                pipe.time()
                pipe.get(cache_key)
                (seconds, microseconds), raw = await pipe.execute()
        except (RedisError, OSError):
            logger.debug(
                "AWID cache read skipped because Redis is unavailable", exc_info=True
            )
            return 0, None
        redis_now = int(seconds) * _MICROSECONDS + int(microseconds)
        if raw is None:
            return redis_now, None
        try:
            entry = json.loads(raw)
            if not isinstance(entry, dict):
                raise ValueError("identity-tree cache entry is not an object")
        except (ValueError, TypeError, UnicodeError):
            logger.warning(
                "Invalid AWID cache payload for %s; dropping entry", cache_key
            )
            await self._invalidate_keys(cache_key)
            return redis_now, None
        return redis_now, entry

    async def _read_id_status_entry(
        self, cache_key: str
    ) -> tuple[int, dict[str, Any] | None]:
        redis_now, entry = await self._read_registry_cache_payload(cache_key)
        if entry is not None and (
            type(entry.get("fetched_at")) is not int
            or not isinstance(entry.get("status"), dict)
            or not isinstance(entry.get("namespace_authority"), dict)
        ):
            logger.warning(
                "Invalid AWID cache payload for %s; dropping entry", cache_key
            )
            await self._invalidate_keys(cache_key)
            return redis_now, None
        return redis_now, entry

    async def _read_registry_cache_route(
        self, route_key: str
    ) -> tuple[int, _RegistryCacheRoute | None]:
        redis_now, entry = await self._read_registry_cache_payload(route_key)
        if entry is None:
            return redis_now, None
        origin, fetched_at = entry.get("registry_url"), entry.get("fetched_at")
        if origin is None and isinstance(entry.get("discovery_id"), str):
            return redis_now, None
        if isinstance(origin, str) and type(fetched_at) is int:
            try:
                if canonical_server_origin(origin) == origin:
                    return redis_now, _RegistryCacheRoute(
                        registry_url=origin, fetched_at=fetched_at
                    )
            except ValueError:
                logger.warning(
                    "Invalid AWID origin locator for %s", route_key, exc_info=True
                )
        await self._invalidate_keys(route_key)
        return redis_now, None

    async def _write_registry_cache_route(
        self,
        route_key: str,
        registry_url: str,
        *,
        fetched_at: int,
        retention_seconds: int,
        discovery_id: str | None = None,
    ) -> None:
        payload = json.dumps({"registry_url": registry_url, "fetched_at": fetched_at})
        if discovery_id is None:
            await self._redis_set(route_key, payload, ex=retention_seconds)
        else:
            await self._update_registry_route(
                route_key, "publish", discovery_id, payload, retention_seconds
            )

    async def _update_registry_route(
        self,
        route_key: str,
        action: Literal["confirm", "publish"],
        discovery_id: str,
        value: str,
        retention_seconds: int,
    ) -> bool:
        try:
            # Redis shares its EVAL annotation with the synchronous client.
            result = cast(
                Awaitable[int],
                self.redis_client.eval(
                    _UPDATE_REGISTRY_ROUTE,
                    1,
                    route_key,
                    action,
                    discovery_id,
                    value,
                    retention_seconds,
                ),
            )
            return await result == 1
        except (RedisError, OSError):
            logger.debug("AWID registry route update unavailable", exc_info=True)
            return False

    async def _team_read_origin(
        self,
        domain: str,
        name: str,
        *,
        fresh_seconds: int,
        outage_grace_seconds: int = 0,
    ) -> _TeamReadOrigin:
        """Locate origin-scoped evidence without renewing its freshness or grace.

        DNS recovery may change the origin. A lookup outage can point the key
        and CRL readers back to the last origin only to check their own grace;
        without eligible evidence they fail closed.
        Explicit resolver/transport policies keep their original selection.
        """
        if (
            not self._uses_dns_registry_discovery()
            or self.registry_origin_context is not None
        ):
            registry_url = await self._registry_url_for_domain(
                domain, fallback_on_dns_error=outage_grace_seconds == 0
            )
            return _TeamReadOrigin(registry_url=registry_url)

        route_key = self._team_registry_route_key(domain, name)
        _, route = await self._read_registry_cache_route(route_key)
        started_at = _cache_now()
        if route is not None and 0 <= started_at - route.fetched_at < fresh_seconds:
            return _TeamReadOrigin(registry_url=route.registry_url)

        try:
            origin = await self._registry_url_for_domain(
                domain, fallback_on_dns_error=False
            )
        except RegistryError as exc:
            if not isinstance(exc.__cause__, DnsLookupError):
                raise
            if not outage_grace_seconds:
                # A discovery failure cannot install a new locator.
                return _TeamReadOrigin(
                    registry_url=canonical_server_origin(self.registry_url)
                )
            _, route = await self._read_registry_cache_route(route_key)
            if (
                route is not None
                and 0 <= _cache_now() - route.fetched_at <= outage_grace_seconds
            ):
                return _TeamReadOrigin(
                    registry_url=route.registry_url, lookup_error=exc
                )
            raise

        discovery_id = uuid4().hex
        confirmed = await self._update_registry_route(
            route_key,
            "confirm",
            discovery_id,
            origin,
            _TEAM_REVOCATIONS_OUTAGE_GRACE_SECONDS,
        )
        return _TeamReadOrigin(
            registry_url=origin,
            discovered_at=started_at,
            discovery_id=discovery_id if confirmed else None,
        )

    async def _remember_team_read_origin(
        self, domain: str, name: str, origin: _TeamReadOrigin
    ) -> None:
        if origin.discovered_at is not None and origin.discovery_id is not None:
            await self._write_registry_cache_route(
                self._team_registry_route_key(domain, name),
                origin.registry_url,
                fetched_at=origin.discovered_at,
                retention_seconds=_TEAM_REVOCATIONS_OUTAGE_GRACE_SECONDS,
                discovery_id=origin.discovery_id,
            )

    async def resolve_key(self, did_aw: str) -> KeyResolution:
        """Reuse bounded key evidence with explicit enrollment; otherwise fetch through the registry client."""
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
        """Invalidate key evidence, fetch it live, and populate the cache only after success."""
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
        """Read namespace metadata through the registry-origin-specific bounded cache."""
        registry_url = await self._registry_url_for_domain(domain)
        return await self._cached_read(
            cache_key=self._namespace_cache_key(domain, registry_url=registry_url),
            ttl_seconds=_NAMESPACE_CACHE_TTL_SECONDS,
            fetcher=lambda: self._get_namespace_at_origin(
                domain=domain, registry_url=registry_url
            ),
            encode=lambda value: None if value is None else _namespace_to_json(value),
            decode=lambda payload: (
                None if payload is None else _namespace_from_json(payload)
            ),
        )

    async def get_namespace_fresh(
        self,
        domain: str,
        *,
        registry_origin: str | None = None,
    ) -> Namespace | None:
        """Fetch live namespace authority; an explicit registry pin bypasses cached routing evidence."""
        if registry_origin is not None:
            return await RegistryClient.get_namespace_fresh(
                self, domain, registry_origin=registry_origin
            )
        registry_url = await self._registry_url_for_domain(domain)
        cache_key = self._namespace_cache_key(domain, registry_url=registry_url)
        await self._invalidate_keys(cache_key)
        value = await self._get_namespace_at_origin(
            domain=domain, registry_url=registry_url
        )
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
        """Read the complete address list through its registry-origin and generation-scoped cache."""
        registry_url = await self._registry_url_for_domain(domain)
        caller_did_key = None
        return await self._cached_read(
            cache_key=self._domain_addresses_cache_key(
                domain, registry_url=registry_url, caller_did_key=caller_did_key
            ),
            ttl_seconds=_ADDRESS_CACHE_TTL_SECONDS,
            generation_key=self._address_generation_key(domain, registry_url),
            fetcher=lambda: self._list_addresses_at_origin(
                domain=domain, registry_url=registry_url
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
        """Read an address through its bounded cache; only proven absence returns None."""
        registry_url = await self._registry_url_for_domain(domain)
        caller_did_key = None
        return await self._cached_read(
            cache_key=self._address_cache_key(
                domain, name, registry_url=registry_url, caller_did_key=caller_did_key
            ),
            ttl_seconds=_ADDRESS_CACHE_TTL_SECONDS,
            generation_key=self._address_generation_key(domain, registry_url),
            fetcher=lambda: self._resolve_address_at_origin(
                domain=domain, name=name, registry_url=registry_url
            ),
            encode=lambda value: None if value is None else _address_to_json(value),
            decode=lambda payload: (
                None if payload is None else _address_from_json(payload)
            ),
        )

    async def resolve_address_fresh(
        self,
        domain: str,
        name: str,
        *,
        signing_key: bytes | None = None,
        did_key: str | None = None,
    ) -> Address | None:
        """Invalidate the address cache and fetch current authority from the selected registry."""
        registry_url = await self._registry_url_for_domain(domain)
        cache_key = await self._generation_cache_key(
            self._address_cache_key(
                domain,
                name,
                registry_url=registry_url,
                caller_did_key=None,
            ),
            self._address_generation_key(domain, registry_url),
        )
        await self._invalidate_keys(cache_key)
        value = await self._resolve_address_at_origin(
            domain=domain, name=name, registry_url=registry_url
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
        """Read identity address bindings through the bounded stable-identity cache."""
        return await self._cached_read(
            cache_key=self._did_addresses_cache_key(did_aw),
            ttl_seconds=_ADDRESS_CACHE_TTL_SECONDS,
            fetcher=lambda: super(CachedRegistryClient, self).list_did_addresses(
                did_aw
            ),
            encode=lambda value: [_address_to_json(item) for item in value],
            decode=lambda payload: [_address_from_json(item) for item in payload],
        )

    async def get_team_public_key(self, domain: str, name: str) -> str | None:
        """Read controller authority with the revocation freshness/grace bounds.

        Refresh synchronously after freshness expires. Team metadata's longer
        TTL and stale-while-revalidate path must never authorize a controller.
        """
        ttl_seconds = _TEAM_REVOCATIONS_CACHE_TTL_SECONDS
        grace_seconds = _TEAM_REVOCATIONS_OUTAGE_GRACE_SECONDS
        origin = await self._team_read_origin(
            domain, name, fresh_seconds=ttl_seconds, outage_grace_seconds=grace_seconds
        )
        registry_url, lookup_error = origin.registry_url, origin.lookup_error
        cache_key = self._team_public_key_cache_key(
            domain, name, registry_url=registry_url
        )
        cached = await self._read_cache_entry(cache_key, decode=lambda value: value)
        fetched_at = (
            _cache_entry_fetched_at(cached, ttl_seconds) if cached is not None else None
        )
        if (
            lookup_error is None
            and cached is not None
            and fetched_at is not None
            and max(0, _cache_now() - fetched_at) < ttl_seconds
        ):
            await self._remember_team_read_origin(domain, name, origin)
            return cached["value"]
        try:
            if lookup_error is not None:
                raise lookup_error
            # Bind to HTTP, bypassing get_team's metadata cache entirely.
            team = await self._get_team_at_origin(
                domain=domain, name=name, registry_url=registry_url
            )
        except Exception as exc:
            if isinstance(exc, RegistryError) and exc.status_code in (401, 403):
                await self._invalidate_keys(cache_key)
                raise
            age = max(0, _cache_now() - fetched_at) if fetched_at is not None else None
            if cached is not None and age is not None and age <= grace_seconds:
                logger.warning(
                    "AWID team key refresh failed for team %s/%s; "
                    "serving last-known-good team key aged %ds "
                    "(outage grace bound %ds): %s",
                    domain,
                    name,
                    age,
                    grace_seconds,
                    exc,
                )
                return cached["value"]
            raise
        key = team.team_did_key if team is not None else None
        if not key:
            # A successful not-found read replaces prior authority; it is not
            # an outage and must not let that old key reappear during grace.
            await self._invalidate_keys(cache_key)
            await self._remember_team_read_origin(domain, name, origin)
            return None
        await self._write_cache_entry(
            cache_key,
            value=key,
            ttl_seconds=ttl_seconds,
            encode=lambda value: value,
            retention_seconds=ttl_seconds + grace_seconds,
        )
        await self._remember_team_read_origin(domain, name, origin)
        return key

    async def refresh_team_key_after_signature_failure(
        self,
        domain: str,
        name: str,
        *,
        rejected_key: str,
    ) -> str | None:
        """Retry a rejected cached key with bounded, coalesced registry work.

        The five-second Redis admission window starts before the attempt and
        is shared across clients. A client's callers share an in-flight task
        even if the attempt outlasts that window. An unchanged or failed read
        never renews the old key's fact age.
        """
        origin = await self._team_read_origin(
            domain, name, fresh_seconds=_TEAM_REVOCATIONS_CACHE_TTL_SECONDS
        )
        registry_url = origin.registry_url
        cache_key = self._team_public_key_cache_key(
            domain, name, registry_url=registry_url
        )
        task = self._team_key_signature_refreshes.get(cache_key)
        if task is None:
            task = asyncio.create_task(
                self._refresh_rejected_team_key(
                    domain,
                    name,
                    cache_key=cache_key,
                    registry_url=registry_url,
                    rejected_key=rejected_key,
                )
            )
            self._team_key_signature_refreshes[cache_key] = task
            task.add_done_callback(
                lambda _task: self._team_key_signature_refreshes.pop(cache_key, None)
            )
        key = await asyncio.shield(task)
        if key is not None:
            await self._remember_team_read_origin(domain, name, origin)
        return key

    async def _refresh_rejected_team_key(
        self,
        domain: str,
        name: str,
        *,
        cache_key: str,
        registry_url: str,
        rejected_key: str,
    ) -> str | None:
        try:
            cached = await self._read_cache_entry(cache_key, decode=lambda value: value)
            if (
                cached is not None
                and cached["fresh"]
                and cached["value"] != rejected_key
            ):
                return cached["value"]
            # The admission key is per registry/team, independent of the
            # reader's cache partition. No Redis means no attacker-driven read.
            admitted = await self.redis_client.set(
                f"awid:team_key_signature_refresh:{registry_url}:{domain}/{name}",
                "1",
                nx=True,
                ex=_TEAM_KEY_SIGNATURE_REFRESH_COOLDOWN_SECONDS,
            )
            if not admitted:
                return None
            key = await self.get_team_public_key_fresh(
                domain, name, registry_origin=registry_url
            )
            if key and key != rejected_key:
                await self._write_cache_entry(
                    cache_key,
                    value=key,
                    ttl_seconds=_TEAM_REVOCATIONS_CACHE_TTL_SECONDS,
                    retention_seconds=(
                        _TEAM_REVOCATIONS_CACHE_TTL_SECONDS
                        + _TEAM_REVOCATIONS_OUTAGE_GRACE_SECONDS
                    ),
                    encode=lambda value: value,
                )
                return key
        except Exception:
            logger.warning(
                "AWID team key signature-failure refresh failed for %s/%s",
                domain,
                name,
                exc_info=True,
            )
        return None

    async def get_team(self, domain: str, name: str) -> Team | None:
        origin = await self._team_read_origin(
            domain, name, fresh_seconds=_TEAM_METADATA_CACHE_TTL_SECONDS
        )
        registry_url = origin.registry_url
        team = await self._cached_read(
            cache_key=self._team_metadata_cache_key(
                domain, name, registry_url=registry_url
            ),
            ttl_seconds=_TEAM_METADATA_CACHE_TTL_SECONDS,
            fetcher=lambda: self._get_team_at_origin(
                domain=domain, name=name, registry_url=registry_url
            ),
            encode=lambda value: None if value is None else _team_to_json(value),
            decode=lambda payload: (
                None if payload is None else _team_from_json(payload)
            ),
        )
        await self._remember_team_read_origin(domain, name, origin)
        return team

    async def get_team_fresh(self, domain: str, name: str) -> Team | None:
        registry_url = await self._registry_url_for_domain(domain)
        cache_key = self._team_metadata_cache_key(
            domain, name, registry_url=registry_url
        )
        await self._invalidate_keys(cache_key)
        value = await self._get_team_at_origin(
            domain=domain, name=name, registry_url=registry_url
        )
        await self._write_cache_entry(
            cache_key,
            value=value,
            ttl_seconds=_TEAM_METADATA_CACHE_TTL_SECONDS,
            encode=lambda payload: None if payload is None else _team_to_json(payload),
        )
        return value

    async def get_team_revocations(self, domain: str, name: str) -> set[str]:
        """Read the complete revocation set under the documented freshness and outage-grace bounds."""
        return await self._cached_team_revocations(domain, name)

    async def get_team_revocations_for_certificates(
        self,
        domain: str,
        name: str,
        certificate_ids: list[str],
        *,
        fresh: bool = False,
    ) -> set[str]:
        """Local membership in the same complete CRL and freshness policy.

        The derived Redis index does not replace the evidence or make an
        exact-ID registry request. Fresh checks still fetch the complete CRL.
        """
        ids = list(dict.fromkeys(certificate_ids))
        if not ids:
            return set()
        if fresh:
            return (await self.get_team_revocations_fresh(domain, name)).intersection(
                ids
            )
        return await self._cached_team_revocations(domain, name, certificate_ids=ids)

    async def _cached_team_revocations(
        self,
        domain: str,
        name: str,
        *,
        certificate_ids: list[str] | None = None,
    ) -> set[str]:
        # Revocations get a dedicated read path rather than _cached_read: they
        # and controller keys have an outage grace (see
        # _TEAM_REVOCATIONS_OUTAGE_GRACE_SECONDS). Freshness, staleness, and
        # grace are all decided on the age of the cached data (its stored fetch
        # timestamp), never on Redis expiry alone.
        ttl_seconds = _TEAM_REVOCATIONS_CACHE_TTL_SECONDS
        grace_seconds = _TEAM_REVOCATIONS_OUTAGE_GRACE_SECONDS
        origin = await self._team_read_origin(
            domain, name, fresh_seconds=ttl_seconds, outage_grace_seconds=grace_seconds
        )
        registry_url, lookup_error = origin.registry_url, origin.lookup_error
        cache_key = self._team_revocations_cache_key(
            domain, name, registry_url=registry_url
        )
        retention_seconds = ttl_seconds + grace_seconds

        cached = None
        if certificate_ids is not None:
            cached = await revocation_cache.read(
                self.redis_client, cache_key, certificate_ids, now=_cache_now()
            )
        if cached is None:
            cached = await self._read_cache_entry(
                cache_key, decode=lambda payload: set(payload)
            )
            if cached is not None and certificate_ids is not None:
                # One cold upgrade/repair, under CAS and the old remaining TTL.
                # A failed repair never substitutes for the complete-list read.
                entry = {
                    **cached["payload"],
                    "fetched_at": _cache_entry_fetched_at(cached, ttl_seconds),
                }
                await revocation_cache.publish(
                    self.redis_client,
                    cache_key,
                    entry,
                    retention_seconds=retention_seconds,
                    expected=cached["raw"],
                )

        def project(value):
            return (
                value
                if certificate_ids is None
                else value.intersection(certificate_ids)
            )

        # Refresh the complete paginated set. A timestamp-only high-water mark
        # cannot safely order commits: PostgreSQL NOW() is transaction-start
        # time, so a revocation that waited on a row lock can commit after our
        # read with an older timestamp and be missed by an incremental `since`.
        async def fetch_revocations() -> set[str]:
            return (
                await self._scan_team_revocations(
                    domain, name, registry_url=registry_url
                )
            ).certificate_ids

        def encode_revocations(value: set[str]) -> list[str]:
            return sorted(value)

        cached_age: int | None = None
        if cached is not None:
            fetched_at = _cache_entry_fetched_at(cached, ttl_seconds)
            cached_age = max(0, _cache_now() - fetched_at)
            if lookup_error is None and cached["fresh"]:
                await self._remember_team_read_origin(domain, name, origin)
                return project(cached["value"])
            if lookup_error is None and cached_age <= ttl_seconds * _STALE_MULTIPLIER:
                # Serve bounded stale evidence while refreshing; record an
                # unsuccessful background refresh with the retained evidence age.
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
                    fetcher=fetch_revocations,
                    encode=encode_revocations,
                    retention_seconds=retention_seconds,
                    on_failure=_on_refresh_failure,
                ):
                    await self._remember_team_read_origin(domain, name, origin)
                    return project(cached["value"])

        try:
            if lookup_error is not None:
                raise lookup_error
            fresh_value = await fetch_revocations()
        except Exception as exc:
            if isinstance(exc, RegistryError) and exc.status_code in (401, 403):
                await self._invalidate_keys(cache_key)
                raise
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
                return project(cached["value"])
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
            encode=encode_revocations,
            retention_seconds=retention_seconds,
        )
        await self._remember_team_read_origin(domain, name, origin)
        return project(set(fresh_value))

    async def refresh_team_certificates_after_miss(
        self,
        domain: str,
        name: str,
        *,
        certificate_id: str,
    ) -> TeamCertificateStanding:
        """Establish the standing of a signature-verified certificate omitted by the cache."""
        if not isinstance(certificate_id, str) or not certificate_id.strip():
            raise ValueError(
                "The presented certificate ID is required on a registration miss."
            )
        loop = asyncio.get_running_loop()
        started = loop.time()
        state: _TeamCertificateMissState | None = None
        try:
            async with asyncio.timeout(self.timeout_seconds) as deadline:
                origin = await self._team_read_origin(
                    domain, name, fresh_seconds=_TEAM_CERTIFICATES_CACHE_TTL_SECONDS
                )
                registry_url = origin.registry_url
                generation_key = self._team_certificates_generation_key(
                    domain, name, registry_url=registry_url
                )
                cache_key = await self._generation_cache_key(
                    self._team_certificates_cache_key(
                        domain, name, active_only=False, registry_url=registry_url
                    ),
                    generation_key,
                )
                window_key = f"awid:team_certificates_miss_refresh:{self.registry_url}:{domain}/{name}"
                origin_digest = hashlib.sha256(registry_url.encode()).hexdigest()
                # Both writes must use the same captured generation.
                generation = cache_key.rsplit(":", 1)[-1]
                observation_key = (
                    f"{window_key}:observation:{origin_digest}:generation:{generation}"
                )
                digest = hashlib.sha256(
                    canonical_json_bytes(
                        {
                            "origin": registry_url,
                            "certificate_id": certificate_id,
                        }
                    )
                ).hexdigest()
                point_key = f"{cache_key}:point:{digest}"
                seconds, micros = await self.redis_client.time()
                request_time = seconds * _MICROSECONDS + micros
                state = self._team_certificate_miss_states.setdefault(
                    observation_key, _TeamCertificateMissState(observation_key)
                )
                state.readers += 1
                while True:
                    completed_before_read = state.completed_refresh
                    point = await self._read_cache_entry(
                        point_key, decode=TeamCertificateStanding
                    )
                    if point is not None and point["fresh"]:
                        return point["value"]

                    observation = await self._read_team_certificate_observation(
                        observation_key
                    )
                    if observation is not None:
                        standing = observation.standing(certificate_id)
                        if (
                            standing != TeamCertificateStanding.UNREGISTERED
                            or observation.started_us >= request_time
                        ):
                            return standing

                    refresh = state.refresh
                    if refresh is None or refresh.task.done():
                        if state.completed_refresh is not completed_before_read:
                            continue
                        admission = await self._admit_team_certificate_read(
                            window_key, allow_point=True
                        )
                        # A list producer may have started while we awaited
                        # Redis. Join it even if the admission window rolled.
                        refresh = state.refresh
                        if refresh is None or refresh.task.done():
                            # A producer may also have completed. Re-read its
                            # Redis evidence with the original freshness rules.
                            if state.completed_refresh is not completed_before_read:
                                continue
                            if admission == 0:
                                standing = (
                                    await self._cache_exact_team_certificate_standing(
                                        domain,
                                        name,
                                        certificate_id=certificate_id,
                                        registry_url=registry_url,
                                        cache_key=point_key,
                                    )
                                )
                                await self._remember_team_read_origin(
                                    domain, name, origin
                                )
                                return standing
                            task = asyncio.create_task(
                                self._refresh_missing_team_certificate(
                                    domain,
                                    name,
                                    registry_url=registry_url,
                                    cache_key=cache_key,
                                    observation_key=observation_key,
                                    window_key=window_key,
                                    wait_ms=max(admission, 0),
                                    requested_at=request_time,
                                    origin=origin,
                                )
                            )
                            refresh = _TeamCertificateMissRefresh(
                                task, waits_for_window=admission > 0
                            )
                            state.refresh = refresh
                            task.add_done_callback(
                                partial(
                                    self._finish_team_certificate_miss_refresh, state
                                )
                            )
                    if refresh.waits_for_window:
                        deadline.reschedule(
                            started
                            + self.timeout_seconds
                            + _TEAM_CERTIFICATES_MISS_WINDOW_SECONDS
                        )
                    observation = await asyncio.shield(refresh.task)
                    standing = observation.standing(certificate_id)
                    if (
                        standing != TeamCertificateStanding.UNREGISTERED
                        or observation.started_us >= request_time
                    ):
                        return standing
        except (RedisError, OSError) as exc:
            raise RegistryError(
                "AWID certificate existence refresh unavailable", status_code=503
            ) from exc
        finally:
            if state is not None:
                state.readers -= 1
                self._discard_idle_team_certificate_miss_state(state)

    def _finish_team_certificate_miss_refresh(
        self,
        state: _TeamCertificateMissState,
        task: asyncio.Task[_TeamCertificateObservation],
    ) -> None:
        if not task.cancelled():
            task.exception()  # Observe failures after every waiter was cancelled.
        self._discard_idle_team_certificate_miss_state(state)

    def _discard_idle_team_certificate_miss_state(
        self, state: _TeamCertificateMissState
    ) -> None:
        # Keep the completed task identity while an overlapping reader may
        # still be acting on a cache miss observed before it completed.
        if state.readers or (
            state.refresh is not None and not state.refresh.task.done()
        ):
            return
        if self._team_certificate_miss_states.get(state.observation_key) is state:
            self._team_certificate_miss_states.pop(state.observation_key)

    async def _read_team_certificate_observation(
        self, cache_key: str
    ) -> _TeamCertificateObservation | None:
        cached = await self._read_cache_entry(
            cache_key,
            decode=lambda value: _TeamCertificateObservation(**value),
        )
        return cached["value"] if cached is not None and cached["fresh"] else None

    async def _admit_team_certificate_read(
        self, window_key: str, *, allow_point: bool
    ) -> int:
        """Return -1 for a list slot, 0 for a point slot, or the wait in milliseconds."""
        return await cast(
            Awaitable[int],
            self.redis_client.eval(
                _TEAM_CERTIFICATE_READ_ADMISSION,
                1,
                window_key,
                _TEAM_CERTIFICATES_MISS_WINDOW_SECONDS,
                _TEAM_CERTIFICATES_POINT_LIMIT,
                int(allow_point),
            ),
        )

    async def _refresh_missing_team_certificate(
        self,
        domain: str,
        name: str,
        *,
        registry_url: str,
        cache_key: str,
        observation_key: str,
        window_key: str,
        wait_ms: int,
        requested_at: int,
        origin: _TeamReadOrigin,
    ) -> _TeamCertificateObservation:
        wait_allowance = _TEAM_CERTIFICATES_MISS_WINDOW_SECONDS if wait_ms else 0
        async with asyncio.timeout(self.timeout_seconds + wait_allowance):
            while wait_ms > 0:
                # Only this worker's shared producer probes Redis. A peer
                # worker may finish and publish before its window expires.
                await asyncio.sleep(min(wait_ms / 1000, 0.1))
                observation = await self._read_team_certificate_observation(
                    observation_key
                )
                if observation is not None and observation.started_us >= requested_at:
                    return observation
                wait_ms = await self._admit_team_certificate_read(
                    window_key, allow_point=False
                )
            observation = await self._fetch_team_certificate_miss_list(
                domain,
                name,
                registry_url=registry_url,
                cache_key=cache_key,
                observation_key=observation_key,
            )
            await self._remember_team_read_origin(domain, name, origin)
            return observation

    async def _fetch_team_certificate_miss_list(
        self,
        domain: str,
        name: str,
        *,
        registry_url: str,
        cache_key: str,
        observation_key: str,
    ) -> _TeamCertificateObservation:
        async with asyncio.timeout(self.timeout_seconds):
            seconds, micros = await self.redis_client.time()
            observed = seconds * _MICROSECONDS + micros
            try:
                certificates = await self.list_team_certificates_fresh(
                    domain,
                    name,
                    active_only=False,
                    registry_url=registry_url,
                )
            except RegistryError as exc:
                if not is_team_not_found(exc.status_code, exc.body):
                    raise
                certificates = []
            await self._write_cache_entry(
                cache_key,
                value=certificates,
                ttl_seconds=_TEAM_CERTIFICATES_CACHE_TTL_SECONDS,
                encode=lambda value: [
                    _team_certificate_to_json(item) for item in value
                ],
                require_write=True,
            )
            observation = _TeamCertificateObservation(
                observed,
                {
                    cert.certificate_id: bool(cert.revoked_at)
                    for cert in certificates
                    if cert.certificate_id
                },
            )
            # Only exact standing is shared across credential partitions. The
            # list with member metadata stays in the reader's authorized cache.
            await self._write_cache_entry(
                observation_key,
                value=observation,
                encode=asdict,
                require_write=True,
                ttl_seconds=_TEAM_CERTIFICATES_MISS_WINDOW_SECONDS,
                retention_seconds=_TEAM_CERTIFICATES_MISS_WINDOW_SECONDS,
            )
            return observation

    async def _cache_exact_team_certificate_standing(
        self,
        domain: str,
        name: str,
        *,
        certificate_id: str,
        registry_url: str,
        cache_key: str,
    ) -> TeamCertificateStanding:
        try:
            status = await self.get_team_certificate_status_fresh(
                domain,
                name,
                certificate_id,
                registry_url=registry_url,
                budgeted=True,
            )
        except RegistryError as exc:
            if 400 <= exc.status_code < 500 and exc.status_code != 429:
                raise RegistryError(
                    "AWID certificate status unavailable", status_code=503
                ) from exc
            raise
        except ValueError as exc:
            raise RegistryError(
                "Invalid AWID certificate status response", status_code=502
            ) from exc
        if status is None:
            standing = evaluate_team_certificate_standing(
                revoked=False, registered=False
            )
            ttl = _TEAM_CERTIFICATES_NEGATIVE_TTL_SECONDS
        else:
            if not isinstance(status, dict):
                raise RegistryError(
                    "Invalid AWID certificate status response", status_code=502
                )
            state, revoked_at = status.get("status"), status.get("revoked_at")
            reported_team_key = status.get("team_did_key")
            if (
                status.get("team_id") != build_team_id(domain, name)
                or not isinstance(reported_team_key, str)
                or not reported_team_key
                or (state, revoked_at is None)
                not in (("active", True), ("revoked", False))
                or (revoked_at is not None and not isinstance(revoked_at, str))
            ):
                raise RegistryError(
                    "Invalid AWID certificate status response", status_code=502
                )
            standing = evaluate_team_certificate_standing(
                revoked=state == "revoked",
                registered=True,
            )
            ttl = _TEAM_CERTIFICATES_POINT_TTL_SECONDS
        # A point observation never changes the age or completeness of a list.
        await self._write_cache_entry(
            cache_key,
            value=standing,
            ttl_seconds=ttl,
            retention_seconds=ttl,
            encode=lambda value: value,
            require_write=True,
        )
        return standing

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
        origin = await self._team_read_origin(
            domain, name, fresh_seconds=_TEAM_CERTIFICATES_CACHE_TTL_SECONDS
        )
        registry_url = origin.registry_url

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

        certificates = await self._cached_read(
            cache_key=self._team_certificates_cache_key(
                domain,
                name,
                active_only=active_only,
                signing_key=signing_key,
                registry_url=registry_url,
            ),
            ttl_seconds=_TEAM_CERTIFICATES_CACHE_TTL_SECONDS,
            generation_key=self._team_certificates_generation_key(
                domain, name, registry_url=registry_url
            ),
            fetcher=lambda: self._list_team_certificates_at_origin(
                domain=domain,
                name=name,
                registry_url=registry_url,
                active_only=active_only,
                signing_key=signing_key,
            ),
            encode=lambda value: [_team_certificate_to_json(item) for item in value],
            decode=lambda payload: [
                _team_certificate_from_json(item) for item in payload
            ],
            on_refresh_failure=_on_refresh_failure,
        )
        await self._remember_team_read_origin(domain, name, origin)
        return certificates

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
        """Invalidate certificate evidence before and after submitting the registration."""
        await self._invalidate_team_certificate_cache_keys(
            domain,
            name,
            tolerate_unavailable=True,
        )
        try:
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
        finally:
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
        """Invalidate revocation evidence around the exact certificate revocation."""
        await self._invalidate_team_certificate_cache_keys(
            domain, name, tolerate_unavailable=True
        )
        await self._invalidate_keys(self._team_revocations_cache_key(domain, name))
        try:
            await super().revoke_team_certificate(
                domain,
                name,
                team_controller_signing_key=team_controller_signing_key,
                certificate_id=certificate_id,
            )
        finally:
            await self._invalidate_team_certificate_cache_keys(
                domain,
                name,
                tolerate_unavailable=True,
            )
            await self._invalidate_keys(self._team_revocations_cache_key(domain, name))

    async def invalidate_team_certificate_cache(self, domain: str, name: str) -> None:
        """Invalidate certificate generations and the team revocation and key cache entries."""
        try:
            await self._invalidate_team_certificate_cache_keys(domain, name)
        finally:
            await self._invalidate_keys(
                self._team_revocations_cache_key(domain, name),
                self._team_public_key_cache_key(domain, name),
            )

    async def _register_initial_did(
        self, entry: dict[str, Any], signer: PayloadSigner
    ) -> Any:
        cache_key = self._did_key_cache_key(entry["did_aw"])
        await self._invalidate_keys(cache_key)
        answer = await super()._register_initial_did(entry, signer)
        await self._invalidate_keys(cache_key)
        return answer

    async def register_id_certificate(
        self,
        bundle: dict[str, Any],
        *,
        signer: PayloadSigner,
        expected_head: str | None,
        invitation_id: str | None,
    ) -> dict[str, Any]:
        """Invalidate domain status evidence around the identity-tree registration."""
        domain = bundle["certificates"][-1]["certificate"]["domain"]
        await self._invalidate_id_status_cache(domain)
        try:
            receipt = await super().register_id_certificate(
                bundle,
                signer=signer,
                expected_head=expected_head,
                invitation_id=invitation_id,
            )
        finally:
            await self._invalidate_id_status_cache(domain)
        return receipt

    async def revoke_id_certificate(
        self,
        domain: str,
        id: str,
        *,
        signer: PayloadSigner,
        expected_head: str | None,
        effective_from: str | None = None,
    ) -> dict[str, Any]:
        """Invalidate domain status evidence around the identity-tree revocation."""
        await self._invalidate_id_status_cache(domain)
        try:
            receipt = await super().revoke_id_certificate(
                domain,
                id,
                signer=signer,
                expected_head=expected_head,
                effective_from=effective_from,
            )
        finally:
            await self._invalidate_id_status_cache(domain)
        return receipt

    async def rotate_key(
        self,
        did_aw: str,
        new_did_key: str,
        old_signing_key: bytes,
        new_signing_key: bytes,
    ) -> DIDMapping:
        """Invalidate key evidence before rotation and again after the mapping is returned."""
        await self._invalidate_keys(self._did_key_cache_key(did_aw))
        mapping = await super().rotate_key(
            did_aw, new_did_key, old_signing_key, new_signing_key
        )
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
        """Invalidate namespace evidence before and after controller-authorized registration."""
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
        """Invalidate namespace evidence around the signed delivery-origin update."""
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
        """Invalidate team metadata and revocations around namespace-authorized registration."""
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
        """Invalidate team metadata before and after the team-authorized visibility update."""
        cache_key = self._team_metadata_cache_key(domain, name)
        await self._invalidate_keys(cache_key)
        team = await super().set_team_visibility(
            domain, name, visibility, team_controller_signing_key
        )
        await self._invalidate_keys(cache_key)
        return team

    async def delete_team(
        self,
        domain: str,
        name: str,
        namespace_controller_signing_key: bytes,
    ) -> dict[str, Any]:
        """Invalidate team evidence before and after namespace-authorized deletion."""
        await self._invalidate_team_cache(domain, name)
        result = await super().delete_team(
            domain, name, namespace_controller_signing_key
        )
        await self._invalidate_team_cache(domain, name)
        return result

    async def rotate_namespace_controller(
        self,
        domain: str,
        new_controller_did: str,
        new_controller_signing_key: bytes,
        parent_signing_key: bytes | None = None,
    ) -> Namespace:
        """Invalidate namespace evidence around the controller rotation."""
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
        """Invalidate namespace evidence around the dual-signed controller rotation."""
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
        """Invalidate identity and address evidence around registration, including uncertain failures."""
        await self._invalidate_keys(self._did_key_cache_key(did_aw))
        await self._invalidate_address_cache(domain=domain, name=name, did_aws=[])
        address = None
        try:
            address = await super().register_address(
                domain,
                name,
                did_aw,
                controller_signing_key,
                current_did_key,
            )
        finally:
            await self._invalidate_address_cache(
                domain=domain,
                name=name,
                did_aws=[address.did_aw] if address is not None else [],
            )
        return address

    async def update_address(
        self,
        domain: str,
        name: str,
        controller_signing_key: bytes,
    ) -> Address:
        """Invalidate address evidence around the controller update, including uncertain failures."""
        await self._invalidate_address_cache(domain=domain, name=name, did_aws=[])
        address = None
        try:
            address = await super().update_address(
                domain,
                name,
                controller_signing_key,
            )
        finally:
            await self._invalidate_address_cache(
                domain=domain,
                name=name,
                did_aws=[address.did_aw] if address is not None else [],
            )
        return address

    async def delete_address(
        self,
        domain: str,
        name: str,
        controller_signing_key: bytes,
    ) -> None:
        registry_url = canonical_server_origin(self.registry_url)
        previous = await self._resolve_address_at_origin(
            domain=domain,
            name=name,
            registry_url=canonical_server_origin(self.registry_url),
        )
        if previous is None:
            cached_key = await self._generation_cache_key(
                self._address_cache_key(
                    domain, name, registry_url=registry_url, caller_did_key=None
                ),
                self._address_generation_key(domain, registry_url),
            )
            previous = await self._peek_cached_address(cached_key)
        did_aws = [previous.did_aw] if previous is not None else []
        await self._invalidate_address_cache(domain=domain, name=name, did_aws=did_aws)
        try:
            await super().delete_address(domain, name, controller_signing_key)
        finally:
            await self._invalidate_address_cache(
                domain=domain, name=name, did_aws=did_aws
            )

    async def reassign_address(
        self,
        domain: str,
        name: str,
        new_did_aw: str,
        controller_signing_key: bytes,
    ) -> Address:
        """Invalidate both identities' address evidence around reassignment, including uncertain failures."""
        await self._invalidate_keys(self._did_key_cache_key(new_did_aw))
        previous = await self._resolve_address_at_origin(
            domain=domain,
            name=name,
            registry_url=canonical_server_origin(self.registry_url),
        )
        did_aws = [new_did_aw]
        if previous is not None and previous.did_aw != new_did_aw:
            did_aws.append(previous.did_aw)
        await self._invalidate_address_cache(domain=domain, name=name, did_aws=did_aws)
        try:
            return await super().reassign_address(
                domain, name, new_did_aw, controller_signing_key
            )
        finally:
            await self._invalidate_address_cache(
                domain=domain, name=name, did_aws=did_aws
            )

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
        generation_key: str | None = None,
    ) -> Any:
        # on_refresh_failure is opt-in: a tier that passes nothing keeps the
        # silent debug line _refresh_cache_entry falls back to. When given, it
        # is called with the exception and the age of the data still being
        # served, measured from the entry's stored fetch timestamp.
        # reusable, when given, decides whether a cached value may be served at
        # all; one it rejects is fetched fresh as though nothing were cached.
        if generation_key is not None:
            cache_key = await self._generation_cache_key(cache_key, generation_key)
        cached_payload = await self._read_cache_entry(cache_key, decode=decode)
        if (
            cached_payload is not None
            and reusable is not None
            and not reusable(cached_payload["value"])
        ):
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
                "raw": raw,
            }
        except Exception:
            logger.warning(
                "Invalid AWID cache payload for %s; dropping entry", cache_key
            )
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
        require_write: bool = False,
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
        if revocation_cache.is_revocation_key(
            cache_key, prefix=self._team_revocations_cache_key_prefix()
        ):
            if await revocation_cache.publish(
                self.redis_client, cache_key, entry, retention_seconds=retention_seconds
            ):
                return
            # No usable index: keep the ordinary complete-list cache. A plain
            # entry lacks the version prefix, so an old index cannot answer.
            await self._invalidate_keys(*revocation_cache.index_keys(cache_key))
        if require_write:
            if not await self.redis_client.set(
                cache_key, payload, ex=retention_seconds
            ):
                raise RegistryError(
                    "AWID certificate existence cache write failed", status_code=503
                )
        else:
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

        def discard_completed_refresh(_task: asyncio.Task[None]) -> None:
            self._refresh_tasks.pop(cache_key, None)

        task.add_done_callback(discard_completed_refresh)
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
            if isinstance(exc, RegistryError) and exc.status_code in (401, 403):
                await self._invalidate_keys(cache_key)
                logger.warning(
                    "AWID cache refresh authorization refused for %s", cache_key
                )
                return
            if on_failure is not None:
                on_failure(exc)
            else:
                logger.debug(
                    "AWID cache refresh failed for %s", cache_key, exc_info=True
                )

    async def _peek_cached_address(self, cache_key: str) -> Address | None:
        cached_payload = await self._read_cache_entry(
            cache_key,
            decode=lambda payload: (
                None if payload is None else _address_from_json(payload)
            ),
        )
        if cached_payload is None:
            return None
        return cached_payload["value"]

    async def _invalidate_team_cache(self, domain: str, name: str) -> None:
        await self._invalidate_team_certificate_cache_keys(
            domain, name, tolerate_unavailable=True
        )
        await self._invalidate_keys(
            self._team_metadata_cache_key(domain, name),
            self._team_public_key_cache_key(domain, name),
            self._team_revocations_cache_key(domain, name),
        )

    async def _invalidate_namespace_cache(self, domain: str) -> None:
        registry_url = canonical_server_origin(self.registry_url)
        await self._invalidate_keys(
            self._namespace_cache_key(domain, registry_url=registry_url)
        )

    async def _invalidate_address_cache(
        self,
        *,
        domain: str,
        name: str,
        did_aws: list[str],
        registry_url: str | None = None,
    ) -> None:
        registry_url = registry_url or canonical_server_origin(self.registry_url)
        await self._invalidate_generation(
            self._address_generation_key(domain, registry_url)
        )
        await self._invalidate_keys(
            *(self._did_addresses_cache_key(did_aw) for did_aw in did_aws)
        )

    async def _invalidate_id_status_cache(self, domain: str) -> None:
        await self._invalidate_generation(self._id_status_generation_key(domain))

    async def _invalidate_keys(self, *keys: str) -> None:
        expanded = list(keys)
        for key in keys:
            if key and revocation_cache.is_revocation_key(
                key, prefix=self._team_revocations_cache_key_prefix()
            ):
                expanded.extend(revocation_cache.index_keys(key))
        unique_keys = tuple(dict.fromkeys(key for key in expanded if key))
        if not unique_keys:
            return
        try:
            await self.redis_client.delete(*unique_keys)
        except (RedisError, OSError):
            logger.debug(
                "AWID cache invalidation skipped because Redis is unavailable",
                exc_info=True,
            )

    async def _invalidate_team_certificate_cache_keys(
        self,
        domain: str,
        name: str,
        *,
        tolerate_unavailable: bool = False,
    ) -> None:
        await self._invalidate_generation(
            self._team_certificates_generation_key(domain, name),
            tolerate_unavailable=tolerate_unavailable,
        )
        # R9's list generation also discards the derived CRL index. The full
        # CRL retains its own freshness; a later membership read can backfill
        # from it without making another registry request.
        await self._invalidate_keys(
            *revocation_cache.index_keys(self._team_revocations_cache_key(domain, name))
        )

    async def _invalidate_generation(
        self, key: str, *, tolerate_unavailable: bool = True
    ) -> None:
        try:
            if not await self.redis_client.set(
                key, uuid4().hex, ex=_CACHE_GENERATION_TTL_SECONDS
            ):
                raise RedisError("AWID cache generation write failed")
        except (RedisError, OSError):
            if not tolerate_unavailable:
                raise
            logger.debug(
                "AWID cache invalidation skipped because Redis is unavailable",
                exc_info=True,
            )

    async def _generation_cache_key(self, cache_key: str, generation_key: str) -> str:
        # Snapshot before acquisition. An older producer can only write its old
        # token's key; invalidation never lets it repopulate the current cache.
        token = await self._read_cache_generation(generation_key)
        return self._cache_key_at_generation(cache_key, token)

    @staticmethod
    def _cache_key_at_generation(cache_key: str, token: str) -> str:
        return f"{cache_key}:generation:{token}"

    async def _read_cache_generation(self, generation_key: str) -> str:
        token = None
        try:
            token = await self.redis_client.get(generation_key)
            if token is None:
                await self.redis_client.set(
                    generation_key,
                    uuid4().hex,
                    nx=True,
                    ex=_CACHE_GENERATION_TTL_SECONDS,
                )
                token = await self.redis_client.get(generation_key)
            if isinstance(token, bytes):
                token = token.decode("ascii")
        except (RedisError, OSError, UnicodeError):
            logger.debug("AWID cache generation unavailable", exc_info=True)
        if (
            not isinstance(token, str)
            or len(token) != 32
            or any(c not in "0123456789abcdef" for c in token)
        ):
            # Unknown/lost metadata must not select any retained evidence.
            token = uuid4().hex
        return token

    def _id_status_generation_key(
        self, domain: str, *, registry_url: str | None = None
    ) -> str:
        origin = canonical_server_origin(registry_url or self.registry_url)
        return f"awid:cache_generation:id_status:{origin}:{domain}"

    def _address_generation_key(self, domain: str, registry_url: str) -> str:
        return f"awid:cache_generation:addresses:{registry_url}:{domain}"

    def _team_certificates_generation_key(
        self, domain: str, name: str, *, registry_url: str | None = None
    ) -> str:
        origin = canonical_server_origin(registry_url or self.registry_url)
        return f"awid:cache_generation:team_certificates:{origin}:{domain}/{name}"

    async def _redis_get(self, key: str) -> str | None:
        try:
            value = await self.redis_client.get(key)
        except (RedisError, OSError):
            logger.debug(
                "AWID cache read skipped because Redis is unavailable", exc_info=True
            )
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
            logger.debug(
                "AWID cache write skipped because Redis is unavailable", exc_info=True
            )

    # Value-key versions isolate entries written before answering-origin pinning.
    # They must not be reused as evidence after this cache-owner upgrade.
    def _id_status_route_key(self, request: dict[str, Any]) -> str:
        digest = hashlib.sha256(canonical_json_bytes(request)).hexdigest()
        return self._registry_route_key("id_status", f"{request['domain']}:{digest}")

    def _team_registry_route_key(self, domain: str, name: str) -> str:
        return self._registry_route_key("team", build_team_id(domain, name))

    def _registry_route_key(self, kind: str, scope: str) -> str:
        origin = canonical_server_origin(self.registry_url)
        return f"awid:registry_route:v1:{kind}:{origin}:{scope}"

    def _id_status_cache_key(
        self, request: dict[str, Any], *, registry_url: str | None = None
    ) -> str:
        digest = hashlib.sha256(canonical_json_bytes(request)).hexdigest()
        return f"{self._id_status_cache_key_prefix(request['domain'], registry_url=registry_url)}:{digest}"

    def _id_status_cache_key_prefix(
        self, domain: str, *, registry_url: str | None = None
    ) -> str:
        origin = canonical_server_origin(registry_url or self.registry_url)
        return f"awid:registry_cache:v3:id_status:{origin}:{domain}"

    def _did_key_cache_key(self, did_aw: str) -> str:
        return f"awid:registry_cache:v1:did_key:{self.registry_url}:{did_aw}"

    def _did_addresses_cache_key(self, did_aw: str) -> str:
        return f"awid:registry_cache:v1:did_addresses:{self.registry_url}:{did_aw}"

    def _namespace_cache_key(self, domain: str, *, registry_url: str) -> str:
        return f"awid:registry_cache:v2:namespace:{registry_url}:{domain}"

    def _domain_addresses_cache_key(
        self, domain: str, *, registry_url: str, caller_did_key: str | None
    ) -> str:
        return f"{self._domain_addresses_cache_key_prefix(domain, registry_url=registry_url)}:{_lookup_cache_scope(caller_did_key)}"

    def _domain_addresses_cache_key_prefix(
        self, domain: str, *, registry_url: str
    ) -> str:
        return f"awid:registry_cache:v3:domain_addresses:{registry_url}:{domain}"

    def _address_cache_key(
        self, domain: str, name: str, *, registry_url: str, caller_did_key: str | None
    ) -> str:
        return f"{self._address_cache_key_prefix(domain, name, registry_url=registry_url)}:{_lookup_cache_scope(caller_did_key)}"

    def _address_cache_key_prefix(
        self, domain: str, name: str, *, registry_url: str
    ) -> str:
        return f"awid:registry_cache:v4:address:{registry_url}:{domain}:{name}"

    def _team_reader_cache_suffix(self, domain: str, name: str) -> str:
        if not self.member_signing_keys or self.service_token:
            return ""
        key = self.member_signing_keys.get(build_team_id(domain, name))
        return ":member-reader:" + (
            did_key_from_signing_key(key) if key is not None else "anon"
        )

    def _team_metadata_cache_key(
        self, domain: str, name: str, *, registry_url: str | None = None
    ) -> str:
        origin = canonical_server_origin(registry_url or self.registry_url)
        return f"awid:registry_cache:v3:team:{origin}:{domain}/{name}{self._team_reader_cache_suffix(domain, name)}"

    def _team_revocations_cache_key_prefix(self) -> str:
        # Match every answering-origin partition for index publication/invalidation.
        return "awid:registry_cache:v3:team_revocations:"

    def _team_revocations_cache_key(
        self, domain: str, name: str, *, registry_url: str | None = None
    ) -> str:
        origin = canonical_server_origin(registry_url or self.registry_url)
        return f"{self._team_revocations_cache_key_prefix()}{origin}:{domain}/{name}{self._team_reader_cache_suffix(domain, name)}"

    def _team_public_key_cache_key(
        self, domain: str, name: str, *, registry_url: str | None = None
    ) -> str:
        origin = canonical_server_origin(registry_url or self.registry_url)
        return f"awid:registry_cache:v2:team_public_key:{origin}:{domain}/{name}{self._team_reader_cache_suffix(domain, name)}"

    def _team_certificates_cache_key(
        self,
        domain: str,
        name: str,
        *,
        active_only: bool,
        signing_key: bytes | None = None,
        registry_url: str | None = None,
    ) -> str:
        suffix = "active" if active_only else "all"
        return (
            f"{self._team_certificates_cache_key_prefix(domain, name, registry_url=registry_url)}:"
            f"{suffix}:{self._team_certificates_cache_scope(signing_key)}"
        )

    def _team_certificates_cache_key_prefix(
        self, domain: str, name: str, *, registry_url: str | None = None
    ) -> str:
        origin = canonical_server_origin(registry_url or self.registry_url)
        return f"awid:registry_cache:v3:team_certificates:{origin}:{domain}/{name}{self._team_reader_cache_suffix(domain, name)}"

    def _team_certificates_cache_scope(self, signing_key: bytes | None) -> str:
        if signing_key is not None:
            return did_key_from_signing_key(signing_key)
        if self.service_token is not None:
            token_digest = hashlib.sha256(
                self.service_token.encode("utf-8")
            ).hexdigest()
            return f"service-sha256:{token_digest}"
        return "anon"


def _utc_timestamp() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _lookup_cache_scope(caller_did_key: str | None) -> str:
    normalized = (caller_did_key or "").strip()
    return normalized or "anon"


def _cache_now() -> int:
    return int(time.time())


def _monotonic_ns() -> int:
    return time.monotonic_ns()


def _whole_seconds_up(nanoseconds: int) -> int:
    """Whole seconds, rounded up, so an age never reads younger than it is."""
    return -(-nanoseconds // 1_000_000_000)


@dataclass(frozen=True)
class _IDStatusRefresh:
    """One status refresh: the entry and its age now, or none when it failed."""

    entry: dict[str, Any] | None
    age: int | None


async def _payload_signature(
    signer: PayloadSigner, payload: bytes, expected_key: str | None
) -> tuple[str, bytes]:
    """The signer's (did:key, signature) for ``payload``, verified with the strict ID profile."""
    answer = signer(payload)
    if inspect.isawaitable(answer):
        answer = await answer
    if type(answer) is not tuple or len(answer) != 2:
        raise ValueError("signer must answer (did_key, signature)")
    did_key, signature = answer
    if expected_key is not None and did_key != expected_key:
        raise ValueError(
            "signer answered with a key other than the one named for its role"
        )
    try:
        verify_ed25519(did_key, payload, signature)
    except IDCertificateError as exc:
        raise ValueError(f"signer answer refused: {exc.code}") from exc
    return did_key, signature


def _id_status_evidence(entry: dict[str, Any], *, age: int | None) -> IDChainEvidence:
    # The age is never clamped: a negative one is unavailable evidence to the verifier.
    return IDChainEvidence(
        status=entry["status"],
        namespace_authority=entry["namespace_authority"],
        age_seconds=age,
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


def _assert_signing_key_matches(expected_did: str, signing_key: bytes) -> None:
    actual_did = did_key_from_signing_key(signing_key)
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
    return IDTreeEnrollment(
        enrolled=parsed["state"] == "enrolled", domain=parsed["domain"]
    )


def _id_tree_enrollment_to_json(value: IDTreeEnrollment) -> dict[str, Any]:
    return (
        {"enrolled": True, "domain": value.domain}
        if value.enrolled
        else {"enrolled": False}
    )


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
        **(
            {}
            if value.id_tree is None
            else {"id_tree": _id_tree_enrollment_to_json(value.id_tree)}
        ),
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
        identity_scope=normalize_identity_scope(
            data.get("identity_scope") or data.get("lifetime")
        ),
        issued_at=data["issued_at"],
        revoked_at=data.get("revoked_at"),
    )


def _team_certificate_to_json(value: TeamCertificate) -> dict[str, Any]:
    return asdict(value)
