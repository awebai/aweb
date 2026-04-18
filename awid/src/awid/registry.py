"""HTTP client for the external AWID registry."""

from __future__ import annotations

import asyncio
import fnmatch
import json
import logging
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

import httpx
from nacl.signing import SigningKey
from redis.asyncio import Redis
from redis.exceptions import RedisError

from awid.did import did_from_public_key, stable_id_from_did_key
from awid.log import (
    canonical_server_origin,
    identity_state_hash,
    log_entry_payload,
)
from awid.signing import canonical_json_bytes, sign_message


DomainRegistryResolver = Callable[[str], Awaitable[str]]

logger = logging.getLogger(__name__)

_ADDRESS_CACHE_TTL_SECONDS = 5 * 60
_NAMESPACE_CACHE_TTL_SECONDS = 15 * 60
_DID_KEY_CACHE_TTL_SECONDS = 5 * 60
_TEAM_METADATA_CACHE_TTL_SECONDS = 10 * 60  # 10 minutes
_TEAM_REVOCATIONS_CACHE_TTL_SECONDS = 10 * 60  # 10 minutes
_TEAM_CERTIFICATES_CACHE_TTL_SECONDS = 10 * 60  # 10 minutes
# Keep stale entries for one additional TTL window so callers can get
# stale-while-revalidate behavior instead of taking a hard miss immediately.
_STALE_MULTIPLIER = 2


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


@dataclass(frozen=True)
class Namespace:
    namespace_id: str
    domain: str
    controller_did: str | None
    verification_status: str
    last_verified_at: str | None
    created_at: str


@dataclass(frozen=True)
class Address:
    address_id: str
    domain: str
    name: str
    did_aw: str
    current_did_key: str
    reachability: str
    created_at: str
    visible_to_team_id: str | None = None


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
    lifetime: str
    issued_at: str
    revoked_at: str | None = None


class RegistryError(Exception):
    def __init__(self, message: str, *, status_code: int, detail: str | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.detail = detail or message


class AlreadyRegisteredError(RegistryError):
    def __init__(self, *, did_aw: str, existing_did_key: str) -> None:
        self.did_aw = did_aw
        self.existing_did_key = existing_did_key
        super().__init__(
            f"DID already registered: {did_aw}",
            status_code=409,
            detail="did_aw already registered",
        )


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
    _http_client: httpx.AsyncClient = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "_http_client",
            httpx.AsyncClient(
                timeout=self.timeout_seconds,
                transport=self.transport,
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
        from awid.dns_verify import DnsVerificationError, discover_registry_override

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
        registry_url: str | None = None,
    ) -> dict[str, Any]:
        response = await self._http_client.request(
            method,
            f"{self._resolved_base_url(registry_url=registry_url)}{path}",
            headers=headers,
            json=json,
        )
        if not 200 <= response.status_code < 300:
            detail = None
            try:
                detail = response.json().get("detail")
            except Exception:
                detail = None
            if response.status_code == 409:
                if detail == "did_aw must be registered before address assignment":
                    raise DIDRegistrationRequiredError()
                if detail == "did_aw current key does not match":
                    raise DIDCurrentKeyMismatchError()
                if detail == "address already bound to a different did_aw":
                    raise AddressAlreadyBoundError()
            raise RegistryError(
                detail or response.text,
                status_code=response.status_code,
                detail=detail or response.text,
            )
        if not response.content:
            return {}
        return response.json()

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
        return _key_resolution_from_json(await self._request_json("GET", f"/v1/did/{did_aw}/key"))

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
    ) -> Namespace:
        registry_url = await self._registry_url_for_domain(domain)
        _assert_signing_key_matches(controller_did, controller_signing_key)
        headers = self._signed_namespace_headers(
            domain=domain,
            operation="register",
            signing_key=controller_signing_key,
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
                json={"domain": domain, "controller_did": controller_did},
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
        reachability: str,
        visible_to_team_id: str | None = None,
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
                    "reachability": reachability,
                    **(
                        {}
                        if visible_to_team_id is None
                        else {"visible_to_team_id": visible_to_team_id}
                    ),
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
            headers=self._signed_address_lookup_headers(
                domain=domain,
                name=name,
                operation="get_address",
                signing_key=signing_key,
                did_key=did_key,
            ),
            registry_url=await self._registry_url_for_domain(domain),
        )
        return None if data is None else _address_from_json(data)

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
            headers=self._signed_address_lookup_headers(
                domain=domain,
                name=None,
                operation="list_addresses",
                signing_key=signing_key,
                did_key=did_key,
            ),
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

    async def get_team_revocations(self, domain: str, name: str) -> set[str]:
        """Fetch the set of revoked certificate IDs for a team.

        GET /v1/namespaces/{domain}/teams/{name}/revocations
        Returns set of certificate_id strings.
        """
        try:
            data = await self._request_json(
                "GET",
                f"/v1/namespaces/{domain}/teams/{name}/revocations",
                registry_url=await self._registry_url_for_domain(domain),
            )
        except RegistryError as exc:
            if exc.status_code == 404:
                return set()
            raise
        return {r["certificate_id"] for r in data.get("revocations", [])}

    async def list_team_certificates(
        self,
        domain: str,
        name: str,
        *,
        active_only: bool = True,
    ) -> list[TeamCertificate]:
        path = f"/v1/namespaces/{domain}/teams/{name}/certificates"
        if active_only:
            path += "?active_only=true"
        data = await self._request_json(
            "GET",
            path,
            registry_url=await self._registry_url_for_domain(domain),
        )
        return [_team_certificate_from_json(item) for item in data.get("certificates", [])]

    async def update_address(
        self,
        domain: str,
        name: str,
        controller_signing_key: bytes,
        reachability: str | None = None,
        visible_to_team_id: str | None = None,
    ) -> Address:
        registry_url = await self._registry_url_for_domain(domain)
        payload: dict[str, Any] = {}
        if reachability is not None:
            payload["reachability"] = reachability
        if visible_to_team_id is not None:
            payload["visible_to_team_id"] = visible_to_team_id
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
                json=payload,
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

    def _signed_address_lookup_headers(
        self,
        *,
        domain: str,
        name: str | None,
        operation: str,
        signing_key: bytes | None,
        did_key: str | None = None,
    ) -> dict[str, str] | None:
        if signing_key is None:
            return None
        signer_did = _did_key_from_signing_key(signing_key)
        if did_key is not None and did_key.strip() and did_key.strip() != signer_did:
            raise ValueError("signing_key must match did_key for signed address lookup")
        timestamp = _utc_timestamp()
        payload_dict: dict[str, Any] = {
            "domain": domain,
            "operation": operation,
            "timestamp": timestamp,
        }
        if name is not None:
            payload_dict["name"] = name
        payload = canonical_json_bytes(payload_dict)
        return {
            "Authorization": f"DIDKey {signer_did} {sign_message(signing_key, payload)}",
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

    def __init__(
        self,
        registry_url: str,
        redis_client: Redis,
        *,
        timeout_seconds: float = 5.0,
        transport: httpx.AsyncBaseTransport | None = None,
        base_url: str | None = None,
        domain_registry_resolver: DomainRegistryResolver | None = None,
    ) -> None:
        super().__init__(
            registry_url=registry_url,
            timeout_seconds=timeout_seconds,
            transport=transport,
            base_url=base_url,
            domain_registry_resolver=domain_registry_resolver,
        )
        object.__setattr__(self, "redis_client", redis_client)
        object.__setattr__(self, "_refresh_tasks", {})

    async def resolve_key(self, did_aw: str) -> KeyResolution:
        return await self._cached_read(
            cache_key=self._did_key_cache_key(did_aw),
            ttl_seconds=_DID_KEY_CACHE_TTL_SECONDS,
            fetcher=lambda: super(CachedRegistryClient, self).resolve_key(did_aw),
            encode=lambda value: _key_resolution_to_json(value),
            decode=lambda payload: _key_resolution_from_json(payload),
        )

    async def get_namespace(self, domain: str) -> Namespace | None:
        registry_url = await self._registry_url_for_domain(domain)
        return await self._cached_read(
            cache_key=self._namespace_cache_key(domain, registry_url=registry_url),
            ttl_seconds=_NAMESPACE_CACHE_TTL_SECONDS,
            fetcher=lambda: super(CachedRegistryClient, self).get_namespace(domain),
            encode=lambda value: None if value is None else _namespace_to_json(value),
            decode=lambda payload: None if payload is None else _namespace_from_json(payload),
        )

    async def list_addresses(
        self,
        domain: str,
        *,
        signing_key: bytes | None = None,
        did_key: str | None = None,
    ) -> list[Address]:
        registry_url = await self._registry_url_for_domain(domain)
        caller_did_key = _normalize_lookup_did_key(signing_key=signing_key, did_key=did_key)
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
        caller_did_key = _normalize_lookup_did_key(signing_key=signing_key, did_key=did_key)
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

    async def list_did_addresses(self, did_aw: str) -> list[Address]:
        return await self._cached_read(
            cache_key=self._did_addresses_cache_key(did_aw),
            ttl_seconds=_ADDRESS_CACHE_TTL_SECONDS,
            fetcher=lambda: super(CachedRegistryClient, self).list_did_addresses(did_aw),
            encode=lambda value: [_address_to_json(item) for item in value],
            decode=lambda payload: [_address_from_json(item) for item in payload],
        )

    async def get_team_public_key(self, domain: str, name: str) -> str | None:
        team = await self.get_team(domain, name)
        if team is None:
            return None
        return team.team_did_key

    async def get_team(self, domain: str, name: str) -> Team | None:
        return await self._cached_read(
            cache_key=self._team_metadata_cache_key(domain, name),
            ttl_seconds=_TEAM_METADATA_CACHE_TTL_SECONDS,
            fetcher=lambda: super(CachedRegistryClient, self).get_team(domain, name),
            encode=lambda value: None if value is None else _team_to_json(value),
            decode=lambda payload: None if payload is None else _team_from_json(payload),
        )

    async def get_team_revocations(self, domain: str, name: str) -> set[str]:
        result = await self._cached_read(
            cache_key=self._team_revocations_cache_key(domain, name),
            ttl_seconds=_TEAM_REVOCATIONS_CACHE_TTL_SECONDS,
            fetcher=lambda: super(CachedRegistryClient, self).get_team_revocations(domain, name),
            encode=lambda value: sorted(value),
            decode=lambda payload: set(payload),
        )
        return result if isinstance(result, set) else set()

    async def list_team_certificates(
        self,
        domain: str,
        name: str,
        *,
        active_only: bool = True,
    ) -> list[TeamCertificate]:
        return await self._cached_read(
            cache_key=self._team_certificates_cache_key(domain, name, active_only=active_only),
            ttl_seconds=_TEAM_CERTIFICATES_CACHE_TTL_SECONDS,
            fetcher=lambda: super(CachedRegistryClient, self).list_team_certificates(
                domain, name, active_only=active_only
            ),
            encode=lambda value: [_team_certificate_to_json(item) for item in value],
            decode=lambda payload: [_team_certificate_from_json(item) for item in payload],
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
    ) -> Namespace:
        await self._invalidate_namespace_cache(domain)
        namespace = await super().register_namespace(
            domain,
            controller_did,
            controller_signing_key,
            parent_signing_key,
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

    async def register_address(
        self,
        domain: str,
        name: str,
        did_aw: str,
        controller_signing_key: bytes,
        reachability: str,
        visible_to_team_id: str | None = None,
        current_did_key: str | None = None,
    ) -> Address:
        await self._invalidate_keys(self._did_key_cache_key(did_aw))
        await self._invalidate_address_cache(domain=domain, name=name, did_aws=[])
        address = await super().register_address(
            domain,
            name,
            did_aw,
            controller_signing_key,
            reachability,
            visible_to_team_id,
            current_did_key,
        )
        await self._invalidate_address_cache(domain=domain, name=name, did_aws=[address.did_aw])
        return address

    async def update_address(
        self,
        domain: str,
        name: str,
        controller_signing_key: bytes,
        reachability: str | None = None,
        visible_to_team_id: str | None = None,
    ) -> Address:
        await self._invalidate_address_cache(domain=domain, name=name, did_aws=[])
        address = await super().update_address(
            domain,
            name,
            controller_signing_key,
            reachability,
            visible_to_team_id,
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
    ) -> Any:
        cached_payload = await self._read_cache_entry(cache_key, decode=decode)
        if cached_payload is not None:
            if cached_payload["fresh"]:
                return cached_payload["value"]
            if self._schedule_refresh(
                cache_key=cache_key,
                ttl_seconds=ttl_seconds,
                fetcher=fetcher,
                encode=encode,
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
                "value": value,
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
    ) -> None:
        payload = json.dumps(
            {
                "fresh_until": _cache_now() + ttl_seconds,
                "value": encode(value),
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        await self._redis_set(cache_key, payload, ex=ttl_seconds * _STALE_MULTIPLIER)

    def _schedule_refresh(
        self,
        *,
        cache_key: str,
        ttl_seconds: int,
        fetcher: Callable[[], Awaitable[Any]],
        encode: Callable[[Any], Any],
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
    ) -> None:
        try:
            fresh_value = await fetcher()
            await self._write_cache_entry(
                cache_key,
                value=fresh_value,
                ttl_seconds=ttl_seconds,
                encode=encode,
            )
        except Exception:
            logger.debug("AWID cache refresh failed for %s", cache_key, exc_info=True)

    async def _peek_cached_address(self, cache_key: str) -> Address | None:
        cached_payload = await self._read_cache_entry(
            cache_key,
            decode=lambda payload: None if payload is None else _address_from_json(payload),
        )
        if cached_payload is None:
            return None
        return cached_payload["value"]

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

    def _team_certificates_cache_key(self, domain: str, name: str, *, active_only: bool) -> str:
        suffix = "active" if active_only else "all"
        return f"awid:registry_cache:v1:team_certificates:{self.registry_url}:{domain}/{name}:{suffix}"


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _normalize_lookup_did_key(*, signing_key: bytes | None, did_key: str | None) -> str | None:
    normalized = (did_key or "").strip() or None
    if signing_key is None:
        return None
    signer_did = _did_key_from_signing_key(signing_key)
    if normalized is not None and normalized != signer_did:
        raise ValueError("signing_key must match did_key for signed address lookup")
    return signer_did


def _lookup_cache_scope(caller_did_key: str | None) -> str:
    normalized = (caller_did_key or "").strip()
    return normalized or "anon"


def _cache_now() -> int:
    return int(time.time())


def _did_key_from_signing_key(signing_key: bytes) -> str:
    key = SigningKey(signing_key)
    return did_from_public_key(bytes(key.verify_key))


def _assert_signing_key_matches(expected_did: str, signing_key: bytes) -> None:
    actual_did = _did_key_from_signing_key(signing_key)
    if actual_did != expected_did:
        raise ValueError("signing_key does not match the supplied controller_did")


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
    )


def _namespace_from_json(data: dict[str, Any]) -> Namespace:
    return Namespace(
        namespace_id=data["namespace_id"],
        domain=data["domain"],
        controller_did=data.get("controller_did"),
        verification_status=data["verification_status"],
        last_verified_at=data.get("last_verified_at"),
        created_at=data["created_at"],
    )


def _address_from_json(data: dict[str, Any]) -> Address:
    return Address(
        address_id=data["address_id"],
        domain=data["domain"],
        name=data["name"],
        did_aw=data["did_aw"],
        current_did_key=data["current_did_key"],
        reachability=data["reachability"],
        created_at=data["created_at"],
        visible_to_team_id=data.get("visible_to_team_id"),
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
        lifetime=data["lifetime"],
        issued_at=data["issued_at"],
        revoked_at=data.get("revoked_at"),
    )


def _team_certificate_to_json(value: TeamCertificate) -> dict[str, Any]:
    return asdict(value)
