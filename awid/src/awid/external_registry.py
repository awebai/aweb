"""Verified-only external registry adapter for inactive federation authority."""

from __future__ import annotations

import asyncio
import socket
import ssl
from dataclasses import dataclass
from typing import Any, Callable, Protocol
from urllib.parse import urlsplit

from awid.external_authority import (
    OriginContext,
    RegistryAuthority,
    TXTOutcomeResolver,
    authority_statement,
    canonical_protocol_address,
    canonical_protocol_domain,
    discover_registry_authority,
    isolated_registry_test_enabled,
    validate_resolved_addresses,
)
from awid.external_http import PinnedRegistryHTTP, escaped_path_component
from awid.federation_errors import FederationAuthorityError
from awid.log import canonical_server_origin
from awid.did import validate_did, validate_stable_id
from awid.identity_log_verify import (
    IdentityCheckpoint,
    VerifiedIdentityLog,
    verify_identity_head,
    verify_identity_log,
)


class HostResolver(Protocol):
    async def resolve_all(self, hostname: str) -> tuple[str, ...]: ...


class RegistryHTTP(Protocol):
    async def get_json(self, path: str, *, bypass_cache: bool = False) -> Any: ...

    async def aclose(self) -> None: ...


class SystemHostResolver:
    async def resolve_all(self, hostname: str) -> tuple[str, ...]:
        try:
            results = await asyncio.get_running_loop().getaddrinfo(
                hostname,
                None,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
                proto=socket.IPPROTO_TCP,
            )
        except OSError as exc:
            raise FederationAuthorityError("sender_registry_unavailable") from exc
        addresses: list[str] = []
        for _family, _type, _proto, _canonname, sockaddr in results:
            address = sockaddr[0]
            if address not in addresses:
                addresses.append(address)
        return tuple(addresses)


@dataclass(frozen=True)
class ExternalAuthorityEvidence:
    canonical_address: str
    authority_selection: str
    authority_name: str
    controller_did: str
    authority_statement_version: str
    authority_statement_digest: str
    inherited: bool
    registry_explicit: bool
    registry_origin: str
    address_id: str | None
    did_aw: str
    current_did_key: str
    delivery_origin: str
    authority_generation: int
    approved_ips: tuple[str, ...]
    verified_log: VerifiedIdentityLog
    verified_checkpoint: IdentityCheckpoint | None = None

    def claim_evidence(self) -> dict[str, object]:
        return {
            "canonical_address": self.canonical_address,
            "did_aw": self.did_aw,
            "current_did_key": self.current_did_key,
            "delivery_origin": self.delivery_origin,
            "generation": self.authority_generation,
        }


HTTPFactory = Callable[[str, tuple[str, ...], int], RegistryHTTP]


class StrictExternalRegistry:
    def __init__(
        self,
        *,
        txt_resolver: TXTOutcomeResolver,
        host_resolver: HostResolver | None = None,
        http_factory: HTTPFactory | None = None,
        origin_context: OriginContext | None = None,
        ssl_context: ssl.SSLContext | None = None,
        deadline_seconds: float = 5.0,
    ) -> None:
        if not 0 < deadline_seconds <= 5.0:
            raise ValueError("resolver deadline must be at most five seconds")
        self.deadline_seconds = deadline_seconds
        self.txt_resolver = txt_resolver
        self.host_resolver = host_resolver or SystemHostResolver()
        self.origin_context = origin_context or OriginContext()
        self.ssl_context = ssl_context
        self.http_factory = http_factory or self._default_http_factory
        self._clients: dict[tuple[str, tuple[str, ...], int], RegistryHTTP] = {}

    def _default_http_factory(
        self, origin: str, approved_ips: tuple[str, ...], generation: int
    ) -> RegistryHTTP:
        return PinnedRegistryHTTP(
            origin=origin,
            approved_ips=approved_ips,
            authority_generation=generation,
            ssl_context=self.ssl_context,
        )

    async def _client(
        self, authority: RegistryAuthority, generation: int
    ) -> tuple[RegistryHTTP, tuple[str, ...]]:
        hostname = urlsplit(authority.registry_origin).hostname
        if not hostname:
            raise FederationAuthorityError("sender_registry_origin_forbidden")
        answers = await self.host_resolver.resolve_all(hostname)
        approved = validate_resolved_addresses(
            answers,
            allow_nonpublic_test=isolated_registry_test_enabled(
                authority.registry_origin, self.origin_context
            ),
        )
        key = (authority.registry_origin, approved, generation)
        client = self._clients.get(key)
        if client is None:
            client = self.http_factory(authority.registry_origin, approved, generation)
            self._clients[key] = client
        return client, approved

    async def fetch_evidence(
        self,
        address: str,
        *,
        authority_generation: int,
        checkpoint: IdentityCheckpoint | None = None,
        bypass_cache: bool = False,
    ) -> ExternalAuthorityEvidence:
        try:
            async with asyncio.timeout(self.deadline_seconds):
                return await self._fetch_evidence(
                    address,
                    authority_generation=authority_generation,
                    checkpoint=checkpoint,
                    bypass_cache=bypass_cache,
                )
        except FederationAuthorityError:
            raise
        except TimeoutError as exc:
            raise FederationAuthorityError("sender_registry_unavailable") from exc

    async def _fetch_evidence(
        self,
        address: str,
        *,
        authority_generation: int,
        checkpoint: IdentityCheckpoint | None,
        bypass_cache: bool,
    ) -> ExternalAuthorityEvidence:
        canonical_address = canonical_protocol_address(address)
        domain, name = canonical_address.split("/", 1)
        if authority_generation < 1:
            raise ValueError("authority_generation must be positive")
        authority = await discover_registry_authority(
            domain,
            self.txt_resolver,
            origin_context=self.origin_context,
        )
        client, approved_ips = await self._client(authority, authority_generation)
        namespace = await self._object(
            client,
            f"/v1/namespaces/{escaped_path_component(domain)}",
            bypass_cache=bypass_cache,
        )
        namespace_domain = namespace.get("domain")
        namespace_controller = namespace.get("controller_did")
        if not isinstance(namespace_domain, str) or not isinstance(namespace_controller, str):
            raise FederationAuthorityError("sender_address_did_mismatch")
        try:
            canonical_namespace_domain = canonical_protocol_domain(namespace_domain)
        except FederationAuthorityError as exc:
            raise FederationAuthorityError("sender_address_did_mismatch") from exc
        if canonical_namespace_domain != domain:
            raise FederationAuthorityError("sender_address_did_mismatch")
        if not validate_did(namespace_controller):
            raise FederationAuthorityError("sender_registry_protocol_invalid")
        if authority.selection == "dns" and namespace_controller != authority.controller_did:
            raise FederationAuthorityError("sender_address_did_mismatch")
        controller_did = namespace_controller

        statement = authority_statement(
            authority_name=authority.authority_name,
            controller_did=controller_did,
            inherited=authority.inherited,
            registry_explicit=authority.registry_explicit,
            registry_origin=authority.registry_origin,
            selection=authority.selection,
            version="awid-v1",
        )
        address_row = await self._object(
            client,
            (
                f"/v1/namespaces/{escaped_path_component(domain)}"
                f"/addresses/{escaped_path_component(name)}"
            ),
            bypass_cache=bypass_cache,
        )
        address_domain = address_row.get("domain")
        if not isinstance(address_domain, str) or address_row.get("name") != name:
            raise FederationAuthorityError("sender_address_did_mismatch")
        try:
            canonical_address_domain = canonical_protocol_domain(address_domain)
        except FederationAuthorityError as exc:
            raise FederationAuthorityError("sender_address_did_mismatch") from exc
        if canonical_address_domain != domain:
            raise FederationAuthorityError("sender_address_did_mismatch")
        did_aw = address_row.get("did_aw")
        current_did_key = address_row.get("current_did_key")
        if not isinstance(did_aw, str) or not isinstance(current_did_key, str):
            raise FederationAuthorityError("sender_address_did_mismatch")
        try:
            validate_stable_id(did_aw)
        except ValueError as exc:
            raise FederationAuthorityError("sender_registry_protocol_invalid") from exc
        delivery = address_row.get("delivery")
        delivery_origin = (
            delivery.get("origin") if isinstance(delivery, dict) else address_row.get("delivery_origin")
        )
        if not isinstance(delivery_origin, str) or not delivery_origin:
            raise FederationAuthorityError("sender_route_missing", did_aw=did_aw)
        try:
            if canonical_server_origin(delivery_origin) != delivery_origin:
                raise FederationAuthorityError("sender_registry_protocol_invalid")
        except ValueError as exc:
            raise FederationAuthorityError("sender_registry_protocol_invalid") from exc
        address_id = address_row.get("address_id")
        if address_id is not None and not isinstance(address_id, str):
            raise FederationAuthorityError("sender_registry_protocol_invalid")

        key_row = await self._object(
            client,
            f"/v1/did/{escaped_path_component(did_aw)}/key",
            bypass_cache=bypass_cache,
        )
        if key_row.get("did_aw") != did_aw:
            raise FederationAuthorityError("sender_address_did_mismatch", did_aw=did_aw)
        if key_row.get("current_did_key") != current_did_key:
            raise FederationAuthorityError("sender_current_key_mismatch", did_aw=did_aw)

        verified: VerifiedIdentityLog | None = None
        head = key_row.get("log_head")
        if key_row.get("status") != "OK_DEGRADED" and isinstance(head, dict):
            try:
                verified = verify_identity_head(
                    did_aw=did_aw,
                    current_did_key=current_did_key,
                    entry=head,
                    checkpoint=checkpoint,
                )
            except FederationAuthorityError as exc:
                if exc.reason != "sender_identity_unverifiable":
                    raise
        if verified is None:
            try:
                log = await client.get_json(
                    f"/v1/did/{escaped_path_component(did_aw)}/log",
                    bypass_cache=bypass_cache,
                )
            except FederationAuthorityError as exc:
                if exc.reason in {"sender_identity_not_found", "sender_registry_unavailable"}:
                    raise FederationAuthorityError(
                        "sender_identity_unverifiable", did_aw=did_aw
                    ) from exc
                raise
            if not isinstance(log, list):
                raise FederationAuthorityError("sender_registry_protocol_invalid")
            verified = verify_identity_log(
                did_aw=did_aw,
                entries=log,
                expected_current_did_key=current_did_key,
                checkpoint=checkpoint,
            )

        return ExternalAuthorityEvidence(
            canonical_address=canonical_address,
            authority_selection=authority.selection,
            authority_name=authority.authority_name,
            controller_did=controller_did,
            authority_statement_version=statement.version,
            authority_statement_digest=statement.digest,
            inherited=authority.inherited,
            registry_explicit=authority.registry_explicit,
            registry_origin=authority.registry_origin,
            address_id=address_id,
            did_aw=did_aw,
            current_did_key=current_did_key,
            delivery_origin=delivery_origin,
            authority_generation=authority_generation,
            approved_ips=approved_ips,
            verified_log=verified,
            verified_checkpoint=checkpoint,
        )

    async def _object(
        self, client: RegistryHTTP, path: str, *, bypass_cache: bool
    ) -> dict[str, Any]:
        value = await client.get_json(path, bypass_cache=bypass_cache)
        if not isinstance(value, dict):
            raise FederationAuthorityError("sender_registry_protocol_invalid")
        return value

    async def expire_generation(self, authority_generation: int) -> None:
        expired = [
            key for key in self._clients if key[2] == authority_generation
        ]
        for key in expired:
            client = self._clients.pop(key)
            await client.aclose()

    async def aclose(self) -> None:
        clients = tuple(self._clients.values())
        self._clients.clear()
        for client in clients:
            await client.aclose()
