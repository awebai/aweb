"""HTTP client for the external or embedded AWID registry."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx
from nacl.signing import SigningKey

from aweb.awid.did import did_from_public_key, stable_id_from_did_key
from aweb.awid.log import canonical_server_origin, log_entry_payload, state_hash
from aweb.awid.signing import canonical_json_bytes, sign_message
from aweb.config import is_local_awid_registry_url


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
    server: str
    address: str
    handle: str | None
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


@dataclass(frozen=True)
class RegistryClient:
    registry_url: str
    timeout_seconds: float = 5.0
    transport: httpx.AsyncBaseTransport | None = None
    base_url: str | None = None

    def _resolved_base_url(self) -> str:
        if self.base_url:
            if not is_local_awid_registry_url(self.registry_url):
                raise ValueError(
                    "base_url override is only allowed in local mode"
                )
            return self.base_url.rstrip("/")
        if is_local_awid_registry_url(self.registry_url):
            if self.transport is None:
                raise ValueError(
                    "registry_url='local' requires an explicit base_url or transport for HTTP access"
                )
            return "http://awid.local"
        return canonical_server_origin(self.registry_url)

    async def _request_json(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        json: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        async with httpx.AsyncClient(
            base_url=self._resolved_base_url(),
            timeout=self.timeout_seconds,
            transport=self.transport,
        ) as client:
            response = await client.request(method, path, headers=headers, json=json)
        if not 200 <= response.status_code < 300:
            detail = None
            try:
                detail = response.json().get("detail")
            except Exception:
                detail = None
            raise RegistryError(
                detail or response.text,
                status_code=response.status_code,
                detail=detail or response.text,
            )
        if not response.content:
            return {}
        return response.json()

    async def _request_optional_json(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        json: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        try:
            return await self._request_json(method, path, headers=headers, json=json)
        except RegistryError as exc:
            if exc.status_code == 404:
                return None
            raise

    async def _get_did_full(self, did_aw: str, signing_key: bytes) -> DIDMapping:
        path = f"/v1/did/{did_aw}/full"
        return _did_mapping_from_json(
            await self._request_json(
                "GET",
                path,
                headers=self._signed_path_headers("GET", path, signing_key),
            )
        )

    async def register_did(self, did_key: str, signing_key: bytes, server_url: str) -> DIDMapping:
        signer_did = _did_key_from_signing_key(signing_key)
        if signer_did != did_key:
            raise ValueError("signing_key must match did_key for DID registration")

        did_aw = stable_id_from_did_key(did_key)
        canonical_server = canonical_server_origin(server_url)
        timestamp = _utc_timestamp()
        mapping_state_hash = state_hash(
            did_aw=did_aw,
            current_did_key=did_key,
            server=canonical_server,
            address="",
            handle=None,
        )
        proof = sign_message(
            signing_key,
            log_entry_payload(
                did_aw=did_aw,
                seq=1,
                operation="create",
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
                    "did_key": did_key,
                    "server": canonical_server,
                    "address": "",
                    "handle": None,
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
        return await self._get_did_full(did_aw, signing_key)

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

        current_mapping = await self._get_did_full(did_aw, old_signing_key)
        if current_mapping.current_did_key != old_did_key:
            raise ValueError("old_signing_key does not match the current did:key")

        key_resolution = await self.resolve_key(did_aw)
        if key_resolution.log_head is None:
            raise ValueError("DID registry response is missing log_head")

        timestamp = _utc_timestamp()
        seq = key_resolution.log_head.seq + 1
        prev_entry_hash = key_resolution.log_head.entry_hash
        next_state_hash = state_hash(
            did_aw=did_aw,
            current_did_key=new_did_key,
            server=current_mapping.server,
            address=current_mapping.address,
            handle=current_mapping.handle,
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
        return await self._get_did_full(did_aw, new_signing_key)

    async def update_server(
        self,
        did_aw: str,
        server_url: str,
        signing_key: bytes,
    ) -> DIDMapping:
        current_did_key = _did_key_from_signing_key(signing_key)
        current_mapping = await self._get_did_full(did_aw, signing_key)
        if current_mapping.current_did_key != current_did_key:
            raise ValueError("signing_key does not match the current did:key")

        key_resolution = await self.resolve_key(did_aw)
        if key_resolution.log_head is None:
            raise ValueError("DID registry response is missing log_head")

        canonical_server = canonical_server_origin(server_url)
        timestamp = _utc_timestamp()
        seq = key_resolution.log_head.seq + 1
        prev_entry_hash = key_resolution.log_head.entry_hash
        next_state_hash = state_hash(
            did_aw=did_aw,
            current_did_key=current_did_key,
            server=canonical_server,
            address=current_mapping.address,
            handle=current_mapping.handle,
        )
        signature = sign_message(
            signing_key,
            log_entry_payload(
                did_aw=did_aw,
                seq=seq,
                operation="update_server",
                previous_did_key=current_did_key,
                new_did_key=current_did_key,
                prev_entry_hash=prev_entry_hash,
                state_hash=next_state_hash,
                authorized_by=current_did_key,
                timestamp=timestamp,
            ),
        )
        await self._request_json(
            "PUT",
            f"/v1/did/{did_aw}",
            json={
                "operation": "update_server",
                "new_did_key": current_did_key,
                "server": canonical_server,
                "seq": seq,
                "prev_entry_hash": prev_entry_hash,
                "state_hash": next_state_hash,
                "authorized_by": current_did_key,
                "timestamp": timestamp,
                "signature": signature,
            },
        )
        return await self._get_did_full(did_aw, signing_key)

    async def register_namespace(
        self,
        domain: str,
        controller_did: str,
        controller_signing_key: bytes,
        parent_signing_key: bytes | None = None,
    ) -> Namespace:
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
            )
        )

    async def get_namespace(self, domain: str) -> Namespace | None:
        data = await self._request_optional_json("GET", f"/v1/namespaces/{domain}")
        return None if data is None else _namespace_from_json(data)

    async def rotate_namespace_controller(
        self,
        domain: str,
        new_controller_did: str,
        new_controller_signing_key: bytes,
        parent_signing_key: bytes | None = None,
    ) -> Namespace:
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
            )
        )

    async def register_address(
        self,
        domain: str,
        name: str,
        did_aw: str,
        controller_signing_key: bytes,
        reachability: str,
    ) -> Address:
        key_resolution = await self.resolve_key(did_aw)
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
                    "current_did_key": key_resolution.current_did_key,
                    "reachability": reachability,
                },
            )
        )

    async def resolve_address(self, domain: str, name: str) -> Address | None:
        data = await self._request_optional_json("GET", f"/v1/namespaces/{domain}/addresses/{name}")
        return None if data is None else _address_from_json(data)

    async def list_addresses(self, domain: str) -> list[Address]:
        data = await self._request_json("GET", f"/v1/namespaces/{domain}/addresses")
        return [_address_from_json(item) for item in data.get("addresses", [])]

    async def update_address(
        self,
        domain: str,
        name: str,
        controller_signing_key: bytes,
        reachability: str | None = None,
    ) -> Address:
        payload: dict[str, Any] = {}
        if reachability is not None:
            payload["reachability"] = reachability
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
            )
        )

    async def delete_address(
        self,
        domain: str,
        name: str,
        controller_signing_key: bytes,
    ) -> None:
        await self._request_json(
            "DELETE",
            f"/v1/namespaces/{domain}/addresses/{name}",
            headers=self._signed_address_headers(
                domain=domain,
                name=name,
                operation="delete_address",
                signing_key=controller_signing_key,
            ),
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


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


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
        server=data["server"],
        address=data["address"],
        handle=data.get("handle"),
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
    )
