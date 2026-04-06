from __future__ import annotations

import os
import re

from nacl.signing import SigningKey

from aweb.address_reachability import normalize_address_reachability
from aweb.awid.did import did_from_public_key
from aweb.awid.registry import RegistryClient


SUBDOMAIN_LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
AGENT_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$")


def validate_subdomain_label(value: str) -> str:
    label = (value or "").strip().lower()
    if not label:
        raise ValueError("Subnamespace label is required")
    if not SUBDOMAIN_LABEL_PATTERN.fullmatch(label):
        raise ValueError(
            "Subnamespace label must contain only lowercase letters, digits, or hyphens"
        )
    return label


def validate_agent_name(value: str) -> str:
    name = (value or "").strip().lower()
    if not name:
        raise ValueError("Agent name is required")
    if len(name) > 64:
        raise ValueError("Agent name must be 64 characters or fewer")
    if not AGENT_NAME_PATTERN.fullmatch(name):
        raise ValueError(
            "Agent name must start with an alphanumeric character and contain only letters, digits, hyphens, or underscores"
        )
    return name


def _normalize_domain(domain: str) -> str:
    value = (domain or "").strip().lower().rstrip(".")
    if not value:
        raise ValueError("Domain is required")
    if len(value) > 256:
        raise ValueError("Domain is too long")
    return value


def derive_owner_slug(*, project_slug: str, owner_ref: str | None = None) -> str:
    candidate = (owner_ref or project_slug or "").strip().lower()
    return validate_subdomain_label(candidate)


def managed_namespace_domain(owner_slug: str) -> str:
    owner_slug = validate_subdomain_label(owner_slug)
    managed_domain = (os.environ.get("AWEB_MANAGED_DOMAIN") or "").strip().lower()
    if managed_domain:
        return f"{owner_slug}.{managed_domain}"
    return owner_slug


def namespace_slug_from_domain(domain: str) -> str:
    normalized = _normalize_domain(domain)
    managed_domain = (os.environ.get("AWEB_MANAGED_DOMAIN") or "").strip().lower()
    suffix = f".{managed_domain}" if managed_domain else ""
    if suffix and normalized.endswith(suffix):
        return normalized[: -len(suffix)]
    return normalized


def _controller_did_from_signing_key(signing_key: bytes) -> str:
    return did_from_public_key(bytes(SigningKey(signing_key).verify_key))


def _parent_signing_key_for_domain(domain: str, controller_signing_key: bytes) -> bytes | None:
    normalized = _normalize_domain(domain)
    managed_domain = (os.environ.get("AWEB_MANAGED_DOMAIN") or "").strip().lower()
    if managed_domain and normalized.endswith(f".{managed_domain}") and normalized != managed_domain:
        return controller_signing_key
    return None


def _namespace_record(namespace) -> dict:
    return {
        "namespace_id": str(namespace.namespace_id),
        "domain": str(namespace.domain),
        "controller_did": str(namespace.controller_did) if namespace.controller_did else None,
        "verification_status": str(namespace.verification_status),
        "last_verified_at": str(namespace.last_verified_at) if namespace.last_verified_at else None,
        "created_at": str(namespace.created_at),
    }


def _address_record(address) -> dict:
    return {
        "address_id": str(address.address_id),
        "domain": str(address.domain),
        "name": str(address.name),
        "did_aw": str(address.did_aw),
        "current_did_key": str(address.current_did_key),
        "reachability": str(address.reachability),
        "created_at": str(address.created_at),
        "address": f"{address.domain}/{address.name}",
    }


async def get_namespace(*, registry_client: RegistryClient, domain: str) -> dict | None:
    namespace = await registry_client.get_namespace(_normalize_domain(domain))
    return _namespace_record(namespace) if namespace is not None else None


async def ensure_dns_namespace_registered(
    *,
    registry_client: RegistryClient,
    domain: str,
    controller_signing_key: bytes,
) -> dict:
    normalized = _normalize_domain(domain)
    controller_did = _controller_did_from_signing_key(controller_signing_key)
    existing = await registry_client.get_namespace(normalized)
    if existing is not None:
        if existing.controller_did and existing.controller_did != controller_did:
            raise ValueError("Namespace is controlled by a different DID")
        return _namespace_record(existing)
    namespace = await registry_client.register_namespace(
        domain=normalized,
        controller_did=controller_did,
        controller_signing_key=controller_signing_key,
        parent_signing_key=_parent_signing_key_for_domain(normalized, controller_signing_key),
    )
    return _namespace_record(namespace)


async def get_namespace_address(
    *,
    registry_client: RegistryClient,
    domain: str,
    name: str,
) -> dict | None:
    address = await registry_client.resolve_address(_normalize_domain(domain), validate_agent_name(name))
    return _address_record(address) if address is not None else None


async def list_namespace_addresses(
    *,
    registry_client: RegistryClient,
    domain: str,
) -> list[dict]:
    normalized = _normalize_domain(domain)
    namespace = await registry_client.get_namespace(normalized)
    if namespace is None:
        return []
    return [_address_record(address) for address in await registry_client.list_addresses(normalized)]


async def register_namespace_address(
    *,
    registry_client: RegistryClient,
    domain: str,
    name: str,
    did_aw: str,
    current_did_key: str,
    controller_signing_key: bytes,
    reachability: str = "private",
) -> dict:
    del current_did_key
    address = await registry_client.register_address(
        domain=_normalize_domain(domain),
        name=validate_agent_name(name),
        did_aw=did_aw,
        controller_signing_key=controller_signing_key,
        reachability=normalize_address_reachability(reachability),
    )
    return _address_record(address)


async def reassign_namespace_address(
    *,
    registry_client: RegistryClient,
    domain: str,
    name: str,
    did_aw: str,
    current_did_key: str,
    controller_signing_key: bytes,
    reachability: str | None = None,
) -> dict:
    del current_did_key
    normalized_domain = _normalize_domain(domain)
    normalized_name = validate_agent_name(name)
    address = await registry_client.reassign_address(
        normalized_domain,
        normalized_name,
        did_aw,
        controller_signing_key,
    )
    if reachability is not None:
        address = await registry_client.update_address(
            normalized_domain,
            normalized_name,
            controller_signing_key,
            normalize_address_reachability(reachability),
        )
    return _address_record(address)


async def set_namespace_address_reachability(
    *,
    registry_client: RegistryClient,
    domain: str,
    name: str,
    controller_signing_key: bytes,
    reachability: str,
) -> dict:
    address = await registry_client.update_address(
        _normalize_domain(domain),
        validate_agent_name(name),
        controller_signing_key,
        normalize_address_reachability(reachability),
    )
    return _address_record(address)


async def delete_namespace_address(
    *,
    registry_client: RegistryClient,
    domain: str,
    name: str,
    controller_signing_key: bytes,
) -> bool:
    normalized_domain = _normalize_domain(domain)
    normalized_name = validate_agent_name(name)
    existing = await registry_client.resolve_address(normalized_domain, normalized_name)
    if existing is None:
        return False
    await registry_client.delete_address(normalized_domain, normalized_name, controller_signing_key)
    return True
