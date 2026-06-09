"""AWID A2A publication and bridge delegation assertion helpers."""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from awid.atomic_claim import canonical_registry_origin, normalize_claim_custody
from awid.did import validate_stable_id
from awid.signing import canonical_json_bytes

A2A_PUBLICATION_OPERATION = "publish_a2a_route"
A2A_DELEGATION_OPERATION = "delegate_a2a_bridge"
A2A_CUSTODY_DELEGATED_BRIDGE = "self_to_delegated_bridge"
A2A_CUSTODY_HOSTED_DELEGATED_BRIDGE = "hosted_to_delegated_bridge"
A2A_AUTHORITY_SELF_IDENTITY_KEY = "self_identity_key"
A2A_AUTHORITY_HOSTED_SESSION = "hosted_session"
A2A_AUTHORITY_HOSTED_DELEGATION = "hosted_delegation"
A2A_AUTHORITY_SELF_DELEGATION = "self_identity_delegation"
A2A_STATUS_ACTIVE = "active"
A2A_STATUS_REVOKED = "revoked"
A2A_CARD_DIGEST_ALG_SHA256 = "sha256"
A2A_MIN_ALLOWED_OPERATIONS = ("send_task", "receive_reply", "cancel_task", "serve_card")

A2A_CONFLICT_CODES = (
    "a2a_publication_exists_different_digest",
    "a2a_publication_exists_different_gateway",
    "a2a_delegation_missing",
    "a2a_delegation_digest_mismatch",
    "a2a_delegation_expired",
    "a2a_delegation_revoked",
    "a2a_card_digest_mismatch",
    "a2a_card_url_invalid",
    "a2a_rpc_url_invalid",
    "a2a_route_id_invalid",
    "a2a_identity_signature_invalid",
    "a2a_identity_key_history_invalid",
    "a2a_delegation_signature_invalid",
    "a2a_timestamp_stale",
    "a2a_namespace_not_registered",
    "a2a_address_not_registered",
    "a2a_custody_combination_unsupported",
    "a2a_authority_source_invalid",
    "a2a_payload_canonicalization_mismatch",
    "a2a_primitive_disabled",
    "a2a_primitive_not_supported",
)

_ROUTE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_ASSERTION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_DIGEST_HEX_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_DIGEST_B64_RE = re.compile(r"^sha256:[A-Za-z0-9+/]+$")
_RFC3339_Z_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


@dataclass(frozen=True)
class A2APublicationFields:
    operation: str
    assertion_id: str
    address: str
    did_aw: str
    current_did_key: str
    signer_did: str
    signer_kid: str
    card_url: str
    rpc_url: str
    route_id: str
    tenant: str | None
    gateway_identity: str
    delegation_id: str | None
    delegation_digest: str | None
    card_digest_alg: str
    card_digest: str
    card_revision: str
    default_for_host: bool
    status: str
    published_at: str
    expires_at: str
    registry_url: str
    identity_custody: str
    authority_source: str


@dataclass(frozen=True)
class A2ADelegationFields:
    operation: str
    delegation_id: str
    delegator_did_aw: str
    delegator_current_did_key: str
    delegated_gateway_identity: str
    address: str
    route_id: str
    card_url: str
    rpc_url: str
    allowed_operations: tuple[str, ...]
    card_digest_alg: str
    card_digest: str
    custody_mode: str
    authority_source: str
    signer_did: str
    signer_kid: str
    issued_at: str
    expires_at: str
    status: str
    revoked_at: str | None
    revocation_reason: str | None
    registry_url: str


def raw_standard_b64(data: bytes) -> str:
    return base64.b64encode(data).rstrip(b"=").decode("ascii")


def decode_raw_standard_b64(value: str, *, field_name: str) -> bytes:
    value = (value or "").strip()
    if not value:
        raise ValueError(f"{field_name} must not be empty")
    if "=" in value:
        raise ValueError(f"{field_name} must be standard base64 without padding")
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4), validate=True)
    except Exception as exc:
        raise ValueError(f"{field_name} must be standard base64 without padding") from exc


def signed_assertion_digest(canonical: bytes, signature: str) -> str:
    signature_bytes = decode_raw_standard_b64(signature, field_name="signature")
    return "sha256:" + raw_standard_b64(hashlib.sha256(canonical + signature_bytes).digest())


def parse_contract_time(value: str, *, field_name: str) -> datetime:
    value = (value or "").strip()
    if not _RFC3339_Z_RE.match(value):
        raise ValueError(f"{field_name} must be RFC3339 UTC seconds with Z")
    return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(timezone.utc)


def canonical_address(address: str) -> tuple[str, str, str]:
    raw = (address or "").strip().lower()
    if raw.count("/") != 1:
        raise ValueError("address must be domain/name")
    domain, name = raw.split("/", 1)
    domain = domain.rstrip(".")
    if not domain or ".." in domain or "/" in domain or "\\" in domain:
        raise ValueError("invalid address domain")
    if not name or name in {".", ".."} or "/" in name or "\\" in name or "." in name:
        raise ValueError("invalid address name")
    return f"{domain}/{name}", domain, name


def normalize_https_url(value: str, *, field_name: str) -> str:
    raw = (value or "").strip()
    parsed = urlparse(raw)
    if parsed.scheme.lower() != "https":
        raise ValueError(f"{field_name} must be an absolute https URL")
    if not parsed.hostname:
        raise ValueError(f"{field_name} host is required")
    if parsed.username or parsed.password:
        raise ValueError(f"{field_name} must not include userinfo")
    if parsed.fragment:
        raise ValueError(f"{field_name} must not include a fragment")
    host = parsed.hostname.lower()
    host_out = f"[{host}]" if ":" in host and not host.startswith("[") else host
    port = None if parsed.port in {None, 443} else parsed.port
    path = parsed.path or "/"
    query = f"?{parsed.query}" if parsed.query else ""
    return f"https://{host_out}{f':{port}' if port is not None else ''}{path}{query}"


def validate_route_id(route_id: str) -> str:
    route_id = (route_id or "").strip()
    if route_id in {".", ".."} or ".." in route_id or not _ROUTE_RE.match(route_id):
        raise ValueError("route_id must be a non-empty path-safe segment")
    return route_id


def validate_assertion_id(value: str, *, field_name: str) -> str:
    value = (value or "").strip()
    if not _ASSERTION_ID_RE.match(value):
        raise ValueError(f"{field_name} is invalid")
    return value


def validate_card_digest_alg(value: str) -> str:
    value = (value or "").strip().lower()
    if value != A2A_CARD_DIGEST_ALG_SHA256:
        raise ValueError("card_digest_alg must be sha256")
    return value


def validate_card_digest(value: str) -> str:
    value = (value or "").strip()
    if not _DIGEST_HEX_RE.match(value):
        raise ValueError("card_digest must be sha256:<64 lowercase hex chars>")
    return value


def validate_signed_digest(value: str, *, field_name: str) -> str:
    value = (value or "").strip()
    if not _DIGEST_B64_RE.match(value):
        raise ValueError(f"{field_name} must be sha256:<base64>")
    return value


def _did_key(value: str, *, field_name: str) -> str:
    value = (value or "").strip()
    if not value.startswith("did:key:z"):
        raise ValueError(f"{field_name} must be did:key")
    return value


def _did_aw(value: str, *, field_name: str) -> str:
    try:
        return validate_stable_id((value or "").strip())
    except Exception as exc:
        raise ValueError(f"{field_name} must be did:aw") from exc


def _status(value: str) -> str:
    value = (value or "").strip()
    if value not in {A2A_STATUS_ACTIVE, A2A_STATUS_REVOKED}:
        raise ValueError("status must be active or revoked")
    return value


def _optional_nonempty(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    return value or None


def normalize_a2a_publication_fields(fields: A2APublicationFields) -> A2APublicationFields:
    operation = (fields.operation or "").strip() or A2A_PUBLICATION_OPERATION
    if operation != A2A_PUBLICATION_OPERATION:
        raise ValueError(f"operation must be {A2A_PUBLICATION_OPERATION}")
    address, _domain, _name = canonical_address(fields.address)
    route_id = validate_route_id(fields.route_id)
    card_url = normalize_https_url(fields.card_url, field_name="card_url")
    rpc_url = normalize_https_url(fields.rpc_url, field_name="rpc_url")
    tenant = _optional_nonempty(fields.tenant)
    delegation_id = _optional_nonempty(fields.delegation_id)
    delegation_digest = _optional_nonempty(fields.delegation_digest)
    if bool(delegation_id) != bool(delegation_digest):
        raise ValueError("delegation_id and delegation_digest must be supplied together")
    if delegation_digest:
        delegation_digest = validate_signed_digest(delegation_digest, field_name="delegation_digest")
    signer_did = _did_key(fields.signer_did, field_name="signer_did")
    signer_kid = (fields.signer_kid or "").strip()
    if signer_kid != signer_did + "#ed25519":
        raise ValueError("signer_kid must be signer_did#ed25519")
    return A2APublicationFields(
        operation=operation,
        assertion_id=validate_assertion_id(fields.assertion_id, field_name="assertion_id"),
        address=address,
        did_aw=_did_aw(fields.did_aw, field_name="did_aw"),
        current_did_key=_did_key(fields.current_did_key, field_name="current_did_key"),
        signer_did=signer_did,
        signer_kid=signer_kid,
        card_url=card_url,
        rpc_url=rpc_url,
        route_id=route_id,
        tenant=tenant,
        gateway_identity=_did_aw(fields.gateway_identity, field_name="gateway_identity"),
        delegation_id=delegation_id,
        delegation_digest=delegation_digest,
        card_digest_alg=validate_card_digest_alg(fields.card_digest_alg),
        card_digest=validate_card_digest(fields.card_digest),
        card_revision=(fields.card_revision or "").strip(),
        default_for_host=bool(fields.default_for_host),
        status=_status(fields.status),
        published_at=_format_contract_time(parse_contract_time(fields.published_at, field_name="published_at")),
        expires_at=_format_contract_time(parse_contract_time(fields.expires_at, field_name="expires_at")),
        registry_url=canonical_registry_origin(fields.registry_url),
        identity_custody=normalize_claim_custody(fields.identity_custody),
        authority_source=(fields.authority_source or "").strip(),
    )


def normalize_a2a_delegation_fields(fields: A2ADelegationFields) -> A2ADelegationFields:
    operation = (fields.operation or "").strip() or A2A_DELEGATION_OPERATION
    if operation != A2A_DELEGATION_OPERATION:
        raise ValueError(f"operation must be {A2A_DELEGATION_OPERATION}")
    address, _domain, _name = canonical_address(fields.address)
    route_id = validate_route_id(fields.route_id)
    card_url = normalize_https_url(fields.card_url, field_name="card_url")
    rpc_url = normalize_https_url(fields.rpc_url, field_name="rpc_url")
    ops = tuple((op or "").strip() for op in fields.allowed_operations)
    if any(not op for op in ops):
        raise ValueError("allowed_operations must not contain empty entries")
    if ops != A2A_MIN_ALLOWED_OPERATIONS:
        raise ValueError("allowed_operations must equal the v1 product operation order")
    custody_mode = (fields.custody_mode or "").strip()
    if custody_mode not in {A2A_CUSTODY_DELEGATED_BRIDGE, A2A_CUSTODY_HOSTED_DELEGATED_BRIDGE}:
        raise ValueError("unsupported custody_mode")
    revoked_at = _optional_nonempty(fields.revoked_at)
    if fields.status == A2A_STATUS_REVOKED and not revoked_at:
        raise ValueError("revoked_at is required when status is revoked")
    if revoked_at:
        revoked_at = _format_contract_time(parse_contract_time(revoked_at, field_name="revoked_at"))
    signer_did = _did_key(fields.signer_did, field_name="signer_did")
    signer_kid = (fields.signer_kid or "").strip()
    if signer_kid != signer_did + "#ed25519":
        raise ValueError("signer_kid must be signer_did#ed25519")
    return A2ADelegationFields(
        operation=operation,
        delegation_id=validate_assertion_id(fields.delegation_id, field_name="delegation_id"),
        delegator_did_aw=_did_aw(fields.delegator_did_aw, field_name="delegator_did_aw"),
        delegator_current_did_key=_did_key(fields.delegator_current_did_key, field_name="delegator_current_did_key"),
        delegated_gateway_identity=_did_aw(fields.delegated_gateway_identity, field_name="delegated_gateway_identity"),
        address=address,
        route_id=route_id,
        card_url=card_url,
        rpc_url=rpc_url,
        allowed_operations=ops,
        card_digest_alg=validate_card_digest_alg(fields.card_digest_alg),
        card_digest=validate_card_digest(fields.card_digest),
        custody_mode=custody_mode,
        authority_source=(fields.authority_source or "").strip(),
        signer_did=signer_did,
        signer_kid=signer_kid,
        issued_at=_format_contract_time(parse_contract_time(fields.issued_at, field_name="issued_at")),
        expires_at=_format_contract_time(parse_contract_time(fields.expires_at, field_name="expires_at")),
        status=_status(fields.status),
        revoked_at=revoked_at,
        revocation_reason=_optional_nonempty(fields.revocation_reason),
        registry_url=canonical_registry_origin(fields.registry_url),
    )


def _format_contract_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _omit_empty(fields: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in fields.items():
        if value is None:
            continue
        if isinstance(value, str) and not value:
            continue
        out[key] = value
    return out


def a2a_publication_payload(fields: A2APublicationFields) -> dict[str, Any]:
    fields = normalize_a2a_publication_fields(fields)
    return _omit_empty(
        {
            "operation": fields.operation,
            "assertion_id": fields.assertion_id,
            "address": fields.address,
            "did_aw": fields.did_aw,
            "current_did_key": fields.current_did_key,
            "signer_did": fields.signer_did,
            "signer_kid": fields.signer_kid,
            "card_url": fields.card_url,
            "rpc_url": fields.rpc_url,
            "route_id": fields.route_id,
            "tenant": fields.tenant,
            "gateway_identity": fields.gateway_identity,
            "delegation_id": fields.delegation_id,
            "delegation_digest": fields.delegation_digest,
            "card_digest_alg": fields.card_digest_alg,
            "card_digest": fields.card_digest,
            "card_revision": fields.card_revision,
            "default_for_host": fields.default_for_host,
            "status": fields.status,
            "published_at": fields.published_at,
            "expires_at": fields.expires_at,
            "registry_url": fields.registry_url,
            "identity_custody": fields.identity_custody,
            "authority_source": fields.authority_source,
        }
    )


def a2a_delegation_payload(fields: A2ADelegationFields) -> dict[str, Any]:
    fields = normalize_a2a_delegation_fields(fields)
    return _omit_empty(
        {
            "operation": fields.operation,
            "delegation_id": fields.delegation_id,
            "delegator_did_aw": fields.delegator_did_aw,
            "delegator_current_did_key": fields.delegator_current_did_key,
            "delegated_gateway_identity": fields.delegated_gateway_identity,
            "address": fields.address,
            "route_id": fields.route_id,
            "card_url": fields.card_url,
            "rpc_url": fields.rpc_url,
            "allowed_operations": list(fields.allowed_operations),
            "card_digest_alg": fields.card_digest_alg,
            "card_digest": fields.card_digest,
            "custody_mode": fields.custody_mode,
            "authority_source": fields.authority_source,
            "signer_did": fields.signer_did,
            "signer_kid": fields.signer_kid,
            "issued_at": fields.issued_at,
            "expires_at": fields.expires_at,
            "status": fields.status,
            "revoked_at": fields.revoked_at,
            "revocation_reason": fields.revocation_reason,
            "registry_url": fields.registry_url,
        }
    )


def a2a_publication_canonical(fields: A2APublicationFields) -> bytes:
    return canonical_json_bytes(a2a_publication_payload(fields))


def a2a_delegation_canonical(fields: A2ADelegationFields) -> bytes:
    return canonical_json_bytes(a2a_delegation_payload(fields))
