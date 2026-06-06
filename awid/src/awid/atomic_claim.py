"""Atomic DID + namespace-address claim payload helpers."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from urllib.parse import urlparse

from awid.signing import canonical_json_bytes

ATOMIC_ADDRESS_CLAIM_OPERATION = "claim_identity_address"
CUSTODY_SELF = "self"
CUSTODY_HOSTED = "hosted_custodial"


@dataclass(frozen=True)
class AtomicAddressClaimFields:
    operation: str
    domain: str
    address_name: str
    did_aw: str
    current_did_key: str
    registry_url: str
    timestamp: str
    dry_run: bool
    identity_custody: str
    namespace_custody: str


def canonical_registry_origin(raw: str) -> str:
    raw = (raw or "").strip()
    parsed = urlparse(raw)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError("registry_url scheme must be http or https")
    if parsed.username or parsed.password:
        raise ValueError("registry_url must not include userinfo")
    if parsed.params or parsed.query or parsed.fragment:
        raise ValueError("registry_url must not include params, query, or fragment")
    path = parsed.path.rstrip("/")
    if path == "/api":
        path = ""
    if path:
        raise ValueError("registry_url must be an origin URL")
    if not parsed.hostname:
        raise ValueError("registry_url host is required")
    host = parsed.hostname.lower()
    host_out = f"[{host}]" if ":" in host and not host.startswith("[") else host
    default_port = 80 if scheme == "http" else 443
    port = None if parsed.port in {None, default_port} else parsed.port
    return f"{scheme}://{host_out}{f':{port}' if port is not None else ''}"


def normalize_claim_custody(value: str) -> str:
    normalized = (value or "").strip().lower()
    if normalized == CUSTODY_SELF:
        return CUSTODY_SELF
    if normalized in {CUSTODY_HOSTED, "hosted-custodial"}:
        return CUSTODY_HOSTED
    raise ValueError("unsupported custody value")


def normalize_atomic_address_claim_fields(fields: AtomicAddressClaimFields) -> AtomicAddressClaimFields:
    operation = (fields.operation or "").strip() or ATOMIC_ADDRESS_CLAIM_OPERATION
    if operation != ATOMIC_ADDRESS_CLAIM_OPERATION:
        raise ValueError(f"operation must be {ATOMIC_ADDRESS_CLAIM_OPERATION!r}")
    domain = (fields.domain or "").strip().lower().rstrip(".")
    if not domain:
        raise ValueError("domain is required")
    address_name = (fields.address_name or "").strip().lower()
    if (
        not address_name
        or address_name in {".", ".."}
        or "/" in address_name
        or "\\" in address_name
        or "." in address_name
    ):
        raise ValueError("invalid address_name")
    did_aw = (fields.did_aw or "").strip()
    if not did_aw.startswith("did:aw:"):
        raise ValueError("did_aw must start with did:aw:")
    current_did_key = (fields.current_did_key or "").strip()
    if not current_did_key.startswith("did:key:"):
        raise ValueError("current_did_key must start with did:key:")
    identity_custody = normalize_claim_custody(fields.identity_custody)
    namespace_custody = normalize_claim_custody(fields.namespace_custody)
    if identity_custody == CUSTODY_HOSTED and namespace_custody == CUSTODY_SELF:
        raise ValueError("hosted-custodial DID with self-custodial namespace is unsupported")
    timestamp = (fields.timestamp or "").strip()
    if not timestamp:
        raise ValueError("timestamp is required")
    return AtomicAddressClaimFields(
        operation=operation,
        domain=domain,
        address_name=address_name,
        did_aw=did_aw,
        current_did_key=current_did_key,
        registry_url=canonical_registry_origin(fields.registry_url),
        timestamp=timestamp,
        dry_run=bool(fields.dry_run),
        identity_custody=identity_custody,
        namespace_custody=namespace_custody,
    )


def atomic_address_claim_identity_canonical(fields: AtomicAddressClaimFields) -> bytes:
    fields = normalize_atomic_address_claim_fields(fields)
    return canonical_json_bytes(
        {
            "operation": fields.operation,
            "domain": fields.domain,
            "address_name": fields.address_name,
            "did_aw": fields.did_aw,
            "current_did_key": fields.current_did_key,
            "registry_url": fields.registry_url,
            "timestamp": fields.timestamp,
            "dry_run": fields.dry_run,
            "identity_custody": fields.identity_custody,
        }
    )


def atomic_address_claim_identity_proof_hash(
    identity_canonical: bytes, identity_signature: str
) -> str:
    if not identity_canonical:
        raise ValueError("identity canonical payload is required")
    padded = identity_signature.strip() + "=" * (-len(identity_signature.strip()) % 4)
    signature_bytes = base64.b64decode(padded)
    digest = hashlib.sha256(identity_canonical + signature_bytes).digest()
    return "sha256:" + base64.b64encode(digest).rstrip(b"=").decode("ascii")


def atomic_address_claim_namespace_canonical(
    fields: AtomicAddressClaimFields, identity_proof_hash: str
) -> bytes:
    fields = normalize_atomic_address_claim_fields(fields)
    identity_proof_hash = (identity_proof_hash or "").strip()
    if not identity_proof_hash:
        raise ValueError("identity_proof_hash is required")
    return canonical_json_bytes(
        {
            "operation": fields.operation,
            "domain": fields.domain,
            "address_name": fields.address_name,
            "did_aw": fields.did_aw,
            "current_did_key": fields.current_did_key,
            "registry_url": fields.registry_url,
            "timestamp": fields.timestamp,
            "dry_run": fields.dry_run,
            "identity_proof_hash": identity_proof_hash,
            "namespace_custody": fields.namespace_custody,
        }
    )
