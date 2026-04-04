"""Stable identity primitives and runtime support for OSS aweb.

This package is the canonical internal home for did:key / did:aw handling,
signing, custodial signing support, stable-id backfill, and continuity
metadata helpers.
"""

from aweb.awid.custody import (
    decrypt_signing_key,
    destroy_signing_key,
    encrypt_signing_key,
    get_custody_key,
    sign_on_behalf,
)
from aweb.awid.contract import (
    IDENTITY_CUSTODY_MODES,
    IDENTITY_LIFETIMES,
    ResolvedIdentityContract,
    assert_permanent_identity,
    resolve_identity_contract,
)
from aweb.awid.did import (
    decode_public_key,
    did_from_public_key,
    encode_public_key,
    generate_keypair,
    public_key_from_did,
    stable_id_from_did_key,
    stable_id_from_public_key,
    validate_did,
    validate_stable_id,
)
from aweb.awid.log import (
    canonical_server_origin,
    log_entry_payload,
    require_canonical_server_origin,
    sha256_hex,
    state_hash,
)
from aweb.awid.replacement import get_sender_delivery_metadata
from aweb.awid.registry import (
    Address,
    AlreadyRegisteredError,
    CachedRegistryClient,
    DIDKeyEvidence,
    DIDMapping,
    KeyResolution,
    Namespace,
    RegistryClient,
    RegistryError,
)
from aweb.awid.signing import (
    SIGNED_FIELDS,
    VerifyResult,
    canonical_json_bytes,
    canonical_payload,
    sign_message,
    verify_did_key_signature,
    verify_signature,
)
from aweb.awid.stable_id import backfill_missing_stable_ids, ensure_agent_stable_ids

__all__ = [
    "SIGNED_FIELDS",
    "VerifyResult",
    "IDENTITY_CUSTODY_MODES",
    "IDENTITY_LIFETIMES",
    "Address",
    "AlreadyRegisteredError",
    "CachedRegistryClient",
    "DIDKeyEvidence",
    "DIDMapping",
    "KeyResolution",
    "Namespace",
    "ResolvedIdentityContract",
    "RegistryClient",
    "RegistryError",
    "backfill_missing_stable_ids",
    "canonical_server_origin",
    "canonical_json_bytes",
    "canonical_payload",
    "decode_public_key",
    "decrypt_signing_key",
    "destroy_signing_key",
    "did_from_public_key",
    "encode_public_key",
    "encrypt_signing_key",
    "ensure_agent_stable_ids",
    "generate_keypair",
    "get_custody_key",
    "get_sender_delivery_metadata",
    "log_entry_payload",
    "public_key_from_did",
    "require_canonical_server_origin",
    "resolve_identity_contract",
    "assert_permanent_identity",
    "sha256_hex",
    "sign_message",
    "sign_on_behalf",
    "state_hash",
    "stable_id_from_did_key",
    "stable_id_from_public_key",
    "validate_did",
    "validate_stable_id",
    "verify_did_key_signature",
    "verify_signature",
]
