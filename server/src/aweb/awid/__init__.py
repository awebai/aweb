"""Identity primitives: did:key encoding/decoding, signing, registry client."""

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
    canonical_json_bytes,
    canonical_payload,
    sign_message,
    verify_did_key_signature,
)

__all__ = [
    "SIGNED_FIELDS",
    "Address",
    "AlreadyRegisteredError",
    "CachedRegistryClient",
    "DIDKeyEvidence",
    "DIDMapping",
    "KeyResolution",
    "Namespace",
    "RegistryClient",
    "RegistryError",
    "canonical_json_bytes",
    "canonical_payload",
    "decode_public_key",
    "did_from_public_key",
    "encode_public_key",
    "generate_keypair",
    "public_key_from_did",
    "sign_message",
    "stable_id_from_did_key",
    "stable_id_from_public_key",
    "validate_did",
    "validate_stable_id",
    "verify_did_key_signature",
]
