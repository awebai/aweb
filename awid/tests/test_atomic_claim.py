import json
from pathlib import Path

import pytest
from awid.atomic_claim import (
    AtomicAddressClaimFields,
    atomic_address_claim_identity_canonical,
    atomic_address_claim_identity_proof_hash,
    atomic_address_claim_namespace_canonical,
    canonical_registry_origin,
)


def _vector() -> dict:
    path = (
        Path(__file__).parents[2] / "docs" / "vectors" / "atomic-address-claim-v1.json"
    )
    return json.loads(path.read_text())


def _fields(vector: dict) -> AtomicAddressClaimFields:
    return AtomicAddressClaimFields(
        operation=vector["operation"],
        domain=vector["domain"],
        address_name=vector["address_name"],
        did_aw=vector["did_aw"],
        current_did_key=vector["current_did_key"],
        registry_url=vector["registry_url"],
        timestamp=vector["timestamp"],
        dry_run=vector["dry_run"],
        identity_custody=vector["identity_custody"],
        namespace_custody=vector["namespace_custody"],
    )


def test_atomic_address_claim_canonical_fixture():
    vector = _vector()
    fields = _fields(vector)

    identity_canonical = atomic_address_claim_identity_canonical(fields)
    assert identity_canonical.decode() == vector["identity_canonical"]

    identity_proof_hash = atomic_address_claim_identity_proof_hash(
        identity_canonical, vector["identity_signature"]
    )
    assert identity_proof_hash == vector["identity_proof_hash"]

    namespace_canonical = atomic_address_claim_namespace_canonical(
        fields, identity_proof_hash
    )
    assert namespace_canonical.decode() == vector["namespace_canonical"]


def test_atomic_address_claim_registry_url_aliases_match_fixture():
    vector = _vector()

    for alias in vector["registry_url_aliases"]:
        assert canonical_registry_origin(alias["input"]) == alias["canonical"]


def test_atomic_address_claim_rejects_hosted_did_self_namespace():
    vector = _vector()
    fields = _fields(vector)
    fields = AtomicAddressClaimFields(
        operation=fields.operation,
        domain=fields.domain,
        address_name=fields.address_name,
        did_aw=fields.did_aw,
        current_did_key=fields.current_did_key,
        registry_url=fields.registry_url,
        timestamp=fields.timestamp,
        dry_run=fields.dry_run,
        identity_custody="hosted_custodial",
        namespace_custody="self",
    )
    with pytest.raises(ValueError, match="unsupported"):
        atomic_address_claim_identity_canonical(fields)


def test_identity_proof_hash_uses_the_bytes_that_signature_verification_accepts():
    from awid.did import did_key_from_signing_key
    from awid.signing import VerifyResult, sign_message, verify_signature

    vector = _vector()
    canonical = atomic_address_claim_identity_canonical(_fields(vector))
    key = bytes(range(32))
    did = did_key_from_signing_key(key)
    standard = sign_message(key, canonical)
    urlsafe = standard.replace("+", "-").replace("/", "_")
    assert urlsafe != standard  # The fixture exercises both alphabets.
    assert verify_signature(did, canonical, standard) is VerifyResult.VERIFIED
    assert verify_signature(did, canonical, urlsafe) is VerifyResult.VERIFIED
    assert atomic_address_claim_identity_proof_hash(
        canonical, urlsafe
    ) == atomic_address_claim_identity_proof_hash(canonical, standard)
