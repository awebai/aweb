"""The B3 helper reproduces the accepted proof commitment from exact bytes."""

import copy
import json
import os
from dataclasses import replace
from pathlib import Path

import cbor2
import pytest

from aweb_naapp.runtime.passkeys.proof import (
    PasskeyInstallationContext,
    PasskeyProofUnavailable,
    ProofContextUnavailable,
    RetainedPasskeyProof,
    passkey_evidence_commitment,
)

VECTOR = json.loads(
    (Path(__file__).resolve().parents[4] / "docs/vectors/passkey-evidence-v1.json").read_bytes()
)


def proof_for(case):
    return RetainedPasskeyProof.from_parts(
        context=case["context"],
        metadata=case["metadata"],
        expected_challenge=bytes.fromhex(case["expected_challenge_hex"]),
        covered_request=bytes.fromhex(case["covered_request_hex"])
        if "covered_request_hex" in case
        else None,
        **{key: bytes.fromhex(value) for key, value in case["binary_hex"].items()},
    )


@pytest.mark.parametrize("case", VECTOR["cases"], ids=lambda case: case["name"])
def test_the_shared_helper_matches_real_assertion_vectors(case):
    proof = proof_for(case)
    assert passkey_evidence_commitment(proof) == case["commitment_sha256"]
    assert proof.context_canonical.decode() == case["canonical_context_utf8"]
    assert proof.metadata_canonical.decode() == case["canonical_metadata_utf8"]
    assert RetainedPasskeyProof.from_export(proof.export()) == proof
    assert case["metadata"]["subject"] not in repr(proof)
    assert case["binary_hex"]["signature"] not in repr(proof)


@pytest.mark.parametrize(
    "field",
    [
        "signature",
        "authenticator_data",
        "client_data_json",
        "credential_public_key_cose",
        "expected_challenge",
        "challenge_preimage",
        "covered_request",
    ],
)
def test_the_helper_refuses_corrupt_or_missing_retained_proof(field):
    case = next(c for c in VECTOR["cases"] if c["name"] == "approval_without_task")
    proof = proof_for(case)
    value = getattr(proof, field)
    with pytest.raises(PasskeyProofUnavailable):
        passkey_evidence_commitment(replace(proof, **{field: value + b"corrupt"}))
    with pytest.raises(PasskeyProofUnavailable):
        passkey_evidence_commitment(replace(proof, **{field: b""}))


@pytest.mark.parametrize(
    "part,field,value",
    [
        ("context", "generation", True),
        ("context", "require_up", False),
        ("context", "require_uv", False),
        ("context", "scope", "different"),
        ("context", "unexpected", "field"),
        ("metadata", "purpose", "reject"),
        ("metadata", "sign_count_after", True),
        ("metadata", "sign_count_after", 99),
        ("metadata", "sign_count_before", 2),
        ("metadata", "verified_at", "2026-10-21T12:00:00"),
        ("metadata", "verified_at", "2026-10-21T12:00:00.123456+00:99"),
        ("metadata", "verified_at", "2026-10-21T12:06:00.123456Z"),
        ("metadata", "unexpected", "field"),
    ],
)
def test_closed_context_metadata_and_ceremony_bindings_are_enforced(part, field, value):
    case = copy.deepcopy(next(c for c in VECTOR["cases"] if c["name"] == "console_login"))
    case[part][field] = value
    with pytest.raises(PasskeyProofUnavailable):
        passkey_evidence_commitment(proof_for(case))


def test_original_instant_and_immutable_raw_bytes_survive_export_and_rotation():
    case = copy.deepcopy(next(c for c in VECTOR["cases"] if c["name"] == "console_login"))
    case["metadata"]["verified_at"] = "2026-10-21T14:00:00.123456+02:00"
    proof = proof_for(case)
    assert passkey_evidence_commitment(proof) == case["commitment_sha256"]
    assert (
        passkey_evidence_commitment(RetainedPasskeyProof.from_export(proof.export()))
        == case["commitment_sha256"]
    )
    view = proof.context
    view["generation"] = 99
    assert proof.context["generation"] == case["context"]["generation"]


def test_four_field_installation_context_rejects_invalid_generation():
    with pytest.raises(ProofContextUnavailable):
        PasskeyInstallationContext("app", "team", "install", True)


def test_a_cose_private_component_is_not_retained_as_a_public_key():
    proof = proof_for(VECTOR["cases"][0])
    key = cbor2.loads(proof.credential_public_key_cose)
    key[-4] = os.urandom(32)
    with pytest.raises(PasskeyProofUnavailable):
        passkey_evidence_commitment(replace(proof, credential_public_key_cose=cbor2.dumps(key)))
