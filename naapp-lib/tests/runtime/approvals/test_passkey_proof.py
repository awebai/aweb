"""The B3 helper reproduces the accepted proof commitment from exact bytes."""

import copy
import hashlib
import json
import os
from dataclasses import replace
from pathlib import Path

import cbor2
import pytest
from aweb_naapp_testing.webauthn import SoftAuthenticator, SoftCredential, b64url, from_b64url
from awid.signing import canonical_json_bytes
from cryptography.hazmat.primitives.asymmetric import ec

from aweb_naapp.runtime.passkeys.proof import (
    PasskeyInstallationContext,
    PasskeyProofUnavailable,
    ProofContextUnavailable,
    RetainedPasskeyProof,
    passkey_evidence_commitment,
)
from aweb_naapp.runtime.passkeys.rp import RelyingParty
from aweb_naapp.runtime.passkeys.webauthn import verify_assertion

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


def signed_approval_proof(*, challenge_version=1, wrapper_version=1, task_answer_ref=None):
    """Sign the complete malformed binding, so rejection cannot rely on corruption."""
    original = proof_for(next(c for c in VECTOR["cases"] if c["name"] == "approval_without_task"))
    context, metadata = original.context, original.metadata
    metadata["policy_version"] = 1
    if task_answer_ref is not None:
        metadata["task_answer_ref"] = task_answer_ref
    wrapper = json.loads(original.covered_request.split(b"\n", 1)[1])
    wrapper["policy"]["version"] = wrapper_version
    covered = b"aweb.approval-request/1\n" + canonical_json_bytes(wrapper)
    metadata["request_sha256"] = hashlib.sha256(covered).hexdigest()
    fields = json.loads(original.challenge_preimage.split(b"\n", 1)[1])
    fields.update(
        policy_version=challenge_version,
        request_sha256=metadata["request_sha256"],
        task_answer_ref=task_answer_ref,
    )
    preimage = b"aweb.approval-challenge/1\n" + canonical_json_bytes(fields)
    challenge = hashlib.sha256(preimage).digest()
    credential = SoftCredential(
        os.urandom(32), ec.generate_private_key(ec.SECP256R1()), context["rp_id"], os.urandom(32)
    )
    authenticator = SoftAuthenticator(context["origin"])
    authenticator.credentials[credential.credential_id] = credential
    assertion = authenticator.get(dict(rpId=context["rp_id"], challenge=b64url(challenge)))
    verified = verify_assertion(
        assertion,
        challenge=challenge,
        rp=RelyingParty(context["origin"], "proof regression"),
        credential_id=credential.credential_id,
        public_key=credential.cose_public_key(),
        sign_count=0,
    )
    metadata.update(sign_count_before=0, sign_count_after=verified.new_sign_count)
    return RetainedPasskeyProof.from_parts(
        context=context,
        metadata=metadata,
        challenge_preimage=preimage,
        expected_challenge=challenge,
        credential_public_key_cose=credential.cose_public_key(),
        credential_id=credential.credential_id,
        authenticator_data=from_b64url(assertion["response"]["authenticatorData"]),
        client_data_json=from_b64url(assertion["response"]["clientDataJSON"]),
        signature=from_b64url(assertion["response"]["signature"]),
        covered_request=covered,
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"challenge_version": True},
        {"challenge_version": 1.0},
        {"wrapper_version": True},
        {"wrapper_version": 1.0},
        {"challenge_version": True, "wrapper_version": True},
        {"task_answer_ref": ""},
        {"task_answer_ref": True},
    ],
)
def test_signed_approval_proofs_refuse_noninteger_pins_and_invalid_task_refs(changes):
    proof = signed_approval_proof(**changes)
    with pytest.raises(PasskeyProofUnavailable):
        passkey_evidence_commitment(proof)


@pytest.mark.parametrize("task_answer_ref", [None, "task-answer-\u00e9"])
def test_signed_approval_proofs_accept_integer_pins_and_optional_valid_task_refs(task_answer_ref):
    proof = signed_approval_proof(task_answer_ref=task_answer_ref)
    assert len(passkey_evidence_commitment(proof)) == 64


def credential_digest(credential: dict[str, str]) -> str:
    return hashlib.sha256(
        b"aweb.human-credential/1\n" + canonical_json_bytes(credential)
    ).hexdigest()


def a_credential(rp_id: str) -> dict[str, str]:
    key = SoftCredential(os.urandom(32), ec.generate_private_key(ec.SECP256R1()), rp_id, b"")
    return {
        "credential_id": b64url(key.credential_id),
        "public_key": b64url(key.cose_public_key()),
        "rp_id": rp_id,
    }


def signed_credential_change_proof(
    operation="add",
    *,
    fields=None,
    sidecar=None,
    prefix=b"aweb.passkey-credential-change/1\n",
    by_the_new_credential=False,
):
    """A real assertion over a credential_change challenge, signed whatever its
    binding says, so a rejection cannot rely on corruption. `fields` and
    `sidecar` change the signed challenge fields and the retained sidecar."""
    original = proof_for(next(c for c in VECTOR["cases"] if c["name"] == "console_login"))
    context, metadata = original.context, original.metadata
    context["binding_kind"] = "credential_change"
    metadata["purpose"] = "credential_change"
    credential = SoftCredential(
        os.urandom(32), ec.generate_private_key(ec.SECP256R1()), context["rp_id"], os.urandom(32)
    )
    new = (
        {
            "credential_id": b64url(credential.credential_id),
            "public_key": b64url(credential.cose_public_key()),
            "rp_id": context["rp_id"],
        }
        if by_the_new_credential
        else a_credential(context["rp_id"])
    )
    body = {"credential": new}
    signed = {
        "credential_sha256": credential_digest(new),
        "nonce": os.urandom(32).hex(),
        "operation": operation,
        "scope": context["scope"],
        "subject": metadata["subject"],
    }
    if operation == "replace":
        body["retire_credential"] = a_credential(context["rp_id"])
        signed["retire_credential_sha256"] = credential_digest(body["retire_credential"])
    signed.update(fields or {})
    body.update(sidecar or {})
    covered = b"aweb.passkey-credential-change-request/1\n" + canonical_json_bytes(
        {key: value for key, value in body.items() if value is not None}
    )
    preimage = prefix + canonical_json_bytes(
        {key: value for key, value in signed.items() if value is not None}
    )
    challenge = hashlib.sha256(preimage).digest()
    authenticator = SoftAuthenticator(context["origin"])
    authenticator.credentials[credential.credential_id] = credential
    assertion = authenticator.get(dict(rpId=context["rp_id"], challenge=b64url(challenge)))
    metadata.update(sign_count_before=0, sign_count_after=1)
    return RetainedPasskeyProof.from_parts(
        context=context,
        metadata=metadata,
        challenge_preimage=preimage,
        expected_challenge=challenge,
        credential_public_key_cose=credential.cose_public_key(),
        credential_id=credential.credential_id,
        authenticator_data=from_b64url(assertion["response"]["authenticatorData"]),
        client_data_json=from_b64url(assertion["response"]["clientDataJSON"]),
        signature=from_b64url(assertion["response"]["signature"]),
        covered_request=covered,
    )


@pytest.mark.parametrize("operation", ["add", "replace"])
def test_a_credential_change_proof_commits_its_exact_binding(operation):
    proof = signed_credential_change_proof(operation)
    assert len(passkey_evidence_commitment(proof)) == 64
    assert RetainedPasskeyProof.from_export(proof.export()) == proof


@pytest.mark.parametrize(
    "operation,changes",
    [
        ("add", {"fields": {"scope": "another.scope"}}),
        ("add", {"fields": {"subject": "another-subject"}}),
        ("add", {"fields": {"operation": "replace"}}),
        ("add", {"fields": {"retire_credential_sha256": "0" * 64}}),
        ("replace", {"fields": {"operation": "add"}}),
        ("replace", {"fields": {"retire_credential_sha256": None}}),
        ("replace", {"fields": {"retire_credential_sha256": "0" * 64}}),
        ("add", {"fields": {"credential_sha256": "0" * 64}}),
        ("add", {"sidecar": {"credential": a_credential("elsewhere.example.com")}}),
        ("add", {"sidecar": {"retire_credential": a_credential("app.example.com")}}),
        ("replace", {"sidecar": {"retire_credential": None}}),
        ("add", {"prefix": b"aweb.passkey-contact-change/1\n"}),
        ("add", {"prefix": b"aweb.passkey-login/1\n"}),
        ("add", {"fields": {"nonce": "A" * 64}}),
    ],
)
def test_a_credential_change_proof_refuses_a_swapped_binding(operation, changes):
    proof = signed_credential_change_proof(operation, **changes)
    with pytest.raises(PasskeyProofUnavailable):
        passkey_evidence_commitment(proof)


def test_a_credential_change_proof_needs_its_sidecar_and_no_approval_fields():
    proof = signed_credential_change_proof()
    with pytest.raises(PasskeyProofUnavailable):
        passkey_evidence_commitment(replace(proof, covered_request=None))
    metadata = proof.metadata
    metadata["approval_id"] = "approval-1"
    with_approval = replace(proof, metadata_canonical=canonical_json_bytes(metadata))
    with pytest.raises(PasskeyProofUnavailable):
        passkey_evidence_commitment(with_approval)


def test_a_credential_change_proof_signed_by_the_new_credential_is_refused():
    proof = signed_credential_change_proof(by_the_new_credential=True)
    with pytest.raises(PasskeyProofUnavailable):
        passkey_evidence_commitment(proof)


CHANGE_VECTOR = json.loads(
    (
        Path(__file__).resolve().parents[4] / "docs/vectors/passkey-credential-change-v1.json"
    ).read_bytes()
)


@pytest.mark.parametrize("case", CHANGE_VECTOR["cases"], ids=lambda case: case["name"])
def test_the_shared_helper_matches_the_credential_change_vectors(case):
    assert passkey_evidence_commitment(proof_for(case)) == case["commitment_sha256"]


@pytest.mark.parametrize("case", CHANGE_VECTOR["negative_cases"], ids=lambda case: case["name"])
def test_the_shared_helper_refuses_the_credential_change_negatives(case):
    with pytest.raises(PasskeyProofUnavailable):
        passkey_evidence_commitment(proof_for(case))
