"""Decision-84 public byte/proof vectors; B3 owns the future runtime helper.

This is an independent offline reader of the proposed contract, using B3's
existing WebAuthn verifier. It neither stores proof nor supplies a producer codec.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import struct
from datetime import UTC, datetime
from pathlib import Path

import pytest
from aweb_naapp_testing.webauthn import b64url
from awid.signing import canonical_json_bytes

from aweb_naapp.hooks.catalog import packaged_catalog
from aweb_naapp.hooks.envelope import _check_actor
from aweb_naapp.runtime.passkeys.rp import RelyingParty
from aweb_naapp.runtime.passkeys.webauthn import WebAuthnRefused, verify_assertion

VECTOR = json.loads(
    (
        Path(__file__).resolve().parents[3] / "docs" / "vectors" / "passkey-evidence-v1.json"
    ).read_bytes()
)
CASES = {case["name"]: case for case in VECTOR["cases"]}
APPROVAL_PREFIX = b"aweb.approval-challenge/1\n"
REQUEST_PREFIX = b"aweb.approval-request/1\n"
LOGIN_PREFIX = b"aweb.passkey-login/1\n"
APPROVAL_FIELDS = {
    "approval_id",
    "candidate_subject",
    "candidate_subject_type",
    "nonce",
    "policy_ref",
    "policy_version",
    "purpose",
    "request_sha256",
    "task_answer_ref",
}


class ProofRefused(ValueError):
    pass


def _refuse(code):
    raise ProofRefused(code)


def _hex(value):
    if not isinstance(value, str) or not value or not re.fullmatch("(?:[0-9a-f]{2})+", value):
        _refuse("proof_invalid")
    return bytes.fromhex(value)


def _metadata(record):
    result = dict(record)
    for key in ("verified_at", "challenge_issued_at", "challenge_expires_at"):
        instant = datetime.fromisoformat(result[key].replace("Z", "+00:00"))
        if instant.tzinfo is None:
            _refuse("proof_invalid")
        result[key] = instant.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return result


def _input(context, metadata, binary):
    pieces = [canonical_json_bytes(context), canonical_json_bytes(metadata)]
    pieces.extend(binary[name] for name in VECTOR["binary_order"])
    return b"aweb.passkey-evidence/1\n" + b"".join(
        struct.pack(">Q", len(piece)) + piece for piece in pieces
    )


def _verify(case, *, trusted_anchor, expected_context):
    """Independent verification inputs are passed by the reviewer, not the record."""
    context, metadata = case["context"], _metadata(case["metadata"])
    if context != expected_context or (context["origin"], context["rp_id"]) != (
        trusted_anchor["origin"],
        trusted_anchor["rp_id"],
    ):
        _refuse("context_mismatch")
    if set(case["binary_hex"]) != set(VECTOR["binary_order"]):
        _refuse("proof_unavailable")
    binary = {key: _hex(value) for key, value in case["binary_hex"].items()}
    public_key = binary["credential_public_key_cose"]
    if public_key != _hex(trusted_anchor["public_key_cose_hex"]):
        _refuse("untrusted_key")
    preimage = binary["challenge_preimage"]
    prefix = APPROVAL_PREFIX if context["binding_kind"] == "approval" else LOGIN_PREFIX
    if not preimage.startswith(prefix):
        _refuse("binding_mismatch")
    fields = json.loads(preimage[len(prefix) :])
    if prefix + canonical_json_bytes(fields) != preimage:
        _refuse("binding_mismatch")
    if context["binding_kind"] == "approval":
        if set(fields) != APPROVAL_FIELDS or fields["candidate_subject_type"] != "app_local":
            _refuse("binding_mismatch")
        if fields["candidate_subject"] != metadata["subject"]:
            _refuse("binding_mismatch")
        for name in ("approval_id", "purpose", "policy_ref", "policy_version", "request_sha256"):
            if fields[name] != metadata[name]:
                _refuse("binding_mismatch")
        if fields["task_answer_ref"] != metadata.get("task_answer_ref"):
            _refuse("binding_mismatch")
        if "covered_request_hex" not in case:
            _refuse("proof_unavailable")
        covered = _hex(case["covered_request_hex"])
        if hashlib.sha256(covered).hexdigest() != fields["request_sha256"]:
            _refuse("request_mismatch")
        if not covered.startswith(REQUEST_PREFIX):
            _refuse("request_mismatch")
        wrapper = json.loads(covered[len(REQUEST_PREFIX) :])
        if covered != REQUEST_PREFIX + canonical_json_bytes(wrapper):
            _refuse("request_mismatch")
        if wrapper["policy"] != {"ref": fields["policy_ref"], "version": fields["policy_version"]}:
            _refuse("binding_mismatch")
        request = wrapper["request"]
        if (request["team_id"], request["installation_id"], request["install_generation"]) != (
            context["team_id"],
            context["installation_id"],
            context["generation"],
        ):
            _refuse("binding_mismatch")
    elif (
        set(fields) != {"nonce", "scope", "subject"}
        or fields["scope"] != context["scope"]
        or fields["subject"] != metadata["subject"]
        or metadata["purpose"] != "login"
    ):
        _refuse("binding_mismatch")
    if not re.fullmatch("[0-9a-f]{64}", fields["nonce"]):
        _refuse("binding_mismatch")
    challenge = hashlib.sha256(preimage).digest()
    client_data = json.loads(binary["client_data_json"])
    if challenge != _hex(case["expected_challenge_hex"]) or client_data["challenge"] != b64url(
        challenge
    ):
        _refuse("challenge_mismatch")
    before, after = metadata["sign_count_before"], metadata["sign_count_after"]
    if after != int.from_bytes(binary["authenticator_data"][33:37], "big"):
        _refuse("counter_mismatch")
    if not (before == after == 0 or after > before):
        _refuse("counter_mismatch")
    cid = b64url(binary["credential_id"])
    proof = {
        "id": cid,
        "rawId": cid,
        "type": "public-key",
        "response": {
            "authenticatorData": b64url(binary["authenticator_data"]),
            "clientDataJSON": b64url(binary["client_data_json"]),
            "signature": b64url(binary["signature"]),
        },
    }
    try:
        verify_assertion(
            proof,
            challenge=challenge,
            rp=RelyingParty(context["origin"], "vector"),
            credential_id=binary["credential_id"],
            public_key=public_key,
            sign_count=before,
        )
    except WebAuthnRefused:
        _refuse("bad_assertion")
    message = _input(context, metadata, binary)
    if hashlib.sha256(message).hexdigest() != case["commitment_sha256"]:
        _refuse("commitment_mismatch")
    return message


@pytest.mark.parametrize("case", VECTOR["cases"], ids=lambda case: case["name"])
def test_real_retained_assertion_matches_the_frozen_bytes_and_trusted_key(case):
    message = _verify(
        case,
        trusted_anchor=VECTOR["trust_anchors"][case["trusted_key"]],
        expected_context=case["context"],
    )
    assert message == _hex(case["commitment_input_hex"])
    assert canonical_json_bytes(case["context"]).decode() == case["canonical_context_utf8"]
    assert (
        canonical_json_bytes(_metadata(case["metadata"])).decode()
        == case["canonical_metadata_utf8"]
    )


def _mutate(case, mutation):
    binary = case["binary_hex"]
    if mutation == "drop_signature":
        del binary["signature"]
    elif mutation == "corrupt_signature":
        sig = bytearray(_hex(binary["signature"]))
        sig[-1] ^= 1
        binary["signature"] = sig.hex()
    elif mutation == "reserialize_client_data":
        data = json.loads(_hex(binary["client_data_json"]))
        binary["client_data_json"] = canonical_json_bytes(data).hex()
    elif mutation == "substitute_key":
        binary["credential_public_key_cose"] = "00"
    elif mutation == "wrong_origin":
        case["context"]["origin"] = "https://other.example.com"
    elif mutation == "wrong_generation":
        case["context"]["generation"] += 1
    elif mutation == "wrong_scope":
        case["context"]["scope"] = "another-scope"
    elif mutation == "wrong_counter_after":
        case["metadata"]["sign_count_after"] += 1
    elif mutation == "wrong_expected_challenge":
        case["expected_challenge_hex"] = "00" * 32
    elif mutation == "wrong_sidecar":
        case["covered_request_hex"] += "20"
    elif mutation == "wrong_policy_pin":
        case["metadata"]["policy_version"] += 1
    elif mutation == "omit_null_task":
        fields = json.loads(_hex(binary["challenge_preimage"])[len(APPROVAL_PREFIX) :])
        del fields["task_answer_ref"]
        binary["challenge_preimage"] = (APPROVAL_PREFIX + canonical_json_bytes(fields)).hex()
    elif mutation == "wrong_commitment":
        case["commitment_sha256"] = "00" * 32
    else:
        raise AssertionError(f"unknown vector mutation: {mutation}")


@pytest.mark.parametrize("negative", VECTOR["negative_cases"], ids=lambda case: case["name"])
def test_retained_proof_single_fault_cases(negative):
    original = CASES[negative["base"]]
    case = copy.deepcopy(original)
    _mutate(case, negative["mutation"])
    with pytest.raises(ProofRefused, match="^" + negative["error"] + "$"):
        _verify(
            case,
            trusted_anchor=VECTOR["trust_anchors"][case["trusted_key"]],
            expected_context=original["context"],
        )


def test_original_utc_instant_and_null_challenge_spelling_are_preserved():
    original = CASES["console_login"]
    case = copy.deepcopy(original)
    case["metadata"]["verified_at"] = "2026-10-21T14:00:00.123456+02:00"
    assert _verify(
        case,
        trusted_anchor=VECTOR["trust_anchors"][case["trusted_key"]],
        expected_context=original["context"],
    ) == _hex(original["commitment_input_hex"])
    approval = CASES["approval_without_task"]
    assert b'"task_answer_ref":null' in _hex(approval["binary_hex"]["challenge_preimage"])
    assert "task_answer_ref" not in approval["metadata"]


def test_another_valid_assertion_cannot_replace_the_published_commitment():
    case = copy.deepcopy(CASES["approval_with_task"])
    case["commitment_sha256"] = CASES["approval_without_task"]["commitment_sha256"]
    with pytest.raises(ProofRefused, match="^commitment_mismatch$"):
        _verify(
            case,
            trusted_anchor=VECTOR["trust_anchors"][case["trusted_key"]],
            expected_context=case["context"],
        )


def test_verification_has_no_commitment_key_or_live_service_dependency():
    # This entire verifier takes only frozen public bytes and an external key;
    # it has no current signing key, passkey row, evidence lookup or HMAC key.
    original = CASES["approval_without_task"]
    exported = json.loads(json.dumps(original))
    assert _verify(
        exported,
        trusted_anchor=VECTOR["trust_anchors"][exported["trusted_key"]],
        expected_context=original["context"],
    ) == _hex(original["commitment_input_hex"])


def test_console_actor_affects_a_different_subject_and_catalog_fields_are_sha256():
    example = VECTOR["console_governance"]
    assert example["actor"] == {"authority_mode": "system", "attestations": []}
    _check_actor(example["actor"])
    assert example["authorizing_subject"] != example["payload"]["subject_ref"]
    catalog = packaged_catalog()
    catalog.validate(
        "post-governance-hook",
        {
            **example["payload"],
            "approval_evidence_sha256": CASES["console_login"]["commitment_sha256"],
        },
    )
    path = Path(__file__).resolve().parents[3] / "docs" / "vectors" / "hook-catalog-v1.json"
    document = json.loads(path.read_bytes())
    for hook in ("post-governance-hook", "post-secret-use-hook"):
        assert document["hooks"][hook]["fields"]["approval_evidence_sha256"]["type"] == "sha256_hex"
