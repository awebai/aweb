from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from awid.delegation import (
    DelegationAssertion,
    DelegationPayload,
    DelegationSignature,
    canonical_delegation_payload,
    delegation_entry_hash,
    parse_delegation_assertion,
    verify_delegation_signature,
)


VECTOR_PATH = Path(__file__).parents[2] / "docs" / "vectors" / "namespace-delegation-v1.json"


def _vector() -> dict:
    return json.loads(VECTOR_PATH.read_text())


def test_namespace_delegation_vector_reproduces_exact_bytes_hash_and_signature():
    vector = _vector()
    payload = DelegationPayload.model_validate(vector["payload"])

    canonical = canonical_delegation_payload(payload)

    assert canonical == vector["canonical_json_utf8"].encode()
    assert delegation_entry_hash(canonical) == vector["entry_hash"]
    verify_delegation_signature(
        controller_did=vector["parent_controller_did"],
        signature=vector["parent_signature"],
        canonical_payload=canonical,
    )


def test_delegation_payload_is_strict_and_exact():
    vector = _vector()
    payload = dict(vector["payload"])

    with pytest.raises(ValidationError):
        DelegationPayload.model_validate(payload | {"unknown": "field"})
    with pytest.raises(ValidationError):
        DelegationPayload.model_validate(payload | {"sequence": True})
    with pytest.raises(ValidationError):
        DelegationPayload.model_validate(payload | {"sequence": 0})
    with pytest.raises(ValidationError):
        DelegationPayload.model_validate(payload | {"parent_domain": "example.net"})
    with pytest.raises(ValidationError):
        DelegationPayload.model_validate(payload | {"parent_domain": "Aweb.AI"})
    with pytest.raises(ValidationError):
        DelegationPayload.model_validate(payload | {"child_domain": "juanre.aweb.ai."})
    with pytest.raises(ValidationError):
        DelegationPayload.model_validate(payload | {"child_domain": "aweb.ai"})


def test_delegation_previous_hash_and_operation_rules_are_exact():
    payload = dict(_vector()["payload"])

    with pytest.raises(ValidationError):
        DelegationPayload.model_validate(payload | {"sequence": 2})
    with pytest.raises(ValidationError):
        DelegationPayload.model_validate(
            payload
            | {
                "sequence": 1,
                "previous_delegation_hash": "sha256:" + "0" * 64,
            }
        )
    with pytest.raises(ValidationError):
        DelegationPayload.model_validate(payload | {"operation": "delete"})


def test_delegation_signature_requires_canonical_unpadded_standard_base64():
    vector = _vector()
    canonical = vector["parent_signature"]

    DelegationSignature(controller_did=vector["parent_controller_did"], signature=canonical)
    for invalid in (
        canonical + "=",
        canonical.replace("+", "-"),
        canonical[:-1],
        "not base64!",
    ):
        with pytest.raises(ValidationError):
            DelegationSignature(
                controller_did=vector["parent_controller_did"],
                signature=invalid,
            )


def test_assertion_rejects_hash_mismatch_duplicates_and_sorts_signatures():
    vector = _vector()
    signature = {
        "controller_did": vector["parent_controller_did"],
        "signature": vector["parent_signature"],
    }
    assertion = {
        "payload": vector["payload"],
        "entry_hash": vector["entry_hash"],
        "signatures": [signature],
    }

    parsed = parse_delegation_assertion(assertion)
    assert parsed.entry_hash == vector["entry_hash"]

    with pytest.raises(ValueError, match="entry_hash"):
        parse_delegation_assertion(assertion | {"entry_hash": "sha256:" + "0" * 64})
    with pytest.raises(ValidationError):
        DelegationAssertion.model_validate(assertion | {"signatures": [signature, signature]})
    with pytest.raises(ValidationError):
        DelegationAssertion.model_validate(assertion | {"extra": True})
