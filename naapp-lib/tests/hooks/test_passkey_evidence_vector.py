"""Frozen evidence bytes; B3/S13/S14 integration remains a separate proof."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import struct
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aweb_naapp.hooks.catalog import packaged_catalog
from aweb_naapp.hooks.envelope import _check_actor

VECTOR = json.loads(
    (
        Path(__file__).resolve().parents[3] / "docs" / "vectors" / "passkey-evidence-v1.json"
    ).read_bytes()
)
OPTIONAL = {"approval_id", "request_sha256", "policy_ref", "policy_version", "task_answer_ref"}
REQUIRED = {"evidence_ref", "subject", "purpose", "verified_at"}


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _reference_projection(record):
    projection = {k: record[k] for k in REQUIRED}
    projection.update({k: record[k] for k in OPTIONAL if record.get(k) is not None})
    projection["verified_at"] = (
        datetime.fromisoformat(record["verified_at"].replace("Z", "+00:00"))
        .astimezone(UTC)
        .strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    )
    return projection


@pytest.mark.parametrize("case", VECTOR["cases"], ids=lambda case: case["name"])
def test_frozen_projection_and_framed_bytes(case):
    # Independent reading of the contract, not a runtime evidence serializer.
    # The eventual shared B3 helper must consume this same root vector.
    record = {**case["record"], "credential_id": secrets.token_bytes(32), "sign_count": 42}
    projection = _reference_projection(record)
    assert projection == case["projection"]
    context_bytes, evidence_bytes = _canonical(case["context"]), _canonical(projection)
    assert context_bytes == case["canonical_context_utf8"].encode()
    assert evidence_bytes == case["canonical_evidence_utf8"].encode()
    assert not set(VECTOR["excluded_record_fields"]) & projection.keys()
    expected = (
        b"aweb.passkey-evidence/1\n"
        + struct.pack(">Q", len(context_bytes))
        + context_bytes
        + struct.pack(">Q", len(evidence_bytes))
        + evidence_bytes
    )
    assert expected == bytes.fromhex(case["mac_input_hex"])


def test_same_instant_and_null_omission_have_one_spelling():
    cases = {case["name"]: case for case in VECTOR["cases"]}
    first = cases["console_login_nulls_omitted"]
    assert first["mac_input_hex"] == cases["login_offset_same_instant"]["mac_input_hex"]
    assert not OPTIONAL & first["projection"].keys()
    assert cases["login_zero_microseconds"]["projection"]["verified_at"].endswith(".000000Z")


def test_console_actor_and_affected_subject_fit_the_existing_contract():
    example = VECTOR["console_governance"]
    assert example["actor"] == {"authority_mode": "system", "attestations": []}
    _check_actor(example["actor"])
    assert example["authorizing_subject"] != example["payload"]["subject_ref"]
    key = secrets.token_bytes(32)
    message = bytes.fromhex(VECTOR["cases"][0]["mac_input_hex"])
    commitment = hmac.new(key, message, hashlib.sha256).hexdigest()
    catalog = packaged_catalog()
    catalog.validate(
        "post-governance-hook", {**example["payload"], "approval_evidence_sha256": commitment}
    )
    catalog.validate(
        "post-secret-use-hook",
        {
            "action": "approval_decided",
            "op_kind": "broker",
            "approval_id": "approval-1",
            "approval_decision": "approved",
            "approval_evidence_sha256": commitment,
        },
    )


def test_both_catalog_fields_describe_keyed_commitments():
    vector_path = Path(__file__).resolve().parents[3] / "docs" / "vectors" / "hook-catalog-v1.json"
    catalog = json.loads(vector_path.read_bytes())
    for hook in ("post-governance-hook", "post-secret-use-hook"):
        assert (
            catalog["hooks"][hook]["fields"]["approval_evidence_sha256"]["type"]
            == "hmac_sha256_hex"
        )
