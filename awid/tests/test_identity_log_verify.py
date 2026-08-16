from __future__ import annotations

import json
from pathlib import Path

import pytest

from awid.federation_errors import FederationAuthorityError
from awid.identity_log_verify import (
    IdentityCheckpoint,
    decode_identity_key_resolution,
    verify_identity_head,
    verify_identity_log,
)


_ROOT = Path(__file__).resolve().parents[2]
_VECTORS = _ROOT / "docs" / "vectors"


def _load(name: str) -> dict:
    return json.loads((_VECTORS / name).read_text(encoding="utf-8"))


def _checkpoint(value: dict | None) -> IdentityCheckpoint | None:
    if value is None:
        return None
    return IdentityCheckpoint(
        seq=value["seq"],
        entry_hash=value["entry_hash"],
        state_hash=value["state_hash"],
        current_did_key=value["current_did_key"],
        revision=1,
    )


@pytest.mark.parametrize("case", _load("identity-log-negative-v1.json")["cases"], ids=lambda case: case["name"])
def test_identity_head_vectors(case: dict) -> None:
    checkpoint = _checkpoint(case["cached"])
    if case["expected_outcome"] == "OK_VERIFIED":
        verified = verify_identity_head(
            did_aw=case["did_aw"],
            current_did_key=case["current_did_key"],
            entry=case["log_head"],
            checkpoint=checkpoint,
        )
        assert verified.current_did_key == case["current_did_key"]
        return

    with pytest.raises(FederationAuthorityError) as raised:
        verify_identity_head(
            did_aw=case["did_aw"],
            current_did_key=case["current_did_key"],
            entry=case["log_head"],
            checkpoint=checkpoint,
        )
    expected_reason = (
        "sender_identity_unverifiable"
        if case["expected_outcome"] == "OK_DEGRADED"
        else "sender_did_log_invalid"
    )
    assert raised.value.reason == expected_reason


@pytest.mark.parametrize("case", _load("identity-log-negative-v1.json")["log_cases"], ids=lambda case: case["name"])
def test_full_identity_log_vectors(case: dict) -> None:
    if case["expect_error"]:
        with pytest.raises(FederationAuthorityError) as raised:
            verify_identity_log(did_aw=case["did_aw"], entries=case["entries"])
        assert raised.value.reason == "sender_did_log_invalid"
    else:
        verified = verify_identity_log(did_aw=case["did_aw"], entries=case["entries"])
        assert verified.current_did_key == case["expected_current_did_key"]


def test_canonical_positive_log_and_checkpoint_containment() -> None:
    vectors = _load("identity-log-v1.json")
    did_aw = vectors["mapping"]["did_aw"]
    entries = [
        {
            **entry["entry_payload"],
            "entry_hash": entry["entry_hash"],
            "signature": entry["signature_b64"],
        }
        for entry in vectors["entries"]
    ]
    checkpoint = IdentityCheckpoint(
        seq=1,
        entry_hash=entries[0]["entry_hash"],
        state_hash=entries[0]["state_hash"],
        current_did_key=entries[0]["new_did_key"],
        revision=7,
    )
    verified = verify_identity_log(
        did_aw=did_aw,
        entries=entries,
        expected_current_did_key=vectors["mapping"]["rotated_did_key"],
        checkpoint=checkpoint,
    )
    assert verified.seq == 2
    assert verified.contains_checkpoint is True

    with pytest.raises(FederationAuthorityError) as raised:
        verify_identity_log(
            did_aw=did_aw,
            entries=entries[1:],
            expected_current_did_key=vectors["mapping"]["rotated_did_key"],
            checkpoint=checkpoint,
        )
    assert raised.value.reason in {"sender_did_log_invalid", "sender_did_log_split_view"}


@pytest.mark.parametrize("case", _load("identity-log-raw-wire-v1.json")["cases"], ids=lambda case: case["name"])
def test_raw_wire_sequence_values_fail_closed(case: dict) -> None:
    with pytest.raises(FederationAuthorityError) as raised:
        decode_identity_key_resolution(case["resolution_json"].encode("utf-8"))
    assert raised.value.reason == "sender_did_log_invalid"


@pytest.mark.parametrize("malformed_entry", [1, None, []])
def test_full_log_malformed_rows_are_typed(malformed_entry: object) -> None:
    vectors = _load("identity-log-v1.json")
    with pytest.raises(FederationAuthorityError) as raised:
        verify_identity_log(
            did_aw=vectors["mapping"]["did_aw"],
            entries=[malformed_entry],
        )
    assert raised.value.reason == "sender_did_log_invalid"


def test_full_log_bounds_stop_before_signature_work() -> None:
    vectors = _load("identity-log-v1.json")
    entry = vectors["entries"][0]
    wire = {
        **entry["entry_payload"],
        "entry_hash": entry["entry_hash"],
        "signature": entry["signature_b64"],
    }
    with pytest.raises(FederationAuthorityError) as raised:
        verify_identity_log(
            did_aw=vectors["mapping"]["did_aw"],
            entries=[wire] * 4097,
        )
    assert raised.value.reason == "sender_identity_evidence_too_large"
