from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from awid.registry_migration import (
    DestinationCompletePayload,
    RegistryMigrationReceipt,
    make_receipt,
    parse_receipt,
    receipt_payload_bytes,
)
from awid_service.registry_migration import (
    RegistryMigrationError,
    RegistryMigrationService,
)

VECTOR = Path(__file__).parents[2] / "docs" / "vectors" / "registry-migration-receipts-v1.json"


def _vectors():
    return json.loads(VECTOR.read_text())["receipts"]


def test_destination_complete_service_binding_accepts_normative_and_300_second_window():
    vectors = _vectors()
    overlap = parse_receipt({
        "payload": vectors["canonical_overlap"]["payload"],
        "receipt_hash": vectors["canonical_overlap"]["receipt_hash"],
    })
    completion = parse_receipt({
        "payload": vectors["destination_complete"]["payload"],
        "receipt_hash": vectors["destination_complete"]["receipt_hash"],
    }).payload
    row = {
        "source_registry_id": completion.source_registry_id,
        "destination_registry_id": completion.destination_registry_id,
        "source_generation": completion.source_generation,
        "snapshot_digest": completion.snapshot_digest,
        "manifest_digest": completion.manifest_digest,
        "expected_destination_origin": completion.destination_registry_origin,
        "overlap_receipt_hash": completion.overlap_receipt_hash,
        "destination_observation_hash": overlap.payload.destination_observation_hash,
        "old_selection_evidence": {
            "evidence_hash": overlap.payload.old_selection_evidence_hash,
            "old_registry_origin": overlap.payload.old_registry_origin,
            "ttl_seconds": overlap.payload.old_ttl_seconds,
        },
        "overlap_started_at": datetime.fromisoformat(
            overlap.payload.overlap_started_at.replace("Z", "+00:00")
        ),
        "complete_after": datetime.fromisoformat(
            completion.complete_after.replace("Z", "+00:00")
        ),
    }

    RegistryMigrationService._bind_destination_complete(
        row, completion.cutover_id, completion, overlap.payload
    )
    exactly_300 = DestinationCompletePayload.model_validate(
        completion.model_dump(mode="json")
        | {"destination_completed_at": "2026-08-26T18:15:10Z"}
    )
    RegistryMigrationService._bind_destination_complete(
        row, completion.cutover_id, exactly_300, overlap.payload
    )
    over_300 = DestinationCompletePayload.model_validate(
        completion.model_dump(mode="json")
        | {"destination_completed_at": "2026-08-26T18:15:11Z"}
    )
    with pytest.raises(RegistryMigrationError, match="does not match cutover"):
        RegistryMigrationService._bind_destination_complete(
            row, completion.cutover_id, over_300, overlap.payload
        )


def test_registry_migration_semantic_and_readback_known_bytes_cover_both_dispositions():
    vector = json.loads(VECTOR.read_text())["semantic_projection"]
    assert {item["disposition"] for item in vector["decisions"]} == {"inserted", "reused"}
    assert {item["disposition"] for item in vector["projection_cases"]} == {
        "inserted", "reused",
    }
    decisions = {item["disposition"]: item for item in vector["decisions"]}
    for case in vector["projection_cases"]:
        assert RegistryMigrationService._semantic_row(case["source_row"]) == case[
            "semantic_row"
        ]
        assert RegistryMigrationService._semantic_row(case["destination_row"]) == case[
            "semantic_row"
        ]
        semantic_payload = RegistryMigrationService._semantic_projection(
            "did", case["semantic_row"]["did_aw"], case["source_row"]
        )
        assert semantic_payload["version"] == (
            "awid.registry-migration-semantic-projection.v1"
        )
        semantic_bytes = json.dumps(
            semantic_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
        assert semantic_bytes == case["semantic_canonical_json_utf8"].encode()
        assert RegistryMigrationService._digest(semantic_payload) == case[
            "semantic_digest"
        ]
        source_item = {
            "kind": "did", "key": case["semantic_row"]["did_aw"],
            "row": case["source_row"],
        }
        assert RegistryMigrationService._digest(source_item) == case[
            "source_item_digest"
        ]
        assert decisions[case["disposition"]]["semantic_digest"] == case[
            "semantic_digest"
        ]
        assert decisions[case["disposition"]]["source_item_digest"] == case[
            "source_item_digest"
        ]
    assert RegistryMigrationService._semantic_row(
        vector["projection_cases"][0]["source_row"] | {"other_metadata": "included"}
    )["other_metadata"] == "included"
    canonical = json.dumps(
        vector["decisions"], sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    assert canonical == vector["canonical_json_utf8"].encode()
    assert "sha256:" + hashlib.sha256(canonical).hexdigest() == vector[
        "semantic_manifest_digest"
    ]
    readback = json.dumps(
        vector["readback_payload"], sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    assert readback == vector["readback_canonical_json_utf8"].encode()
    assert "sha256:" + hashlib.sha256(readback).hexdigest() == vector[
        "readback_hash"
    ]


@pytest.mark.parametrize("name", ["dns_authorization", "overlap_observation", "canonical_overlap", "destination_complete"])
def test_registry_migration_receipt_vectors_are_byte_exact(name):
    vector = _vectors()[name]
    parsed = parse_receipt(
        {"payload": vector["payload"], "receipt_hash": vector["receipt_hash"]}
    )

    assert receipt_payload_bytes(parsed.payload) == vector["canonical_json_utf8"].encode()
    assert make_receipt(parsed.payload).receipt_hash == vector["receipt_hash"]


def test_receipts_reject_lexically_valid_impossible_timestamp():
    vector = _vectors()["overlap_observation"]
    with pytest.raises(ValidationError):
        RegistryMigrationReceipt.model_validate({
            "payload": vector["payload"]
            | {"destination_observed_at": "2026-13-40T25:61:61Z"},
            "receipt_hash": vector["receipt_hash"],
        })


def test_destination_complete_rejects_malformed_dns_digest_and_controller():
    vector = _vectors()["destination_complete"]
    for field, value in (
        ("destination_dns_answer_digest", "not-a-digest"),
        ("destination_controller_did", "did:key:invalid"),
        ("destination_dns_name", "_awid.Example.COM"),
    ):
        with pytest.raises(ValidationError):
            RegistryMigrationReceipt.model_validate({
                "payload": vector["payload"] | {field: value},
                "receipt_hash": vector["receipt_hash"],
            })


@pytest.mark.parametrize("name", ["dns_authorization", "overlap_observation", "canonical_overlap", "destination_complete"])
def test_registry_migration_receipts_reject_tamper_unknown_and_self_hash(name):
    vector = _vectors()[name]
    wire = {"payload": vector["payload"], "receipt_hash": vector["receipt_hash"]}

    with pytest.raises(ValueError, match="receipt_hash"):
        parse_receipt(wire | {"receipt_hash": "sha256:" + "0" * 64})
    with pytest.raises(ValidationError):
        RegistryMigrationReceipt.model_validate(wire | {"unknown": True})
    with pytest.raises(ValidationError):
        RegistryMigrationReceipt.model_validate(
            wire | {"payload": vector["payload"] | {"receipt_hash": vector["receipt_hash"]}}
        )

    field = next(key for key in vector["payload"] if key.endswith("_digest"))
    with pytest.raises(ValueError, match="receipt_hash"):
        parse_receipt(
            wire
            | {
                "payload": vector["payload"]
                | {field: "sha256:" + "f" * 64}
            }
        )
