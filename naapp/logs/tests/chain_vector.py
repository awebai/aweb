"""Building ``docs/vectors/logs-chain-v1.json`` from the chain cases, and reading it back."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from aweb_naapp.hooks.strictjson import (
    canonical,
    decode_base64url,
    encode_base64url,
    encode_signature,
)
from nacl.signing import SigningKey

from aweb_logs.chain import (
    CHECKPOINT_PREFIX,
    RECEIPT_PREFIX,
    Genesis,
    Link,
    content_commitment,
)
from aweb_logs.verify import Content, StoredEvent

from .chain_cases import LOGS_DID, ChainCase, cases, content, receipt
from .chain_cases import checkpoint as make_checkpoint
from .fixtures import LOGS_SEED, OTHER_LOGS_SEED

AWEB_ROOT = Path(__file__).resolve().parents[3]
VECTOR_PATH = AWEB_ROOT / "docs" / "vectors" / "logs-chain-v1.json"

SCHEME = {
    "authority": "docs/logs-chain.md",
    "encoding": "strict canonical JSON under the hook event rules; digests are 64 lowercase hex; times are UTC to the millisecond; signatures are 86 characters of standard base64, no padding; byte strings in this file are unpadded base64url",
    "genesis": "SHA-256 of 'aweb.logs-genesis/1\\n' and the canonical genesis; every epoch after the first carries previous_checkpoint_sha256",
    "commitment": "SHA-256 of 'aweb.logs-commit/1\\n', the 32-byte salt, the envelope signing bytes and the raw 64-byte signature",
    "event_hash": "SHA-256 of 'aweb.logs-chain/1\\n' and the canonical link {chain_epoch, team_id, team_seq, prev_event_hash, received_at, hook, producer_origin, content_commitment}",
    "artefacts": "aweb.logs-receipt/1 and aweb.logs-checkpoint/1: the prefix and a newline, then the canonical object, signed by the did_key it names; a verifier accepts only keys the logs manifest declares for the logs-receipt or logs-checkpoint purpose",
    "chain_cases": "each case's events are stored rows in storage order; receipt_keys and checkpoint_keys are the keys the verifier knows; report is what verify must return",
}


def b64(data: bytes) -> str:
    return encode_base64url(data)


def unb64(text: str) -> bytes:
    return decode_base64url(text, "vector bytes")


def _artefact_json(signing: bytes, signature: str) -> dict[str, str]:
    return {"signing_bytes_b64url": b64(signing), "signature": signature}


def _event_json(event: StoredEvent) -> dict[str, Any]:
    stored: dict[str, Any] = {"link": event.link.fields(), "event_hash": event.event_hash}
    if event.content is not None:
        stored["content"] = {
            "salt_b64url": b64(event.content.salt),
            "signing_bytes_b64url": b64(event.content.signing_bytes),
            "signature": event.content.signature,
            "producer_did_key": event.content.producer_did_key,
        }
    if event.purge_act is not None:
        stored["purge_act"] = event.purge_act
    return stored


def _case_json(case: ChainCase) -> dict[str, Any]:
    return {
        "name": case.name,
        "genesis": case.genesis.fields(),
        "genesis_hash": case.genesis.hash(),
        "receipt_keys": list(case.receipt_keys),
        "checkpoint_keys": list(case.checkpoint_keys),
        "events": [_event_json(event) for event in case.events],
        "receipts": [_artefact_json(*artefact) for artefact in case.receipts],
        "checkpoints": [_artefact_json(*artefact) for artefact in case.checkpoints],
        "report": case.report,
    }


def _commitment_cases() -> list[dict[str, Any]]:
    entries = []
    for index in range(3):
        stored = content(index)
        entries.append(
            {
                "salt_b64url": b64(stored.salt),
                "signing_bytes_b64url": b64(stored.signing_bytes),
                "signature": stored.signature,
                "content_commitment": content_commitment(
                    stored.salt, stored.signing_bytes, stored.signature
                ),
            }
        )
    return entries


def _signed_raw(prefix: bytes, body: bytes, key_seed: bytes = LOGS_SEED) -> dict[str, str]:
    signing = prefix + body
    return _artefact_json(signing, encode_signature(SigningKey(key_seed).sign(signing).signature))


def _artefact_cases() -> dict[str, list[dict[str, Any]]]:
    chain = cases()[0]
    first = chain.events[0]
    receipt_signing, receipt_signature = receipt(first, "0192f0c4-6f1e-7c3a-9a51-3d2b8e0f4c11")
    checkpoint_signing, checkpoint_signature = make_checkpoint(1, 3, chain.events[-1].event_hash)
    receipt_fields = json.loads(receipt_signing[len(RECEIPT_PREFIX) :])
    checkpoint_fields = json.loads(checkpoint_signing[len(CHECKPOINT_PREFIX) :])

    def receipt_with(**changes: Any) -> bytes:
        return canonical({**receipt_fields, **changes})

    positive = [
        {"name": "receipt", "artefact": "receipt", "fields": receipt_fields}
        | _artefact_json(receipt_signing, receipt_signature),
        {"name": "checkpoint", "artefact": "checkpoint", "fields": checkpoint_fields}
        | _artefact_json(checkpoint_signing, checkpoint_signature),
    ]
    other = SigningKey(OTHER_LOGS_SEED)
    negative = [
        {"name": "checkpoint_bytes_as_a_receipt", "artefact": "receipt", "error": "wrong_prefix"}
        | _artefact_json(checkpoint_signing, checkpoint_signature),
        {"name": "receipt_bytes_as_a_checkpoint", "artefact": "checkpoint", "error": "wrong_prefix"}
        | _artefact_json(receipt_signing, receipt_signature),
        {"name": "signed_by_another_key", "artefact": "receipt", "error": "bad_signature"}
        | _artefact_json(receipt_signing, encode_signature(other.sign(receipt_signing).signature)),
        {"name": "altered_after_signing", "artefact": "receipt", "error": "bad_signature"}
        | _artefact_json(RECEIPT_PREFIX + receipt_with(team_seq=2), receipt_signature),
        {"name": "padded_signature", "artefact": "receipt", "error": "signature_encoding"}
        | _artefact_json(receipt_signing, receipt_signature + "=="),
        {"name": "not_canonical", "artefact": "receipt", "error": "not_canonical"}
        | _signed_raw(RECEIPT_PREFIX, b" " + receipt_with()),
        {"name": "unknown_field", "artefact": "receipt", "error": "unknown_field"}
        | _signed_raw(RECEIPT_PREFIX, receipt_with(note="x")),
        {"name": "missing_field", "artefact": "receipt", "error": "missing_field"}
        | _signed_raw(
            RECEIPT_PREFIX,
            canonical({k: v for k, v in receipt_fields.items() if k != "event_id"}),
        ),
        {"name": "receipt_for_sequence_zero", "artefact": "receipt", "error": "invalid_value"}
        | _signed_raw(RECEIPT_PREFIX, receipt_with(team_seq=0)),
        {"name": "time_in_seconds", "artefact": "receipt", "error": "invalid_value"}
        | _signed_raw(RECEIPT_PREFIX, receipt_with(received_at="2026-10-20T12:00:01Z")),
        {"name": "wrong_type", "artefact": "receipt", "error": "invalid_value"}
        | _signed_raw(RECEIPT_PREFIX, receipt_with(type="aweb.logs-checkpoint")),
        {"name": "float", "artefact": "receipt", "error": "float_value"}
        | _signed_raw(RECEIPT_PREFIX, receipt_with().replace(b'"team_seq":1', b'"team_seq":1.0')),
        {
            "name": "checkpoint_with_uppercase_digest",
            "artefact": "checkpoint",
            "error": "invalid_value",
        }
        | _signed_raw(
            CHECKPOINT_PREFIX,
            canonical({**checkpoint_fields, "event_hash": checkpoint_fields["event_hash"].upper()}),
        ),
    ]
    return {"positive": positive, "negative": negative}


def build_vector() -> dict[str, Any]:
    first_epoch = cases()[0].genesis
    return {
        "name": "logs-chain-v1",
        "status": "proposed (aweb-acgh.16.21); frozen once reviewed",
        "scheme": SCHEME,
        "logs_key": {"kid": "logs-2026-10", "did_key": LOGS_DID},
        "genesis_cases": [
            {"genesis": first_epoch.fields(), "genesis_hash": first_epoch.hash()},
            {
                "genesis": cases()[2].genesis.fields(),
                "genesis_hash": cases()[2].genesis.hash(),
            },
        ],
        "commitment_cases": _commitment_cases(),
        "artefact_cases": _artefact_cases(),
        "chain_cases": [_case_json(case) for case in cases()],
    }


def render(vector: dict[str, Any]) -> bytes:
    return (json.dumps(vector, indent=2, sort_keys=True) + "\n").encode("ascii")


def read_chain_case(entry: dict[str, Any]) -> ChainCase:
    """A chain case as the file states it."""
    events = []
    for stored in entry["events"]:
        stored_content = stored.get("content")
        events.append(
            StoredEvent(
                link=Link(**stored["link"]),
                event_hash=stored["event_hash"],
                content=None
                if stored_content is None
                else Content(
                    salt=unb64(stored_content["salt_b64url"]),
                    signing_bytes=unb64(stored_content["signing_bytes_b64url"]),
                    signature=stored_content["signature"],
                    producer_did_key=stored_content["producer_did_key"],
                ),
                purge_act=stored.get("purge_act"),
            )
        )
    return ChainCase(
        name=entry["name"],
        genesis=Genesis(**entry["genesis"]),
        events=events,
        report=entry["report"],
        receipts=[(unb64(a["signing_bytes_b64url"]), a["signature"]) for a in entry["receipts"]],
        checkpoints=[
            (unb64(a["signing_bytes_b64url"]), a["signature"]) for a in entry["checkpoints"]
        ],
        receipt_keys=tuple(entry["receipt_keys"]),
        checkpoint_keys=tuple(entry["checkpoint_keys"]),
    )
