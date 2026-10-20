from __future__ import annotations

import dataclasses
import hashlib
from typing import Any

import pytest
from aweb_naapp.hooks import envelope as hook_envelope
from aweb_naapp.hooks.strictjson import Refused, encode_signature
from nacl.signing import SigningKey

from aweb_logs.chain import (
    Checkpoint,
    Genesis,
    Link,
    Receipt,
    artefact_sha256,
    content_commitment,
    link_for,
    open_checkpoint,
    open_receipt,
    sign_checkpoint,
    sign_receipt,
)

from .fixtures import (
    LOGS_KID,
    LOGS_ORIGIN,
    LOGS_SEED,
    OTHER_LOGS_SEED,
    TEAM_ID,
    did_key,
    signed_event,
)

SALT = bytes(range(32))
RECEIVED_AT = "2026-10-20T12:00:03.100Z"


def _genesis(**changes: Any) -> Genesis:
    genesis = Genesis(
        team_id=TEAM_ID,
        chain_epoch=1,
        logs_origin=LOGS_ORIGIN,
        created_at="2026-10-20T11:00:00.000Z",
    )
    return dataclasses.replace(genesis, **changes)


def _receipt(**changes: Any) -> Receipt:
    receipt = Receipt(
        team_id=TEAM_ID,
        event_id="0192f0c4-6f1e-7c3a-9a51-3d2b8e0f4c11",
        chain_epoch=1,
        team_seq=1,
        event_hash="ab" * 32,
        received_at=RECEIVED_AT,
        logs_origin=LOGS_ORIGIN,
        kid=LOGS_KID,
        did_key=did_key(LOGS_SEED),
    )
    return dataclasses.replace(receipt, **changes)


def _checkpoint(**changes: Any) -> Checkpoint:
    checkpoint = Checkpoint(
        team_id=TEAM_ID,
        chain_epoch=1,
        team_seq=3,
        event_hash="cd" * 32,
        issued_at="2026-10-20T12:05:00.000Z",
        logs_origin=LOGS_ORIGIN,
        kid=LOGS_KID,
        did_key=did_key(LOGS_SEED),
    )
    return dataclasses.replace(checkpoint, **changes)


def test_the_first_epoch_has_no_previous_checkpoint() -> None:
    with pytest.raises(Refused) as caught:
        _genesis(previous_checkpoint_sha256="00" * 32).hash()
    assert caught.value.code == "invalid_value"


def test_a_later_epoch_records_the_previous_epochs_final_checkpoint() -> None:
    with pytest.raises(Refused) as caught:
        _genesis(chain_epoch=2).hash()
    assert caught.value.code == "missing_field"
    first = _genesis(chain_epoch=2, previous_checkpoint_sha256="00" * 32).hash()
    other = _genesis(chain_epoch=2, previous_checkpoint_sha256="11" * 32).hash()
    assert first != other


@pytest.mark.parametrize(
    "changes",
    [
        {"team_id": "other:example.com"},
        {"chain_epoch": 2, "previous_checkpoint_sha256": "00" * 32},
        {"logs_origin": "https://logs.other.example"},
        {"created_at": "2026-10-20T11:00:00.001Z"},
    ],
)
def test_the_genesis_hash_binds_every_field(changes: dict[str, Any]) -> None:
    assert _genesis(**changes).hash() != _genesis().hash()


def test_a_time_has_one_spelling() -> None:
    with pytest.raises(Refused):
        _genesis(created_at="2026-10-20T11:00:00Z").hash()
    with pytest.raises(Refused):
        _genesis(created_at="2026-10-20T11:00:00.000000Z").hash()


def test_the_commitment_binds_salt_content_and_signature() -> None:
    signing, signature = signed_event("core")
    other_signing, other_signature = signed_event("core", seq=2)
    commitment = content_commitment(SALT, signing, signature)
    assert commitment != content_commitment(bytes(32), signing, signature)
    assert commitment != content_commitment(SALT, other_signing, signature)
    assert commitment != content_commitment(SALT, signing, other_signature)


def test_the_salt_is_32_bytes() -> None:
    signing, signature = signed_event("core")
    with pytest.raises(Refused):
        content_commitment(bytes(31), signing, signature)


@pytest.mark.parametrize(
    ("kind", "producer_origin"),
    [
        ("core", "https://aweb.example.com"),
        ("app", "https://secrets.example.com"),
        ("client", "client:c_41"),
    ],
)
def test_the_link_names_the_producer_by_origin_or_certificate(
    kind: str, producer_origin: str
) -> None:
    signing, signature = signed_event(kind)
    event = hook_envelope.verify(signing, signature, team_id=TEAM_ID)
    link = link_for(
        event,
        chain_epoch=1,
        team_seq=1,
        prev_event_hash=_genesis().hash(),
        received_at=RECEIVED_AT,
        content_commitment=content_commitment(SALT, signing, signature),
    )
    assert link.producer_origin == producer_origin
    assert link.hook == event.hook


def _link() -> Link:
    return Link(
        chain_epoch=1,
        team_id=TEAM_ID,
        team_seq=1,
        prev_event_hash="00" * 32,
        received_at=RECEIVED_AT,
        hook="post-mutation-hook",
        producer_origin="https://aweb.example.com",
        content_commitment="11" * 32,
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"chain_epoch": 2},
        {"team_id": "other:example.com"},
        {"team_seq": 2},
        {"prev_event_hash": "22" * 32},
        {"received_at": "2026-10-20T12:00:03.101Z"},
        {"hook": "post-command-hook"},
        {"producer_origin": "client:c_41"},
        {"content_commitment": "33" * 32},
    ],
)
def test_the_event_hash_binds_every_link_field(changes: dict[str, Any]) -> None:
    assert dataclasses.replace(_link(), **changes).event_hash() != _link().event_hash()


def test_a_link_refuses_a_malformed_digest() -> None:
    with pytest.raises(Refused):
        dataclasses.replace(_link(), prev_event_hash="AB" * 32).event_hash()


def test_a_receipt_opens_to_what_logs_signed() -> None:
    receipt = _receipt()
    signing, signature = sign_receipt(SigningKey(LOGS_SEED), receipt)
    assert signing.startswith(b"aweb.logs-receipt/1\n")
    assert open_receipt(signing, signature) == receipt


def test_logs_signs_only_with_the_key_the_artefact_names() -> None:
    with pytest.raises(Refused) as caught:
        sign_receipt(SigningKey(OTHER_LOGS_SEED), _receipt())
    assert caught.value.code == "signer_mismatch"


def test_a_receipt_signed_by_another_key_is_refused() -> None:
    signing, _ = sign_receipt(SigningKey(LOGS_SEED), _receipt())
    forged = SigningKey(OTHER_LOGS_SEED).sign(signing).signature
    with pytest.raises(Refused) as caught:
        open_receipt(signing, encode_signature(forged))
    assert caught.value.code == "bad_signature"


def test_a_tampered_receipt_is_refused() -> None:
    signing, signature = sign_receipt(SigningKey(LOGS_SEED), _receipt())
    tampered = signing.replace(b'"team_seq":1', b'"team_seq":2')
    with pytest.raises(Refused) as caught:
        open_receipt(tampered, signature)
    assert caught.value.code == "bad_signature"


def test_a_checkpoint_is_never_a_receipt_and_back() -> None:
    receipt_signing, receipt_signature = sign_receipt(SigningKey(LOGS_SEED), _receipt())
    checkpoint_signing, checkpoint_signature = sign_checkpoint(SigningKey(LOGS_SEED), _checkpoint())
    with pytest.raises(Refused) as caught:
        open_receipt(checkpoint_signing, checkpoint_signature)
    assert caught.value.code == "wrong_prefix"
    with pytest.raises(Refused) as caught:
        open_checkpoint(receipt_signing, receipt_signature)
    assert caught.value.code == "wrong_prefix"


def test_receipt_bytes_must_be_canonical_and_known() -> None:
    signing, _ = sign_receipt(SigningKey(LOGS_SEED), _receipt())
    spaced = signing.replace(b'{"chain_epoch"', b'{ "chain_epoch"')
    key = SigningKey(LOGS_SEED)
    with pytest.raises(Refused) as caught:
        open_receipt(spaced, encode_signature(key.sign(spaced).signature))
    assert caught.value.code == "not_canonical"
    extra = signing.replace(b'{"chain_epoch"', b'{"a":1,"chain_epoch"')
    with pytest.raises(Refused) as caught:
        open_receipt(extra, encode_signature(key.sign(extra).signature))
    assert caught.value.code == "unknown_field"


def test_a_checkpoint_links_to_the_previous_one() -> None:
    first_signing, signature = sign_checkpoint(SigningKey(LOGS_SEED), _checkpoint(team_seq=0))
    assert open_checkpoint(first_signing, signature).previous_checkpoint_sha256 is None
    second = _checkpoint(previous_checkpoint_sha256=artefact_sha256(first_signing))
    signing, signature = sign_checkpoint(SigningKey(LOGS_SEED), second)
    opened = open_checkpoint(signing, signature)
    assert opened.previous_checkpoint_sha256 == hashlib.sha256(first_signing).hexdigest()


def test_only_an_empty_epoch_checkpoints_sequence_zero() -> None:
    sign_checkpoint(SigningKey(LOGS_SEED), _checkpoint(team_seq=0))
    with pytest.raises(Refused):
        sign_checkpoint(SigningKey(LOGS_SEED), _checkpoint(team_seq=-1))
    with pytest.raises(Refused):
        sign_receipt(SigningKey(LOGS_SEED), _receipt(team_seq=0))
