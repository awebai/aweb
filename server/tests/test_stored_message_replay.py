"""The shared stored-artifact comparison, independent of transport admission.

These are pure component inputs, not database or encrypted-sender validation.
"""

import json
from dataclasses import replace
from uuid import UUID

import pytest

from awid.did import generate_keypair
from awid.signing import canonical_json_bytes, sign_message
from aweb.messaging.kinds import MessageKind
from aweb.messaging.message_replay import (
    ChatReplayControls,
    EncryptedReplayArtifact,
    PlaintextReplayArtifact,
    StoredMessageClaim,
    StoredMessageState,
    read_stored_message,
)
from aweb.service_errors import ConflictError
from aweb.messaging.mail_storage import MailIdAvailability

MESSAGE_ID = UUID("00000000-0000-0000-0000-000000000001")
CONVERSATION_ID = UUID("00000000-0000-0000-0000-000000000002")
OTHER_CONVERSATION = UUID("00000000-0000-0000-0000-000000000003")


class StoredArtifactReader:
    def __init__(self, row):
        self.row = row

    def get_manager(self, name):
        assert name == "aweb"
        return self

    async def fetch_one(self, query, message_id):
        assert message_id == MESSAGE_ID
        return self.row


def signed_artifact(kind):
    key, _ = generate_keypair()
    payload = canonical_json_bytes({"type": kind.value, "body": "accepted body"}).decode()
    signature = sign_message(key, payload.encode())
    claim = StoredMessageClaim(
        kind=kind,
        message_id=MESSAGE_ID,
        sender_did="did:key:accepted-sender",
        conversation_id=CONVERSATION_ID,
        artifact=PlaintextReplayArtifact(signature=signature, signed_payload=payload),
    )
    row = dict(
        message_id=MESSAGE_ID,
        conversation_id=CONVERSATION_ID,
        session_id=CONVERSATION_ID,
        from_did="did:key:accepted-sender",
        content_mode="legacy_plaintext_v1",
        signature=signature,
        signed_payload=payload,
    )
    return claim, row


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", [MessageKind.MAIL, MessageKind.CHAT])
async def test_signed_retry_uses_one_exact_artifact_rule_for_mail_and_chat(kind):
    claim, row = signed_artifact(kind)
    exact = await read_stored_message(StoredArtifactReader(row), claim=claim)
    assert exact.state is StoredMessageState.EXACT
    assert exact.message["message_id"] == MESSAGE_ID
    absent = await read_stored_message(StoredArtifactReader(None), claim=claim)
    assert absent.state is StoredMessageState.MISSING


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", [MessageKind.MAIL, MessageKind.CHAT])
@pytest.mark.parametrize(
    "row_change",
    [
        {"from_did": "did:key:another-sender"},
        {"conversation_id": OTHER_CONVERSATION, "session_id": OTHER_CONVERSATION},
        {"signed_payload": '{"body":"different signed bytes"}'},
        {"signature": "different signature bytes"},
        {"content_mode": "encrypted_v2"},
    ],
)
async def test_changed_sender_conversation_or_proof_never_acknowledges_a_retry(kind, row_change):
    claim, row = signed_artifact(kind)
    result = await read_stored_message(StoredArtifactReader({**row, **row_change}), claim=claim)
    assert result.state is StoredMessageState.CONFLICT
    assert result.message is None
    with pytest.raises(ConflictError) as refused:
        result.refuse_conflicting_message_id()
    assert refused.value.detail == (
        "message_id already exists for a different signed message. Retry the original request unchanged; choose a new message_id only if you intend to send a different message."
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", [MessageKind.MAIL, MessageKind.CHAT])
async def test_unsigned_id_reuse_is_not_a_stored_signed_proof(kind):
    claim, row = signed_artifact(kind)
    claim = replace(claim, artifact=PlaintextReplayArtifact(signature=None, signed_payload=None))
    row.update(signature=None, signed_payload=None)
    result = await read_stored_message(StoredArtifactReader(row), claim=claim)
    assert result.state is StoredMessageState.CONFLICT


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", [MessageKind.MAIL, MessageKind.CHAT])
async def test_encrypted_retry_compares_the_complete_stored_envelope_and_sender(kind):
    envelope = {
        "type": kind.value,
        "message_id": str(MESSAGE_ID),
        "ciphertext": "accepted opaque bytes",
        "signature": "accepted proof",
    }
    claim = StoredMessageClaim(
        kind=kind,
        message_id=MESSAGE_ID,
        sender_did="did:key:accepted-sender",
        conversation_id=CONVERSATION_ID,
        artifact=EncryptedReplayArtifact(envelope=envelope),
    )
    row = dict(
        message_id=MESSAGE_ID,
        conversation_id=CONVERSATION_ID,
        session_id=CONVERSATION_ID,
        from_did="did:key:accepted-sender",
        content_mode="encrypted_v2",
        encrypted_envelope=json.dumps(envelope),
    )
    exact = await read_stored_message(StoredArtifactReader(row), claim=claim)
    assert exact.state is StoredMessageState.EXACT
    changed = await read_stored_message(
        StoredArtifactReader(
            {
                **row,
                "encrypted_envelope": json.dumps({**envelope, "ciphertext": "changed bytes"}),
            }
        ),
        claim=claim,
    )
    assert changed.state is StoredMessageState.CONFLICT
    another_sender = await read_stored_message(
        StoredArtifactReader({**row, "from_did": "did:key:another-sender"}),
        claim=claim,
    )
    assert another_sender.state is StoredMessageState.CONFLICT


class LookupTrap:
    def get_manager(self, name):
        raise AssertionError("unnamed claim reached a database read")


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", [True, "mail", None])
async def test_unnamed_message_kind_is_refused_before_the_stored_read(kind):
    claim, _ = signed_artifact(MessageKind.MAIL)
    with pytest.raises(TypeError) as refused:
        await read_stored_message(LookupTrap(), claim=replace(claim, kind=kind))
    assert str(refused.value) == "Select a named MessageKind before reading a stored message."


@pytest.mark.parametrize("kind", [MessageKind.MAIL, MessageKind.CHAT])
def test_established_receipt_uses_the_same_identity_rule_before_age_and_commit(kind):
    from aweb.messaging.message_replay import established_federation_receipt

    row = dict(
        envelope_hash="sha256:accepted",
        storage_kind=kind.value,
        legacy_unreplayable=False,
        canonical_metadata=json.dumps({"kind": kind.value, "sender_address": "example.test/alice"}),
        established_result=json.dumps({"message_id": str(MESSAGE_ID), "status": "delivered"}),
    )
    accepted = established_federation_receipt(row, envelope_hash="sha256:accepted", kind=kind)
    assert accepted.metadata["sender_address"] == "example.test/alice"
    assert accepted.result == {
        "message_id": "00000000-0000-0000-0000-000000000001",
        "status": "delivered",
    }
    assert established_federation_receipt(None, envelope_hash="sha256:accepted", kind=kind) is None


@pytest.mark.parametrize(
    "row_change",
    [
        {"envelope_hash": "sha256:changed"},
        {"storage_kind": "another-kind"},
        {"legacy_unreplayable": True},
        {"established_result": None},
        {"established_result": "[]"},
        {"canonical_metadata": "[]"},
    ],
)
def test_legacy_partial_or_changed_receipts_never_supply_an_age_exemption(row_change):
    from awid.federation_errors import FederationAuthorityError
    from aweb.messaging.message_replay import established_federation_receipt

    row = dict(
        envelope_hash="sha256:accepted",
        storage_kind="mail",
        legacy_unreplayable=False,
        canonical_metadata={"kind": "mail"},
        established_result={"status": "delivered"},
    )
    with pytest.raises(FederationAuthorityError) as refused:
        established_federation_receipt(
            {**row, **row_change},
            envelope_hash="sha256:accepted",
            kind=MessageKind.MAIL,
        )
    assert refused.value.reason == "federation_message_replay_conflict"


@pytest.mark.asyncio
@pytest.mark.parametrize("availability", [True, False, "confirmed-unused", None])
async def test_unnamed_mail_id_availability_cannot_select_a_storage_path(availability):
    from aweb.messaging.mail_storage import (
        MailAttestation,
        MailRecipient,
        MailSender,
        MailStorageInput,
        PlaintextMailContent,
        store_mail,
    )

    message = MailStorageInput(
        sender=MailSender(did="did:key:accepted-sender"),
        recipient=MailRecipient(did="did:key:accepted-recipient"),
        content=PlaintextMailContent(subject="subject", body="body"),
        priority="normal",
        attestation=MailAttestation(),
        id_availability=availability,
    )
    with pytest.raises(TypeError) as refused:
        await store_mail(LookupTrap(), message=message)
    assert str(refused.value) == "Choose a named MailIdAvailability before storing mail."


@pytest.mark.asyncio
@pytest.mark.parametrize("availability", list(MailIdAvailability))
async def test_named_mail_id_availability_reaches_the_canonical_writer(availability):
    from aweb.messaging.mail_storage import (
        MailAttestation,
        MailRecipient,
        MailSender,
        MailStorageInput,
        PlaintextMailContent,
        store_mail,
    )

    message = MailStorageInput(
        sender=MailSender(did="did:key:accepted-sender"),
        recipient=MailRecipient(did="did:key:accepted-recipient"),
        content=PlaintextMailContent(subject="subject", body="body"),
        priority="normal",
        attestation=MailAttestation(),
        id_availability=availability,
    )
    with pytest.raises(AssertionError, match="unnamed claim reached a database read"):
        await store_mail(LookupTrap(), message=message)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    [
        {"sender_leaving": True},
        {"hang_on": True},
        {"reply_to": OTHER_CONVERSATION},
    ],
)
async def test_changed_persisted_chat_controls_are_not_the_same_accepted_message(
    change,
):
    claim, row = signed_artifact(MessageKind.CHAT)
    claim = replace(
        claim,
        chat_controls=ChatReplayControls(
            sender_leaving=False,
            hang_on=False,
            reply_to=None,
        ),
    )
    row.update(sender_leaving=False, hang_on=False, reply_to=None)
    exact = await read_stored_message(StoredArtifactReader(row), claim=claim)
    assert exact.state is StoredMessageState.EXACT
    changed = await read_stored_message(StoredArtifactReader({**row, **change}), claim=claim)
    assert changed.state is StoredMessageState.CONFLICT


class StoredChatParties(StoredArtifactReader):
    async def fetch_all(self, query, session_id):
        assert session_id == CONVERSATION_ID
        return [
            {"did": "did:key:accepted-sender"},
            {"did": "did:key:original-recipient"},
        ]


@pytest.mark.asyncio
async def test_optional_signed_recipient_claim_cannot_move_a_stored_chat_to_other_parties():
    claim, row = signed_artifact(MessageKind.CHAT)
    claim = replace(
        claim,
        chat_participant_dids=frozenset(
            {
                "did:key:accepted-sender",
                "did:key:original-recipient",
            }
        ),
    )
    original = await read_stored_message(StoredChatParties(row), claim=claim)
    assert original.state is StoredMessageState.EXACT
    changed = await read_stored_message(
        StoredChatParties(row),
        claim=replace(
            claim,
            chat_participant_dids=frozenset(
                {
                    "did:key:accepted-sender",
                    "did:key:different-recipient",
                }
            ),
        ),
    )
    assert changed.state is StoredMessageState.PARTICIPANTS_CHANGED


def test_attachment_retry_conflict_keeps_its_code_and_explains_the_next_action():
    from aweb.attachment_service import _attachment_retry_conflict

    refused = _attachment_retry_conflict()
    assert refused.status_code == 409
    assert refused.detail == {
        "code": "attachment_conflict",
        "message": "This message ID already has a different attachment request. Retry the original request unchanged, or choose a new message ID for a new message.",
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "controls",
    [
        ChatReplayControls(
            sender_leaving=False, hang_on=False, reply_to=None, timestamp="changed-time"
        ),
        ChatReplayControls(
            sender_leaving=False,
            hang_on=False,
            reply_to=None,
            signing_did="did:key:changed-key",
        ),
    ],
)
async def test_encrypted_chat_retry_retains_its_original_attestation_fields(controls):
    claim, row = signed_artifact(MessageKind.CHAT)
    envelope = {
        "created_at": "accepted-time",
        "from": {"did": "did:key:accepted-sender"},
    }
    row.update(content_mode="encrypted_v2", encrypted_envelope=envelope)
    claim = replace(
        claim,
        artifact=EncryptedReplayArtifact(envelope=envelope),
        chat_controls=controls,
    )
    result = await read_stored_message(StoredArtifactReader(row), claim=claim)
    assert result.state is StoredMessageState.CONFLICT


@pytest.mark.asyncio
async def test_same_artifact_with_different_resolved_parties_never_advises_a_new_message_id():
    claim, row = signed_artifact(MessageKind.CHAT)
    result = await read_stored_message(
        StoredChatParties(row),
        claim=replace(
            claim,
            chat_participant_dids=frozenset({"did:key:accepted-sender", "did:aw:different-form"}),
        ),
    )
    with pytest.raises(ConflictError) as refused:
        result.refuse_conflicting_message_id()
    assert refused.value.detail == (
        "The stored chat participants differ from the resolved recipients. Retry the original conversation and recipient identities unchanged."
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "current_key,expected",
    [
        ("did:key:original-recipient", StoredMessageState.EXACT),
        ("did:key:rotated-recipient", StoredMessageState.PARTICIPANTS_CHANGED),
    ],
)
async def test_registered_party_matches_its_original_local_key_only_while_current(
    current_key, expected
):
    claim, row = signed_artifact(MessageKind.CHAT)
    claim = replace(
        claim,
        chat_participant_dids=frozenset({"did:key:accepted-sender", "did:aw:registered-recipient"}),
        chat_participant_current_keys={"did:aw:registered-recipient": current_key},
    )
    observed = await read_stored_message(StoredChatParties(row), claim=claim)
    assert observed.state is expected
    assert row["from_did"] == "did:key:accepted-sender"


@pytest.mark.asyncio
async def test_one_recorded_key_cannot_stand_in_for_two_requested_parties():
    claim, row = signed_artifact(MessageKind.CHAT)
    claim = replace(
        claim,
        chat_participant_dids=frozenset(
            {
                "did:key:accepted-sender",
                "did:aw:recipient-one",
                "did:aw:recipient-two",
            }
        ),
        chat_participant_current_keys={
            "did:aw:recipient-one": "did:key:original-recipient",
            "did:aw:recipient-two": "did:key:original-recipient",
        },
    )
    observed = await read_stored_message(StoredChatParties(row), claim=claim)
    assert observed.state is StoredMessageState.PARTICIPANTS_CHANGED
