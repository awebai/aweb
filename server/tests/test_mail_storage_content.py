"""Accepted request metadata does not change mail's persisted content shape."""

import pytest

from aweb.message_events import MailSentContext
from aweb.messaging.kinds import ContentMode, MessagePriority
from aweb.messaging.mail_models import SendMessageRequest
from aweb.messaging.mail_storage import (
    EncryptedMailContent,
    PlaintextMailContent,
    mail_content_for_storage,
)


@pytest.mark.parametrize(
    "mode", [None, "", " opaque plaintext ", ContentMode.PLAINTEXT]
)
def test_accepted_plaintext_keeps_content_and_original_callback_mode(mode):
    request = SendMessageRequest(
        to_alias="recipient",
        content_mode=mode,
        subject="subject",
        body="body",
        signed_payload='{"content_mode":" opaque plaintext "}',
        signature="signature",
    )
    stored = mail_content_for_storage(
        request, encrypted_metadata={"signed_envelope_hash": "ignored"}
    )
    assert isinstance(stored, PlaintextMailContent)
    assert (stored.subject, stored.body, stored.mode, stored.version) == (
        "subject",
        "body",
        ContentMode.PLAINTEXT,
        1,
    )
    assert stored.envelope is None and stored.metadata == {}
    context = MailSentContext(
        team_id=None,
        from_agent_id=None,
        from_did="did:key:sender",
        from_did_aw=None,
        to_agent_id=None,
        from_alias="sender",
        message_id="message",
        conversation_id=None,
        to_alias="recipient",
        subject=request.subject,
        priority=request.priority,
        content_mode=request.content_mode,
    )
    assert context.to_context()["content_mode"] == (
        "legacy_plaintext_v1" if mode is None or mode == "" else str(mode)
    )


def test_encrypted_request_stores_only_envelope_and_ciphertext_metadata():
    envelope = {"ciphertext": "ciphertext"}
    request = SendMessageRequest(
        to_alias="recipient",
        content_mode=ContentMode.ENCRYPTED,
        message_version=2,
        encrypted_envelope=envelope,
        priority=MessagePriority.URGENT,
    )
    metadata = {
        "encrypted_ciphertext": "ciphertext",
        "signed_envelope_hash": "sha256:envelope",
    }
    stored = mail_content_for_storage(request, encrypted_metadata=metadata)
    assert isinstance(stored, EncryptedMailContent)
    assert (stored.subject, stored.body, stored.mode, stored.version) == (
        "",
        "",
        ContentMode.ENCRYPTED,
        2,
    )
    assert stored.envelope == {"ciphertext": "ciphertext"}
    assert stored.metadata == {
        "encrypted_ciphertext": "ciphertext",
        "signed_envelope_hash": "sha256:envelope",
    }
