"""The production mail/chat validators verify the retained signed bytes."""

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from aweb.messaging.refusals import DeliveryRefusal
from nacl.signing import SigningKey

from awid.did import did_from_public_key
from awid.signing import canonical_json_bytes, sign_message
from aweb.messaging.chat_send import _validate_signed_chat_payload
from aweb.messaging.mail_send import _validate_signed_mail_payload
from aweb.messaging.verification import message_verification_status


@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("valid", [False, True])
def test_actual_send_validator_checks_signature_authorship(kind, valid):
    key, other = SigningKey.generate(), SigningKey.generate()
    did = did_from_public_key(bytes(key.verify_key))
    message_id, conversation_id = str(uuid4()), str(uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()
    fields = dict(
        type=kind,
        body="actual signed bytes",
        from_did=did,
        message_id=message_id,
        conversation_id=conversation_id,
        timestamp=timestamp,
    )
    if kind == "mail":
        fields["subject"] = ""
    signed_payload = canonical_json_bytes(fields).decode()
    signature = sign_message(bytes(key if valid else other), signed_payload.encode())
    args = dict(
        signature=signature,
        signed_payload=signed_payload,
        from_alias="alice",
        from_address=None,
        from_stable_id=None,
        body=fields["body"],
        from_did=did,
        message_id=message_id,
        timestamp=timestamp,
        conversation_id=conversation_id,
    )
    if kind == "mail":
        validate = _validate_signed_mail_payload
        args.update(
            recipient=None,
            to_agent_id=None,
            to_alias=None,
            requested_to_alias=None,
            priority="normal",
            subject="",
        )
    else:
        validate = _validate_signed_chat_payload
    if valid:
        validate(**args)
    else:
        with pytest.raises(DeliveryRefusal) as rejected:
            validate(**args)
        assert rejected.value.status_code == 422
        assert (
            rejected.value.detail
            == "The message signature does not verify. Sign the message again with the authenticated sender's key and resend it."
        )
    # Old rows can contain a signature that admission only shape-checked.
    # Reading independently verifies it instead of trusting storage success.
    assert message_verification_status({**args}) == ("verified" if valid else "failed")
