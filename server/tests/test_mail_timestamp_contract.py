"""Moved age refusals retain a stable code and a useful next action."""

from datetime import datetime, timedelta, timezone

import pytest
from aweb.messaging.refusals import DeliveryRefusal
from aweb.messaging.mail_send import _parse_signed_timestamp


@pytest.mark.parametrize(
    "timestamp", ["not-a-time", "2026-01-01T00:00:00", "2026-01-01T00:00:00.123Z"]
)
def test_mail_timestamp_shape_refusal_ends_with_a_signing_action(timestamp):
    with pytest.raises(DeliveryRefusal) as caught:
        _parse_signed_timestamp(timestamp)
    assert caught.value.status_code == 422
    assert caught.value.detail.endswith(
        "Sign the message again with the current UTC time and retry."
    )


def test_mail_age_refusal_has_an_additive_code_and_signing_action():
    timestamp = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(
        seconds=301
    )
    with pytest.raises(DeliveryRefusal) as caught:
        _parse_signed_timestamp(timestamp.isoformat())
    assert caught.value.status_code == 422
    assert caught.value.headers == {
        "X-AWEB-Error-Code": "message_timestamp_outside_skew"
    }
    assert caught.value.detail.endswith(
        "Sign the message again with the current UTC time and retry."
    )


def test_fresh_mail_attestation_still_passes():
    timestamp = datetime.now(timezone.utc).replace(microsecond=0)
    assert _parse_signed_timestamp(timestamp.isoformat()) == timestamp


@pytest.mark.parametrize("offset", [-301, 301])
def test_chat_age_refusal_ends_with_the_same_signing_action(offset):
    from aweb.messaging.chat_send import _parse_signed_timestamp as parse_chat_timestamp

    timestamp = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(
        seconds=offset
    )
    with pytest.raises(DeliveryRefusal) as caught:
        parse_chat_timestamp(timestamp.isoformat())
    assert caught.value.status_code == 422
    assert caught.value.detail == (
        "timestamp outside accepted skew. Sign the message again with the current UTC time and retry."
    )
