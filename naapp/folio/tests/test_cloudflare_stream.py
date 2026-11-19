from __future__ import annotations

import pytest
from fastapi import HTTPException

from folio import cloudflare_stream
from folio.cloudflare_stream import (
    sign_stream_playback_token,
    stream_iframe_url,
    video_status_from_cloudflare,
)
from folio.config import Settings
from folio.models import StreamStatus

# Cloudflare Stream's documented video states (result.status.state), from
# https://developers.cloudflare.com/api/resources/stream/methods/get/ (read 2026-11-19).
DOCUMENTED_STATES = {
    "pendingupload": StreamStatus.PENDING_UPLOAD,
    "downloading": StreamStatus.QUEUED,
    "queued": StreamStatus.QUEUED,
    "inprogress": StreamStatus.PROCESSING,
    "live-inprogress": StreamStatus.PROCESSING,
    "ready": StreamStatus.READY,
    "error": StreamStatus.ERROR,
}


def _status(status: dict | None, *, ready_to_stream: bool = False) -> object:
    result: dict = {"uid": "stream-uid", "readyToStream": ready_to_stream}
    if status is not None:
        result["status"] = status
    return video_status_from_cloudflare(result)


def test_stream_iframe_url_requires_signing_config() -> None:
    with pytest.raises(HTTPException) as raised:
        stream_iframe_url(settings=Settings(), stream_uid="uid123")

    assert raised.value.status_code == 503


def test_stream_playback_token_is_signed_for_stream_uid() -> None:
    cryptography = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.rsa")
    serialization = pytest.importorskip("cryptography.hazmat.primitives.serialization")
    jwt = pytest.importorskip("jwt")

    private_key = cryptography.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    public_key = private_key.public_key()
    settings = Settings(
        cloudflare_stream_signing_key_id="key-1",
        cloudflare_stream_signing_key_pem=private_pem,
        cloudflare_stream_playback_host="customer-example.cloudflarestream.com",
        cloudflare_stream_signed_playback_ttl_seconds=600,
    )

    token = sign_stream_playback_token(settings=settings, stream_uid="stream-uid")
    decoded = jwt.decode(token, public_key, algorithms=["RS256"])

    assert decoded["sub"] == "stream-uid"
    assert decoded["kid"] == "key-1"
    assert stream_iframe_url(settings=settings, stream_uid="stream-uid").startswith(
        "https://customer-example.cloudflarestream.com/"
    )


@pytest.mark.parametrize(("state", "expected"), DOCUMENTED_STATES.items())
def test_every_documented_cloudflare_state_is_a_stream_status(state, expected) -> None:
    assert _status({"state": state}) == expected


def test_a_playable_video_is_ready_before_cloudflare_finishes_every_quality() -> None:
    assert _status({"state": "inprogress"}, ready_to_stream=True) == StreamStatus.READY


@pytest.mark.parametrize("status", [{"state": "melting"}, {"state": ""}, {}, None])
def test_an_unrecognized_or_missing_state_is_refused_naming_it(status) -> None:
    with pytest.raises(cloudflare_stream.UnrecognizedStreamState) as refused:
        _status(status)
    assert refused.value.state == (status or {}).get("state")
