from __future__ import annotations

import pytest
from fastapi import HTTPException

from folio.cloudflare_stream import sign_stream_playback_token, stream_iframe_url
from folio.config import Settings


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
