from __future__ import annotations

import base64
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from folio.config import Settings
from folio.repository import _decode_image_asset, _decode_logo, _validate_video_request

_ONE_BY_ONE_PNG = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\rIDATx\x9cc\xf8\xff\xff?\x00\x05\xfe\x02\xfeA\xe2\x8b\x9b"
    b"\x00\x00\x00\x00IEND\xaeB`\x82"
)
_SVG_WITH_SCRIPT = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'


def _logo(content_type: str, payload: bytes) -> SimpleNamespace:
    return SimpleNamespace(
        content_type=content_type,
        data_base64=base64.b64encode(payload).decode("ascii"),
    )


def test_decode_image_asset_accepts_safe_raster_with_matching_magic_bytes() -> None:
    payload, content_type = _decode_image_asset(_logo("image/png", _ONE_BY_ONE_PNG), label="Image")

    assert payload == _ONE_BY_ONE_PNG
    assert content_type == "image/png"


def test_decode_logo_uses_same_raster_validator() -> None:
    payload, content_type = _decode_logo(_logo("image/png", _ONE_BY_ONE_PNG))

    assert payload == _ONE_BY_ONE_PNG
    assert content_type == "image/png"


@pytest.mark.parametrize(
    "content_type",
    [
        "image/svg+xml",
        "image/svg+xml; charset=utf-8",
        "image/png; charset=utf-8",
        "text/html",
    ],
)
def test_decode_image_asset_rejects_svg_parameterized_and_non_image_content_types(content_type: str) -> None:
    with pytest.raises(HTTPException) as raised:
        _decode_image_asset(_logo(content_type, _SVG_WITH_SCRIPT), label="Image")

    assert raised.value.status_code == 400


def test_validate_video_request_accepts_safe_video_types_and_caps_duration() -> None:
    content_type, duration = _validate_video_request(
        SimpleNamespace(content_type="video/mp4", max_duration_seconds=999),
        settings=Settings(cloudflare_stream_max_duration_seconds=600),
    )

    assert content_type == "video/mp4"
    assert duration == 600


@pytest.mark.parametrize("content_type", ["image/svg+xml", "text/html", "video/mp4; codecs=h264"])
def test_validate_video_request_rejects_unsafe_or_parameterized_types(content_type: str) -> None:
    with pytest.raises(HTTPException) as raised:
        _validate_video_request(
            SimpleNamespace(content_type=content_type, max_duration_seconds=60),
            settings=Settings(),
        )

    assert raised.value.status_code == 400


def test_decode_image_asset_rejects_declared_type_magic_byte_mismatch() -> None:
    with pytest.raises(HTTPException) as raised:
        _decode_image_asset(_logo("image/png", _SVG_WITH_SCRIPT), label="Image")

    assert raised.value.status_code == 400
    assert raised.value.detail == "Image bytes must match content_type"
