from __future__ import annotations

import base64
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from folio.repository import _decode_logo

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


def test_decode_logo_accepts_safe_raster_with_matching_magic_bytes() -> None:
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
def test_decode_logo_rejects_svg_parameterized_and_non_image_content_types(content_type: str) -> None:
    with pytest.raises(HTTPException) as raised:
        _decode_logo(_logo(content_type, _SVG_WITH_SCRIPT))

    assert raised.value.status_code == 400


def test_decode_logo_rejects_declared_type_magic_byte_mismatch() -> None:
    with pytest.raises(HTTPException) as raised:
        _decode_logo(_logo("image/png", _SVG_WITH_SCRIPT))

    assert raised.value.status_code == 400
    assert raised.value.detail == "Logo bytes must match content_type"
