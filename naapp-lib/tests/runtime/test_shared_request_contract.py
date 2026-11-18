"""Naapp authentication must consume awid's request contract, using real signatures."""

import base64
import hashlib

import pytest
from awid.did import did_key_from_signing_key
from awid.signing import canonical_json_bytes, sign_message
from fastapi import HTTPException
from nacl.signing import SigningKey
from starlette.requests import Request

from aweb_naapp.runtime.team_auth import _verified_signed_payload


@pytest.mark.parametrize("purpose", [None, "aweb.awid-controller-request"])
def test_team_request_and_controller_request_are_distinct(purpose):
    key = bytes(SigningKey.generate())
    timestamp = "2026-11-18T12:00:00Z"
    payload = {
        "v": 2,
        "aud": "https://app.example.com",
        "method": "GET",
        "path": "/v1/items",
        "team_id": "team:example.com",
        "timestamp": timestamp,
        "body_sha256": hashlib.sha256(b"").hexdigest(),
    }
    if purpose is not None:
        payload["type"] = purpose
    raw = canonical_json_bytes(payload)
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/v1/items",
            "raw_path": b"/v1/items",
            "query_string": b"",
            "headers": [(b"x-aweb-signed-payload", base64.urlsafe_b64encode(raw).rstrip(b"="))],
        }
    )

    def verify():
        return _verified_signed_payload(
            request,
            public_origin="https://app.example.com",
            did_key=did_key_from_signing_key(key),
            signature=sign_message(key, raw),
            header_timestamp=timestamp,
            team_id="team:example.com",
            body=b"",
        )

    if purpose is None:
        assert verify() == payload
    else:
        with pytest.raises(HTTPException) as refusal:
            verify()
        assert refusal.value.status_code == 401
        assert (
            refusal.value.detail
            == "Wrong request envelope type: sign a team-auth v2 request for this service instead of an AWID controller request."
        )


@pytest.mark.parametrize(
    "root,wire,expected",
    [
        ("/api", b"/api/v1/items", "/api/v1/items?q=%2F"),
        ("/api", b"/api2/items", "/api/api2/items?q=%2F"),
        ("/api", b"/v1/items", "/api/v1/items?q=%2F"),
        ("/caf\u00e9", b"/caf%C3%A9/v1/items", "/caf%C3%A9/v1/items?q=%2F"),
    ],
)
def test_raw_target_uses_external_encoded_mount_segments(root, wire, expected):
    from awid.controller_request import raw_controller_request_target
    from awid.request_auth import raw_request_target

    from aweb_naapp.runtime.team_auth import raw_request_target as naapp_target

    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/v1/items",
            "raw_path": wire,
            "root_path": root,
            "query_string": b"q=%2F",
            "headers": [],
        }
    )
    assert raw_request_target(request) == expected
    assert raw_controller_request_target(request) == expected
    assert naapp_target(request) == expected
