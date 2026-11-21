"""Shared producers preserve retained IDs and bind real signed HTTP requests."""

import hashlib

import pytest
from awid.did import did_key_from_signing_key
from awid.signing import VerifyResult, verify_signature
from starlette.requests import Request

from awid import request_auth, team_certificate

SEED = bytes(range(32))


def test_issued_certificate_is_deterministic_and_verifies():
    kwargs = dict(
        team_id="team:example.com",
        team_signing_key=SEED,
        member_did_key=did_key_from_signing_key(bytes(range(32, 64))),
        alias="member",
        certificate_id="retained-id",
        issued_at="2026-11-18T12:00:00Z",
        lifetime="persistent",
    )
    certificate, blob = team_certificate.issue_team_certificate(**kwargs)
    assert (certificate, blob) == team_certificate.issue_team_certificate(**kwargs)
    assert certificate["certificate_id"] == "retained-id"
    assert certificate["issued_at"] == "2026-11-18T12:00:00Z"
    assert certificate["identity_scope"] == "global"
    assert team_certificate.decode_team_certificate(blob) == certificate
    team_certificate.verify_team_certificate_signature(
        certificate, did_key_from_signing_key(SEED)
    )
    with pytest.raises(team_certificate.TeamCertificateError):
        team_certificate.verify_team_certificate_signature(
            dict(certificate, alias="changed"), did_key_from_signing_key(SEED)
        )


def test_request_producer_signs_exact_external_target_body_and_configured_origin():
    timestamp = "2026-11-18T12:00:00Z"
    body = b'{"value":"x"}'
    headers = request_auth.team_auth_request_headers(
        signing_key=SEED,
        team_id="team:example.com",
        audience="HTTPS://APP.EXAMPLE.COM/",
        method="post",
        path="/mount/v1/items/a%2Fb?draft=1",
        body=body,
        timestamp=timestamp,
    )
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/v1/items/a/b",
            "raw_path": b"/mount/v1/items/a%2Fb",
            "root_path": "/mount",
            "query_string": b"draft=1",
            "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        }
    )
    envelope = request_auth.team_auth_signature_payload(
        request,
        team_id="team:example.com",
        timestamp=timestamp,
        body_sha256=hashlib.sha256(body).hexdigest(),
        allowed_audiences=["https://app.example.com"],
    )
    assert envelope.version == 2
    assert envelope.payload["path"] == "/mount/v1/items/a%2Fb?draft=1"
    assert (
        verify_signature(
            did_key_from_signing_key(SEED),
            envelope.canonical_payload,
            headers["Authorization"].split()[2],
        )
        is VerifyResult.VERIFIED
    )
    with pytest.raises(ValueError, match="does not match request"):
        request_auth.team_auth_signature_payload(
            request,
            team_id="team:example.com",
            timestamp=timestamp,
            body_sha256=hashlib.sha256(body + b"changed").hexdigest(),
            allowed_audiences=["https://app.example.com"],
        )
