from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from starlette.requests import Request

from awid.signing import canonical_json_bytes, verify_did_key_signature
from aweb.team_auth_envelope import (
    compact_team_auth_payload,
    raw_request_target,
    team_auth_signature_payload,
)


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _load_vector() -> dict:
    root = Path(__file__).resolve().parents[2]
    return json.loads((root / "docs" / "vectors" / "team-auth-envelope-v2.json").read_text())


def _request(
    *,
    method: str = "POST",
    path: str = "/api/v1/tasks",
    raw_path: bytes | None = None,
    root_path: str = "",
    query_string: bytes = b"",
    signed_payload: bytes | None = None,
) -> Request:
    headers = [(b"host", b"internal.local")]
    if signed_payload is not None:
        headers.append((b"x-aweb-signed-payload", _b64url(signed_payload).encode()))
    return Request(
        {
            "type": "http",
            "method": method,
            "scheme": "http",
            "path": path,
            "root_path": root_path,
            "raw_path": raw_path if raw_path is not None else path.encode(),
            "query_string": query_string,
            "headers": headers,
        }
    )


def test_team_auth_envelope_compact_v1_without_signed_payload_header() -> None:
    timestamp = datetime.now(timezone.utc).isoformat()
    body_sha256 = hashlib.sha256(b"").hexdigest()

    envelope = team_auth_signature_payload(
        _request(method="GET"),
        team_id="default:aweb.ai",
        timestamp=timestamp,
        body_sha256=body_sha256,
        allowed_audiences=["https://app.aweb.ai"],
    )

    assert envelope.version == 1
    assert envelope.canonical_payload == compact_team_auth_payload(
        team_id="default:aweb.ai",
        timestamp=timestamp,
        body_sha256=body_sha256,
    )


def test_team_auth_envelope_v2_binds_presented_payload_to_request() -> None:
    timestamp = datetime.now(timezone.utc).isoformat()
    body_sha256 = hashlib.sha256(b'{"task":"aida"}').hexdigest()
    canonical = canonical_json_bytes(
        {
            "aud": "https://app.aweb.ai",
            "body_sha256": body_sha256,
            "method": "POST",
            "operation": "a2a_route_create",
            "path": "/api/v1/a2a/gateway/routes?dry_run=true",
            "team_id": "default:aweb.ai",
            "timestamp": timestamp,
            "v": 2,
        }
    )

    envelope = team_auth_signature_payload(
        _request(
            path="/api/v1/a2a/gateway/routes",
            query_string=b"dry_run=true",
            signed_payload=canonical,
        ),
        team_id="default:aweb.ai",
        timestamp=timestamp,
        body_sha256=body_sha256,
        allowed_audiences=["https://app.aweb.ai"],
    )

    assert envelope.version == 2
    assert envelope.canonical_payload == canonical
    assert envelope.payload["operation"] == "a2a_route_create"


def test_team_auth_envelope_v2_uses_root_path_aware_raw_target() -> None:
    request = _request(
        path="/v1/tasks",
        raw_path=b"/v1/tasks",
        root_path="/api",
        query_string=b"q=a%2Fb",
    )

    assert raw_request_target(request) == "/api/v1/tasks?q=a%2Fb"


def test_team_auth_envelope_v2_rejects_cross_endpoint_replay() -> None:
    timestamp = datetime.now(timezone.utc).isoformat()
    body_sha256 = hashlib.sha256(b"").hexdigest()
    canonical = canonical_json_bytes(
        {
            "aud": "https://app.aweb.ai",
            "body_sha256": body_sha256,
            "method": "GET",
            "path": "/api/v1/tasks",
            "team_id": "default:aweb.ai",
            "timestamp": timestamp,
            "v": 2,
        }
    )

    with pytest.raises(ValueError, match="does not match request"):
        team_auth_signature_payload(
            _request(
                method="GET",
                path="/api/v1/a2a/gateway/routes",
                query_string=b"",
                signed_payload=canonical,
            ),
            team_id="default:aweb.ai",
            timestamp=timestamp,
            body_sha256=body_sha256,
            allowed_audiences=["https://app.aweb.ai"],
        )


def test_team_auth_envelope_v2_rejects_cross_origin_replay() -> None:
    timestamp = datetime.now(timezone.utc).isoformat()
    body_sha256 = hashlib.sha256(b"").hexdigest()
    canonical = canonical_json_bytes(
        {
            "aud": "https://evil.example",
            "body_sha256": body_sha256,
            "method": "GET",
            "path": "/api/v1/tasks",
            "team_id": "default:aweb.ai",
            "timestamp": timestamp,
            "v": 2,
        }
    )

    with pytest.raises(ValueError, match="audience is not allowed"):
        team_auth_signature_payload(
            _request(method="GET", path="/api/v1/tasks", query_string=b"", signed_payload=canonical),
            team_id="default:aweb.ai",
            timestamp=timestamp,
            body_sha256=body_sha256,
            allowed_audiences=["https://app.aweb.ai"],
        )


def test_team_auth_envelope_v2_rejects_noncanonical_payload() -> None:
    raw = b'{"v":2, "aud":"https://app.aweb.ai"}'

    with pytest.raises(ValueError, match="invalid X-AWEB-Signed-Payload"):
        team_auth_signature_payload(
            _request(signed_payload=raw),
            team_id="default:aweb.ai",
            timestamp="2026-06-12T10:00:00Z",
            body_sha256=hashlib.sha256(b"").hexdigest(),
            allowed_audiences=["https://app.aweb.ai"],
        )


def test_team_auth_envelope_v2_conformance_vector() -> None:
    vector = _load_vector()
    assert "oss_task_create" in {case["name"] for case in vector["cases"]}

    for case in vector["cases"]:
        payload = case["payload"]
        canonical = case["canonical_payload"].encode()
        target = urlsplit(payload["path"])
        assert canonical_json_bytes(payload) == canonical
        assert _b64url(canonical) == case["signed_payload_b64url"]
        verify_did_key_signature(
            did_key=case["did_key"],
            payload=canonical,
            signature_b64=case["signature_b64"],
        )
        envelope = team_auth_signature_payload(
            _request(
                path=target.path,
                query_string=target.query.encode(),
                signed_payload=canonical,
            ),
            team_id=payload["team_id"],
            timestamp=payload["timestamp"],
            body_sha256=hashlib.sha256(case["body"].encode()).hexdigest(),
            allowed_audiences=[payload["aud"]],
        )
        assert envelope.version == vector["version"]
        assert envelope.canonical_payload == canonical


def test_team_auth_envelope_v2_conformance_negative_cases() -> None:
    vector = _load_vector()
    case = vector["cases"][0]
    payload = case["payload"]
    canonical = case["canonical_payload"].encode()
    body_sha256 = hashlib.sha256(case["body"].encode()).hexdigest()

    for negative in vector["negative_cases"]:
        if negative["name"] == "cross_endpoint_replay":
            request = _request(method=payload["method"], path=negative["presented_path"], query_string=b"", signed_payload=canonical)
            audiences = ["https://app.aweb.ai"]
            expected_hash = body_sha256
        elif negative["name"] == "cross_origin_replay":
            request = _request(method=payload["method"], path="/api/v1/a2a/gateway/routes", query_string=b"dry_run=true", signed_payload=canonical)
            audiences = negative["allowed_audiences"]
            expected_hash = body_sha256
        elif negative["name"] == "tampered_body":
            request = _request(method=payload["method"], path="/api/v1/a2a/gateway/routes", query_string=b"dry_run=true", signed_payload=canonical)
            audiences = ["https://app.aweb.ai"]
            expected_hash = hashlib.sha256(negative["presented_body"].encode()).hexdigest()
        elif negative["name"] == "missing_version":
            modified = dict(payload)
            modified.pop(negative["remove_field"])
            request = _request(
                method=payload["method"],
                path="/api/v1/a2a/gateway/routes",
                query_string=b"dry_run=true",
                signed_payload=canonical_json_bytes(modified),
            )
            audiences = ["https://app.aweb.ai"]
            expected_hash = body_sha256
        else:
            raise AssertionError(f"unhandled negative vector {negative['name']}")

        with pytest.raises(ValueError, match=negative["expected_error"]):
            team_auth_signature_payload(
                request,
                team_id=payload["team_id"],
                timestamp=payload["timestamp"],
                body_sha256=expected_hash,
                allowed_audiences=audiences,
            )
