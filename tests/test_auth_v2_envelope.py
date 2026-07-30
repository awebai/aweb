from __future__ import annotations

import base64
import copy
import hashlib
import importlib
import json
import sys
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from aweb_layout import aweb_path
from awid.did import did_from_public_key
from awid.signing import canonical_json_bytes, sign_message, verify_did_key_signature
from fastapi import HTTPException
from nacl.signing import SigningKey
from starlette.requests import Request

from folio.auth import CachedTeamFacts, authenticate_request, raw_request_target
from folio.config import Settings

# aweb's server source is imported below so both implementations of the envelope can be
# checked against the same bytes. Located rather than assumed to be a sibling, and not
# guarded by exists(): if it cannot be found this module must fail loudly, because the
# alternative is a cross-repo conformance check that quietly stops comparing anything.
AWEB_SERVER_SRC = aweb_path("server", "src")
sys.path.insert(0, str(AWEB_SERVER_SRC))

TEAM_ID = "backend:example.com"
PUBLIC_ORIGIN = "https://folio.example.com"


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _aweb_team_auth_envelope() -> Any:
    return importlib.import_module("aweb.team_auth_envelope")


class FakeDB:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[Any, ...]]] = []

    async def execute(self, sql: str, *args: Any) -> None:
        self.calls.append((sql, args))


class FakeTeamCache:
    def __init__(self, facts: CachedTeamFacts | HTTPException) -> None:
        self.facts = facts
        self.requested_team_ids: list[str] = []

    async def get(self, team_id: str) -> CachedTeamFacts:
        self.requested_team_ids.append(team_id)
        if isinstance(self.facts, HTTPException):
            raise self.facts
        return self.facts


async def _body_receiver(body: bytes):
    sent = False

    async def receive() -> dict[str, Any]:
        nonlocal sent
        if sent:
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    return receive


def _certificate(
    *,
    team_key: SigningKey,
    team_did: str,
    member_did: str,
    certificate_id: str = "00000000-0000-4000-8000-000000000001",
) -> dict[str, Any]:
    cert = {
        "version": 1,
        "certificate_id": certificate_id,
        "team_id": TEAM_ID,
        "team_did_key": team_did,
        "member_did_key": member_did,
        "member_did_aw": "did:aw:alice",
        "member_address": "example.com/alice",
        "alias": "alice",
        "lifetime": "persistent",
        "issued_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }
    cert["signature"] = sign_message(bytes(team_key), canonical_json_bytes(cert))
    return cert


def _standard_b64_json(value: dict[str, Any]) -> str:
    return base64.b64encode(json.dumps(value).encode("utf-8")).decode("ascii")


async def _make_request(
    *,
    body: bytes = b"hello",
    method: str = "POST",
    path: str = "/v1/documents/note/versions",
    raw_path: bytes | None = None,
    query_string: bytes = b"",
    root_path: str = "",
    public_origin: str = PUBLIC_ORIGIN,
    timestamp: str | None = None,
    payload_overrides: dict[str, Any] | None = None,
    mutate_payload_bytes: Callable[[bytes], bytes] | None = None,
    sign_payload_bytes: bytes | None = None,
    include_signed_payload: bool = True,
    auth_did_override: str | None = None,
    signature_override: str | None = None,
    certificate_override: dict[str, Any] | None = None,
) -> tuple[Request, dict[str, Any]]:
    team_key = SigningKey.generate()
    member_key = SigningKey.generate()
    team_did = did_from_public_key(bytes(team_key.verify_key))
    member_did = did_from_public_key(bytes(member_key.verify_key))
    cert = certificate_override or _certificate(team_key=team_key, team_did=team_did, member_did=member_did)
    timestamp = timestamp or datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    signed_path = (raw_path or path.encode("ascii")).decode("ascii")
    if root_path and not signed_path.startswith(root_path):
        signed_path = root_path.rstrip("/") + signed_path
    if query_string:
        signed_path = f"{signed_path}?{query_string.decode('ascii')}"
    payload = {
        "aud": public_origin,
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "method": method.upper(),
        "path": signed_path,
        "team_id": str(cert.get("team_id")),
        "timestamp": timestamp,
        "v": 2,
    }
    if payload_overrides:
        for key, value in payload_overrides.items():
            if value is None:
                payload.pop(key, None)
            else:
                payload[key] = value
    canonical = canonical_json_bytes(payload)
    header_payload = mutate_payload_bytes(canonical) if mutate_payload_bytes else canonical
    signed_bytes = sign_payload_bytes or header_payload
    did_key = auth_did_override or member_did
    signature = signature_override or sign_message(bytes(member_key), signed_bytes)

    headers = [
        (b"authorization", f"DIDKey {did_key} {signature}".encode("ascii")),
        (b"x-aweb-timestamp", timestamp.encode("ascii")),
        (b"x-awid-team-certificate", _standard_b64_json(cert).encode("ascii")),
    ]
    if include_signed_payload:
        headers.append((b"x-aweb-signed-payload", _b64url(header_payload).encode("ascii")))

    request = Request(
        {
            "type": "http",
            "method": method,
            "scheme": "https",
            "server": ("folio.example.com", 443),
            "path": path,
            "raw_path": raw_path if raw_path is not None else path.encode("ascii"),
            "root_path": root_path,
            "query_string": query_string,
            "headers": headers,
        },
        await _body_receiver(body),
    )
    return request, {"team_did": team_did, "member_did": member_did, "cert": cert, "payload": payload, "canonical": canonical}


async def _authenticate(
    request: Request,
    *,
    team_did: str,
    revoked: frozenset[str] = frozenset(),
    public_origin: str = PUBLIC_ORIGIN,
) -> Any:
    settings = Settings(public_origin=public_origin)
    cache = FakeTeamCache(CachedTeamFacts(team_did_key=team_did, revoked_certificate_ids=revoked, expires_at=999999999.0))
    return await authenticate_request(request, settings=settings, team_cache=cache, db=FakeDB())  # type: ignore[arg-type]


async def _assert_reject(request: Request, *, team_did: str, status_code: int = 401, public_origin: str = PUBLIC_ORIGIN) -> None:
    with pytest.raises(HTTPException) as raised:
        await _authenticate(request, team_did=team_did, public_origin=public_origin)
    assert raised.value.status_code == status_code


@pytest.mark.asyncio
async def test_authenticate_v2_success_builds_principal_from_verified_certificate() -> None:
    request, ctx = await _make_request()

    principal = await _authenticate(request, team_did=ctx["team_did"])

    assert principal.team_id == TEAM_ID
    assert principal.did_key == ctx["member_did"]
    assert principal.did_aw == "did:aw:alice"
    assert principal.address == "example.com/alice"
    assert principal.alias == "alice"
    assert principal.certificate_id == ctx["cert"]["certificate_id"]
    assert principal.team_did_key == ctx["team_did"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("case", "kwargs"),
    [
        ("missing X-AWEB-Signed-Payload", {"include_signed_payload": False}),
        ("malformed X-AWEB-Signed-Payload", {"mutate_payload_bytes": lambda _raw: b"not json"}),
        ("noncanonical X-AWEB-Signed-Payload", {"mutate_payload_bytes": lambda raw: raw.replace(b'"v":2', b'"v": 2')}),
        ("missing v", {"payload_overrides": {"v": None}}),
        ("wrong v", {"payload_overrides": {"v": 1}}),
        ("timestamp mismatch", {"payload_overrides": {"timestamp": "2026-06-12T00:00:00Z"}}),
        ("body hash mismatch", {"payload_overrides": {"body_sha256": hashlib.sha256(b"other").hexdigest()}}),
        ("method mismatch", {"payload_overrides": {"method": "GET"}}),
        ("path mismatch", {"payload_overrides": {"path": "/v1/documents/other/versions"}}),
        ("team id mismatch", {"payload_overrides": {"team_id": "other:example.com"}}),
        ("aud mismatch", {"payload_overrides": {"aud": "https://other.example.com"}}),
        ("bad did signature", {"signature_override": "not-base64!"}),
    ],
)
async def test_authenticate_v2_rejects_invalid_envelope_cases(case: str, kwargs: dict[str, Any]) -> None:
    request, ctx = await _make_request(**kwargs)

    await _assert_reject(request, team_did=ctx["team_did"])


@pytest.mark.asyncio
async def test_authenticate_v2_rejects_timestamp_outside_skew() -> None:
    old = (datetime.now(UTC) - timedelta(minutes=10)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    request, ctx = await _make_request(timestamp=old)

    await _assert_reject(request, team_did=ctx["team_did"])


@pytest.mark.asyncio
async def test_authenticate_v2_rejects_request_signed_for_another_path_method_or_host() -> None:
    path_replay, path_ctx = await _make_request(payload_overrides={"path": "/v1/documents/original"})
    method_replay, method_ctx = await _make_request(payload_overrides={"method": "GET"})
    host_replay, host_ctx = await _make_request(payload_overrides={"aud": "https://api.other.example"})

    await _assert_reject(path_replay, team_did=path_ctx["team_did"])
    await _assert_reject(method_replay, team_did=method_ctx["team_did"])
    await _assert_reject(host_replay, team_did=host_ctx["team_did"])


@pytest.mark.asyncio
async def test_authenticate_v2_rejects_misconfigured_public_origin() -> None:
    request, ctx = await _make_request()

    await _assert_reject(request, team_did=ctx["team_did"], public_origin="https://folio.example.com/not-an-origin")


@pytest.mark.asyncio
async def test_authenticate_uses_raw_path_with_query_and_root_path_for_binding() -> None:
    request, ctx = await _make_request(
        path="/v1/documents/a/b/versions",
        raw_path=b"/v1/documents/a%2Fb/versions",
        root_path="/api",
        query_string=b"b=2&a=1",
    )

    aweb_envelope = _aweb_team_auth_envelope()

    assert raw_request_target(request) == "/api/v1/documents/a%2Fb/versions?b=2&a=1"
    assert aweb_envelope.raw_request_target(request) == raw_request_target(request)
    principal = await _authenticate(request, team_did=ctx["team_did"])
    assert principal.team_id == TEAM_ID


@pytest.mark.asyncio
async def test_authenticate_v2_rejects_certificate_member_mismatch() -> None:
    request, ctx = await _make_request(auth_did_override="did:key:z6MismatchedMember")

    await _assert_reject(request, team_did=ctx["team_did"])


@pytest.mark.asyncio
async def test_authenticate_v2_verifies_certificate_against_awid_resolved_team_key_not_cert_field() -> None:
    wrong_awid_key = SigningKey.generate()
    wrong_awid_team_did = did_from_public_key(bytes(wrong_awid_key.verify_key))
    request, ctx = await _make_request()

    await _assert_reject(request, team_did=wrong_awid_team_did)
    assert ctx["cert"]["team_did_key"] == ctx["team_did"]


@pytest.mark.asyncio
async def test_authenticate_v2_rejects_revoked_certificate_id() -> None:
    request, ctx = await _make_request()

    with pytest.raises(HTTPException) as raised:
        await _authenticate(request, team_did=ctx["team_did"], revoked=frozenset({ctx["cert"]["certificate_id"]}))
    assert raised.value.status_code == 401


@pytest.mark.asyncio
async def test_authenticate_v2_fails_closed_when_awid_facts_unavailable() -> None:
    request, _ctx = await _make_request()
    settings = Settings(public_origin=PUBLIC_ORIGIN)
    cache = FakeTeamCache(HTTPException(status_code=503, detail="AWID registry unavailable"))

    with pytest.raises(HTTPException) as raised:
        await authenticate_request(request, settings=settings, team_cache=cache, db=FakeDB())  # type: ignore[arg-type]
    assert raised.value.status_code == 503


def test_aweb_team_auth_envelope_v2_conformance_vector() -> None:
    vector_path = aweb_path("docs", "vectors", "team-auth-envelope-v2.json")
    vector = json.loads(vector_path.read_text())
    case = vector["cases"][0]
    canonical = case["canonical_payload"].encode("utf-8")

    assert canonical_json_bytes(case["payload"]) == canonical
    assert _b64url(canonical) == case["signed_payload_b64url"]
    verify_did_key_signature(did_key=case["did_key"], payload=canonical, signature_b64=case["signature_b64"])

    request = Request(
        {
            "type": "http",
            "method": case["payload"]["method"],
            "scheme": "https",
            "path": "/api/v1/a2a/gateway/routes",
            "raw_path": b"/api/v1/a2a/gateway/routes",
            "root_path": "",
            "query_string": b"dry_run=true",
            "headers": [(b"x-aweb-signed-payload", case["signed_payload_b64url"].encode("ascii"))],
        }
    )
    body_sha256 = hashlib.sha256(case["body"].encode()).hexdigest()
    aweb_module = _aweb_team_auth_envelope()
    aweb_envelope = aweb_module.team_auth_signature_payload(
        request,
        team_id=case["payload"]["team_id"],
        timestamp=case["payload"]["timestamp"],
        body_sha256=body_sha256,
        allowed_audiences=[case["payload"]["aud"].upper().replace("HTTPS://", "https://") + "/"],
    )
    assert aweb_envelope.canonical_payload == canonical


def test_crypto_signature_vector_still_verifies_presented_bytes() -> None:
    vector_path = aweb_path("test-vectors", "trust", "crypto-sig-v1.json")
    vector = json.loads(vector_path.read_text())
    valid_case = vector["vectors"][0]

    verify_did_key_signature(
        did_key=valid_case["from_did"],
        payload=valid_case["signed_payload"].encode("utf-8"),
        signature_b64=valid_case["signature"],
    )

    invalid_case = copy.deepcopy(valid_case)
    invalid_case["signed_payload"] = invalid_case["signed_payload"].replace("world", "mallory")
    with pytest.raises(ValueError):
        verify_did_key_signature(
            did_key=invalid_case["from_did"],
            payload=invalid_case["signed_payload"].encode("utf-8"),
            signature_b64=invalid_case["signature"],
        )
