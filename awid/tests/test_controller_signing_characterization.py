"""Existing SDK bytes and real controller authentication before seam extraction.

These controls exercise authentication and signed-object verification, not a
registry write, caller eligibility, database state or holder isolation. No
registry response is fabricated. Legacy omissions are recorded for adcn, not
repaired here or mistaken for permission to export authorization headers.
"""

import base64

from contextlib import aclosing
from datetime import datetime, timezone
from types import SimpleNamespace
from urllib.parse import unquote, urlsplit

import pytest
from fastapi import HTTPException
from nacl.signing import SigningKey
from starlette.requests import Request

from awid.controller_request import verify_controller_json_request
from awid.did import did_from_public_key
from awid.id_tree_requests import covering_payload, rotate_body, rotate_claims, rotate_path
from awid.registry import RegistryClient, _payload_signature
from awid.registry_auth import path_signature_headers
from awid.signing import canonical_json_bytes, sign_message, verify_did_key_signature
from awid.team_server_record import (
    TeamServerRecordError,
    build_team_server_record,
    record_signing_bytes,
    sign_team_server_record,
    verify_team_server_record,
)

SEED = bytes(range(32))
DID = did_from_public_key(bytes(SigningKey(SEED).verify_key))
OTHER_DID = did_from_public_key(bytes(SigningKey(bytes(range(1, 33))).verify_key))
ORIGIN = "https://registry.example.com"
DOMAIN, TEAM = "customer.example", "engineering"
CERTIFICATE_ID = "00000000-0000-4000-8000-000000000001"

# These are the existing route claims, independently of HTTP body fields.
LEGACY = [
    ("register", "namespace", {"default_delivery_origin": "https://delivery.example"}),
    ("update_namespace", "namespace", {"default_delivery_origin": ""}),
    ("delete_namespace", "namespace", {}),
    ("rotate_controller", "namespace", {"new_controller_did": OTHER_DID}),
    ("create_team", "team", {"name": TEAM}),
    ("rotate_team_key", "namespace", {"name": TEAM, "new_team_did_key": OTHER_DID}),
    ("delete_team", "namespace", {"team_name": TEAM}),
    ("set_team_visibility", "namespace", {"team_name": TEAM, "visibility": "public"}),
    ("register_certificate", "namespace", {"team_name": TEAM, "certificate_id": CERTIFICATE_ID}),
    ("revoke_certificate", "namespace", {"team_name": TEAM, "certificate_id": CERTIFICATE_ID}),
    ("register_address", "address", {"name": "agent"}),
    ("update_address", "address", {"name": "agent"}),
    ("delete_address", "address", {"name": "agent"}),
    ("reassign_address", "address", {"name": "agent"}),
]


def http_request(headers, *, body=b"", path="/v1/namespaces", method="POST", origins=(ORIGIN,), root_path=""):
    raw_path, _, query = path.partition("?")
    origin = urlsplit(origins[0] if origins else ORIGIN)

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    return Request({
        "type": "http", "method": method, "path": unquote(raw_path),
        "scheme": origin.scheme, "server": (origin.hostname, origin.port or 443),
        "raw_path": raw_path.encode("ascii"), "root_path": root_path,
        "query_string": query.encode("ascii"),
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        "app": SimpleNamespace(state=SimpleNamespace(awid_public_origins=origins)),
    }, receive)


@pytest.mark.asyncio
@pytest.mark.parametrize("operation,family,claims", LEGACY, ids=[row[0] for row in LEGACY])
async def test_existing_sdk_legacy_claims_authenticate_without_a_covering_envelope(operation, family, claims):
    async with aclosing(RegistryClient(registry_url=ORIGIN)) as client:
        if family == "namespace":
            headers = client._signed_namespace_headers(
                domain=DOMAIN, operation=operation, signing_key=SEED, extra_payload=claims,
            )
        elif family == "team":
            headers = client._signed_team_headers(domain=DOMAIN, name=TEAM, operation=operation, signing_key=SEED)
        else:
            headers = client._signed_address_headers(
                domain=DOMAIN, name="agent", operation=operation, signing_key=SEED,
            )
    assert set(headers) == {"Authorization", "X-AWEB-Timestamp"}
    expected_claims = {"domain": DOMAIN, "operation": operation, **claims}
    assert await verify_controller_json_request(http_request(headers), payload_dict=expected_claims) == DID
    changed = {**expected_claims, "domain": "another.example"}
    with pytest.raises(HTTPException) as refused:
        await verify_controller_json_request(http_request(headers), payload_dict=changed)
    assert refused.value.status_code == 401


@pytest.mark.asyncio
@pytest.mark.parametrize("rotation", [False, True], ids=["parent-register", "parent-recovery"])
async def test_parent_authorization_keeps_its_distinct_headers_and_claims(rotation):
    claims = {"domain": DOMAIN, "child_domain": DOMAIN}
    async with aclosing(RegistryClient(registry_url=ORIGIN)) as client:
        if rotation:
            claims.update(operation="authorize_subdomain_rotation", new_controller_did=OTHER_DID)
            headers = client._signed_parent_namespace_headers(
                parent_signing_key=SEED, child_domain=DOMAIN, new_controller_did=OTHER_DID,
            )
        else:
            claims.update(operation="authorize_subdomain_registration", controller_did=OTHER_DID)
            headers = client._signed_parent_namespace_registration_headers(
                parent_signing_key=SEED, child_domain=DOMAIN, controller_did=OTHER_DID,
            )
    assert set(headers) == {"X-AWEB-Parent-Authorization", "X-AWEB-Parent-Timestamp"}
    options = dict(authorization_header="X-AWEB-Parent-Authorization",
                   timestamp_header="X-AWEB-Parent-Timestamp", signed_payload_header="X-AWEB-Parent-Signed-Payload")
    assert await verify_controller_json_request(http_request(headers), payload_dict=claims, **options) == DID
    with pytest.raises(HTTPException) as refused:
        await verify_controller_json_request(http_request(headers), payload_dict=claims)
    assert refused.value.status_code == 401


@pytest.mark.asyncio
async def test_legacy_header_authentication_does_not_cryptographically_bind_body_or_destination():
    async with aclosing(RegistryClient(registry_url=ORIGIN)) as client:
        headers = client._signed_team_headers(domain=DOMAIN, name=TEAM, operation="create_team", signing_key=SEED)
    claims = {"domain": DOMAIN, "name": TEAM, "operation": "create_team"}
    for body, origins in ((b'{"visibility":"private"}', (ORIGIN,)),
                          (b'{"visibility":"public"}', ("https://other-registry.example",))):
        assert await verify_controller_json_request(
            http_request(headers, body=body, origins=origins, path=f"/v1/namespaces/{DOMAIN}/teams"),
            payload_dict=claims,
        ) == DID


def covering_headers(body, path, *, operation="create_team", claims=None):
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = covering_payload(aud=ORIGIN, path=path, domain=DOMAIN, operation=operation,
                               body=body, timestamp=timestamp, claims=claims)
    return {
        "Authorization": f"DIDKey {DID} {sign_message(SEED, payload)}",
        "X-AWEB-Timestamp": timestamp,
        "X-AWEB-Signed-Payload": base64.urlsafe_b64encode(payload).rstrip(b"=").decode(),
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["body", "path", "method", "audience", "empty-envelope"])
async def test_covering_sdk_bytes_bind_the_request_and_do_not_downgrade(change):
    path = f"/v1/namespaces/{DOMAIN}/teams"
    body = canonical_json_bytes({"name": TEAM, "team_did_key": OTHER_DID, "visibility": "private"})
    claims = {"domain": DOMAIN, "name": TEAM, "operation": "create_team"}
    headers = covering_headers(body, path, claims={"name": TEAM})
    assert await verify_controller_json_request(http_request(headers, body=body, path=path),
                                                payload_dict=claims) == DID
    options = dict(body=body, path=path)
    if change == "body":
        options["body"] = body.replace(b'"private"', b'"public"')
    elif change == "path":
        options["path"] = path + "?cursor=changed"
    elif change == "method":
        options["method"] = "DELETE"
    elif change == "audience":
        options["origins"] = ("https://other-registry.example",)
    else:
        headers["X-AWEB-Signed-Payload"] = ""
    with pytest.raises(HTTPException) as refused:
        await verify_controller_json_request(http_request(headers, **options), payload_dict=claims)
    assert refused.value.status_code == 401


@pytest.mark.asyncio
async def test_covering_target_includes_external_mount_encoding_and_query():
    path = f"/registry/v1/namespaces/{DOMAIN}/teams?cursor=a%2Fb"
    body = canonical_json_bytes({"name": TEAM, "team_did_key": OTHER_DID})
    headers = covering_headers(body, path, claims={"name": TEAM})
    claims = {"domain": DOMAIN, "name": TEAM, "operation": "create_team"}
    assert await verify_controller_json_request(
        http_request(headers, body=body, path=path, root_path="/registry"), payload_dict=claims,
    ) == DID
    with pytest.raises(HTTPException) as refused:
        await verify_controller_json_request(
            http_request(headers, body=body, path=path.replace("a%2Fb", "a/b"), root_path="/registry"),
            payload_dict=claims,
        )
    assert refused.value.status_code == 401


def test_private_certificate_list_proof_binds_the_base_path_not_query():
    path = f"/v1/namespaces/{DOMAIN}/teams/{TEAM}/certificates"
    headers = path_signature_headers("GET", path, SEED)
    scheme, did, signature = headers["Authorization"].split()
    assert (scheme, did) == ("DIDKey", DID)
    raw = f'{headers["X-AWEB-Timestamp"]}\nGET\n{path}'.encode()
    verify_did_key_signature(did_key=DID, payload=raw, signature_b64=signature)
    for query in ("?active_only=true", "?active_only=false&limit=200&cursor=next"):
        with pytest.raises(ValueError):
            verify_did_key_signature(did_key=DID, payload=raw + query.encode(), signature_b64=signature)


def test_team_server_object_signature_is_not_a_generic_json_or_controller_request_signature():
    now = datetime(2026, 11, 15, tzinfo=timezone.utc)
    record = build_team_server_record(f"{TEAM}:{DOMAIN}", DID, "https://coord.example/api", now)
    signature = sign_team_server_record(SEED, record)
    verified = verify_team_server_record(record, signature, team_id=f"{TEAM}:{DOMAIN}",
                                         current_team_did_key=DID, now=now)
    assert verified.server_url == "https://coord.example/api"
    assert record_signing_bytes(record) == b"aweb.team-server/1\n" + canonical_json_bytes(record)
    with pytest.raises(ValueError):
        verify_did_key_signature(did_key=DID, payload=canonical_json_bytes(record), signature_b64=signature)
    with pytest.raises(TeamServerRecordError):
        verify_team_server_record(record, sign_message(SEED, canonical_json_bytes(record)),
                                  team_id=f"{TEAM}:{DOMAIN}", current_team_did_key=DID, now=now)


@pytest.mark.asyncio
@pytest.mark.parametrize("awaitable", [False, True], ids=["sync", "async"])
async def test_existing_signer_validation_keeps_old_and_new_key_roles_distinct(awaitable):
    claims = rotate_claims(from_seq=7, previous_did_key=DID, new_did_key=OTHER_DID)
    payload = covering_payload(
        aud=ORIGIN, path=rotate_path(DOMAIN), domain=DOMAIN,
        operation="rotate_namespace_controller",
        body=rotate_body(DOMAIN, claims), claims=claims,
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    key = SigningKey(SEED)

    def direct(message):
        return DID, key.sign(message).signature

    async def later(message):
        return direct(message)

    signer = later if awaitable else direct
    returned_did, signature = await _payload_signature(signer, payload, DID)
    assert returned_did == DID
    verify_did_key_signature(did_key=DID, payload=payload,
                             signature_b64=base64.b64encode(signature).decode())
    with pytest.raises(ValueError, match="key other than the one named for its role"):
        await _payload_signature(signer, payload, OTHER_DID)
