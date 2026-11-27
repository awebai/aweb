"""Public SDK wire and real controller authentication before seam extraction.

The transport records each outgoing request and raises; it fabricates no
registry response. Controls cover wire/authentication and signed objects,
not registry effects, caller eligibility, database state or holder isolation.
"""

import base64
import json
from contextlib import aclosing, asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from types import SimpleNamespace
from urllib.parse import unquote, urlsplit

import httpx
import pytest
from fastapi import HTTPException
from nacl.signing import SigningKey
from starlette.requests import Request

from awid.controller_request import verify_controller_json_request
from awid.did import did_from_public_key, stable_id_from_did_key
from awid.id_tree_requests import (
    covering_payload,
    rotate_body,
    rotate_claims,
    rotate_path,
)
from awid.registry import RegistryClient
from awid.signing import canonical_json_bytes, sign_message, verify_did_key_signature
from awid.team_certificate import verify_team_certificate_signature
from awid.team_server_record import (
    TeamServerRecordError,
    build_team_server_record,
    record_signing_bytes,
    sign_team_server_record,
    verify_team_server_record,
)

SEED = bytes(range(32))
OTHER_SEED = bytes(range(1, 33))
DID = did_from_public_key(bytes(SigningKey(SEED).verify_key))
OTHER_DID = did_from_public_key(bytes(SigningKey(OTHER_SEED).verify_key))
DID_AW, OTHER_DID_AW = stable_id_from_did_key(DID), stable_id_from_did_key(OTHER_DID)
ORIGIN = "https://registry.example.com"
DOMAIN, TEAM = "customer.example", "engineering"
TEAM_PATH = f"/v1/namespaces/{DOMAIN}/teams"
ADDRESS_PATH = f"/v1/namespaces/{DOMAIN}/addresses"
CERTIFICATE_ID = "00000000-0000-4000-8000-000000000001"


def certificate_blob():
    certificate = {
        "version": 1,
        "certificate_id": CERTIFICATE_ID,
        "team_id": f"{TEAM}:{DOMAIN}",
        "team_did_key": DID,
        "member_did_key": OTHER_DID,
        "alias": "agent",
        "lifetime": "local",
        "issued_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    certificate["signature"] = sign_message(SEED, canonical_json_bytes(certificate))
    verify_team_certificate_signature(certificate, DID)
    return base64.b64encode(canonical_json_bytes(certificate)).decode()


CERTIFICATE = certificate_blob()
CERTIFICATE_BODY = {
    "certificate_id": CERTIFICATE_ID,
    "member_did_key": OTHER_DID,
    "member_did_aw": None,
    "member_address": None,
    "alias": "agent",
    "identity_scope": "local",
    "certificate": CERTIFICATE,
}


@dataclass(frozen=True)
class WireCase:
    call: str
    kwargs: dict
    method: str
    path: str
    body: dict | None
    claims: dict


# Public entry points that reach a mutation without first needing a read answer.
# Namespace deletion and team rotation have no public SDK entry point yet.
# Reassignment's required initial identity lookup has a separate control below.
CASES = [
    WireCase(
        "register_namespace",
        dict(
            domain=DOMAIN,
            controller_did=DID,
            controller_signing_key=SEED,
            default_delivery_origin="https://delivery.example",
        ),
        "POST",
        "/v1/namespaces",
        dict(
            domain=DOMAIN,
            controller_did=DID,
            default_delivery_origin="https://delivery.example",
        ),
        dict(operation="register", default_delivery_origin="https://delivery.example"),
    ),
    WireCase(
        "update_namespace_delivery_origin",
        dict(domain=DOMAIN, controller_signing_key=SEED, default_delivery_origin=None),
        "PATCH",
        f"/v1/namespaces/{DOMAIN}",
        dict(default_delivery_origin=None),
        dict(operation="update_namespace", default_delivery_origin=""),
    ),
    WireCase(
        "rotate_namespace_controller",
        dict(domain=DOMAIN, new_controller_did=DID, new_controller_signing_key=SEED),
        "PUT",
        f"/v1/namespaces/{DOMAIN}",
        dict(new_controller_did=DID),
        dict(operation="rotate_controller", new_controller_did=DID),
    ),
    WireCase(
        "register_team",
        dict(
            domain=DOMAIN,
            name=TEAM,
            display_name="Engineering",
            team_did_key=OTHER_DID,
            visibility="private",
            namespace_controller_signing_key=SEED,
        ),
        "POST",
        TEAM_PATH,
        dict(
            name=TEAM,
            display_name="Engineering",
            team_did_key=OTHER_DID,
            visibility="private",
        ),
        dict(operation="create_team", name=TEAM),
    ),
    WireCase(
        "set_team_visibility",
        dict(
            domain=DOMAIN,
            name=TEAM,
            visibility="public",
            team_controller_signing_key=SEED,
        ),
        "POST",
        f"{TEAM_PATH}/{TEAM}/visibility",
        dict(visibility="public"),
        dict(operation="set_team_visibility", team_name=TEAM, visibility="public"),
    ),
    WireCase(
        "delete_team",
        dict(domain=DOMAIN, name=TEAM, namespace_controller_signing_key=SEED),
        "DELETE",
        f"{TEAM_PATH}/{TEAM}",
        None,
        dict(operation="delete_team", team_name=TEAM),
    ),
    WireCase(
        "register_team_certificate",
        dict(
            domain=DOMAIN,
            name=TEAM,
            team_controller_signing_key=SEED,
            **CERTIFICATE_BODY,
        ),
        "POST",
        f"{TEAM_PATH}/{TEAM}/certificates",
        CERTIFICATE_BODY,
        dict(
            operation="register_certificate",
            team_name=TEAM,
            certificate_id=CERTIFICATE_ID,
        ),
    ),
    WireCase(
        "revoke_team_certificate",
        dict(
            domain=DOMAIN,
            name=TEAM,
            team_controller_signing_key=SEED,
            certificate_id=CERTIFICATE_ID,
        ),
        "POST",
        f"{TEAM_PATH}/{TEAM}/certificates/revoke",
        dict(certificate_id=CERTIFICATE_ID),
        dict(
            operation="revoke_certificate",
            team_name=TEAM,
            certificate_id=CERTIFICATE_ID,
        ),
    ),
    WireCase(
        "register_address",
        dict(
            domain=DOMAIN,
            name="agent",
            did_aw=OTHER_DID_AW,
            current_did_key=OTHER_DID,
            controller_signing_key=SEED,
        ),
        "POST",
        ADDRESS_PATH,
        dict(name="agent", did_aw=OTHER_DID_AW, current_did_key=OTHER_DID),
        dict(operation="register_address", name="agent"),
    ),
    WireCase(
        "update_address",
        dict(domain=DOMAIN, name="agent", controller_signing_key=SEED),
        "PUT",
        f"{ADDRESS_PATH}/agent",
        {},
        dict(operation="update_address", name="agent"),
    ),
    WireCase(
        "delete_address",
        dict(domain=DOMAIN, name="agent", controller_signing_key=SEED),
        "DELETE",
        f"{ADDRESS_PATH}/agent",
        None,
        dict(operation="delete_address", name="agent"),
    ),
]


class RequestCaptured(Exception):
    """Stop at the outgoing request; no registry answer exists."""


@asynccontextmanager
async def recording_client():
    requests = []

    def record(request):
        requests.append(request)
        raise RequestCaptured()

    async with aclosing(
        RegistryClient(registry_url=ORIGIN, transport=httpx.MockTransport(record))
    ) as client:
        yield client, requests


async def capture_call(call, **kwargs):
    async with recording_client() as (client, requests):
        with pytest.raises(RequestCaptured):
            await getattr(client, call)(**kwargs)
    assert len(requests) == 1
    return requests[0]


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=lambda case: case.call)
async def test_public_client_wire_keeps_its_method_target_body_and_route_claims(case):
    sent = await capture_call(case.call, **case.kwargs)
    assert (sent.method, str(sent.url)) == (case.method, ORIGIN + case.path)
    body = b"" if case.body is None else canonical_json_bytes(case.body)
    assert sent.content == body
    claims = {"domain": DOMAIN, **case.claims}
    request = http_request(
        dict(sent.headers),
        body=sent.content,
        path=sent.url.raw_path.decode(),
        method=sent.method,
    )
    assert await verify_controller_json_request(request, payload_dict=claims) == DID
    with pytest.raises(HTTPException) as refused:
        await verify_controller_json_request(
            http_request(
                dict(sent.headers),
                body=sent.content,
                path=sent.url.raw_path.decode(),
                method=sent.method,
            ),
            payload_dict={**claims, "domain": "another.example"},
        )
    assert refused.value.status_code == 401


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=lambda case: case.call)
async def test_client_headers_carry_the_covering_envelope(case):
    sent = await capture_call(case.call, **case.kwargs)
    authentication = {
        name
        for name in sent.headers
        if name == "authorization" or name.startswith("x-aweb-")
    }
    assert authentication == {
        "authorization",
        "x-aweb-timestamp",
        "x-aweb-signed-payload",
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "rotation", [False, True], ids=["parent-register", "parent-recovery"]
)
async def test_parent_authorization_keeps_its_distinct_headers_and_claims(rotation):
    claims = {"domain": DOMAIN, "child_domain": DOMAIN}
    if rotation:
        sent = await capture_call(
            "rotate_namespace_controller",
            domain=DOMAIN,
            new_controller_did=OTHER_DID,
            new_controller_signing_key=OTHER_SEED,
            parent_signing_key=SEED,
        )
        claims.update(
            operation="authorize_subdomain_rotation", new_controller_did=OTHER_DID
        )
        primary = dict(
            domain=DOMAIN, operation="rotate_controller", new_controller_did=OTHER_DID
        )
    else:
        sent = await capture_call(
            "register_namespace",
            domain=DOMAIN,
            controller_did=OTHER_DID,
            controller_signing_key=OTHER_SEED,
            parent_signing_key=SEED,
        )
        claims.update(
            operation="authorize_subdomain_registration", controller_did=OTHER_DID
        )
        primary = dict(domain=DOMAIN, operation="register")
    options = dict(
        authorization_header="X-AWEB-Parent-Authorization",
        timestamp_header="X-AWEB-Parent-Timestamp",
        signed_payload_header="X-AWEB-Parent-Signed-Payload",
    )

    def request():
        return http_request(
            dict(sent.headers),
            body=sent.content,
            path=sent.url.raw_path.decode(),
            method=sent.method,
        )

    assert (
        await verify_controller_json_request(request(), payload_dict=claims, **options)
        == DID
    )
    assert (
        await verify_controller_json_request(request(), payload_dict=primary)
        == OTHER_DID
    )
    with pytest.raises(HTTPException) as refused:
        await verify_controller_json_request(request(), payload_dict=claims)
    assert refused.value.status_code == 401


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "destination",
    [ORIGIN, "https://other-registry.example"],
    ids=["same-registry", "other-registry"],
)
@pytest.mark.parametrize("field", ["visibility", "team_did_key", "address_mapping"])
async def test_authentication_refuses_substituted_effect_fields_and_destination(
    field, destination
):
    call = "register_address" if field == "address_mapping" else "register_team"
    case = next(case for case in CASES if case.call == call)
    sent = await capture_call(case.call, **case.kwargs)
    claims = {"domain": DOMAIN, **case.claims}
    assert (
        await verify_controller_json_request(
            http_request(
                dict(sent.headers), body=sent.content, path=sent.url.raw_path.decode()
            ),
            payload_dict=claims,
        )
        == DID
    )
    changed = json.loads(sent.content)
    if field == "address_mapping":
        changed.update(did_aw=DID_AW, current_did_key=DID)
    elif field == "team_did_key":
        changed[field] = DID
    else:
        changed[field] = "public"
    assert changed != json.loads(sent.content)
    with pytest.raises(HTTPException) as refused:
        await verify_controller_json_request(
            http_request(
                dict(sent.headers),
                body=canonical_json_bytes(changed),
                path=sent.url.raw_path.decode(),
                origins=(destination,),
            ),
            payload_dict=claims,
        )
    assert refused.value.status_code == 401
    if destination != ORIGIN:
        # The unchanged request is refused by any other registry.
        with pytest.raises(HTTPException) as elsewhere:
            await verify_controller_json_request(
                http_request(
                    dict(sent.headers),
                    body=sent.content,
                    path=sent.url.raw_path.decode(),
                    origins=(destination,),
                ),
                payload_dict=claims,
            )
        assert elsewhere.value.status_code == 401


@pytest.mark.asyncio
@pytest.mark.parametrize("active_only", [True, False], ids=["active", "all"])
async def test_adcn_private_certificate_list_query_is_not_in_the_signed_proof(
    active_only,
):
    """records the adcn defect; the adcn fix inverts this assertion"""
    sent = await capture_call(
        "list_team_certificates",
        domain=DOMAIN,
        name=TEAM,
        active_only=active_only,
        signing_key=SEED,
    )
    path = f"{TEAM_PATH}/{TEAM}/certificates"
    assert sent.method == "GET"
    assert (
        str(sent.url)
        == f"{ORIGIN}{path}?active_only={str(active_only).lower()}&limit=200"
    )
    scheme, did, signature = sent.headers["Authorization"].split()
    assert (scheme, did) == ("DIDKey", DID)
    raw = f"{sent.headers['X-AWEB-Timestamp']}\nGET\n{path}".encode()
    verify_did_key_signature(did_key=DID, payload=raw, signature_b64=signature)
    with pytest.raises(ValueError):
        verify_did_key_signature(
            did_key=DID, payload=raw + b"?" + sent.url.query, signature_b64=signature
        )


@pytest.mark.asyncio
async def test_reassignment_resolves_the_new_identity_before_any_mutation():
    sent = await capture_call(
        "reassign_address",
        domain=DOMAIN,
        name="agent",
        new_did_aw=OTHER_DID_AW,
        controller_signing_key=SEED,
    )
    assert (sent.method, str(sent.url), sent.content) == (
        "GET",
        f"{ORIGIN}/v1/did/{OTHER_DID_AW}/key",
        b"",
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("awaitable", [False, True], ids=["sync", "async"])
async def test_public_continuity_client_keeps_old_and_new_key_roles_distinct(awaitable):
    def signer(seed):
        key = SigningKey(seed)
        did = did_from_public_key(bytes(key.verify_key))

        def direct(message):
            return did, key.sign(message).signature

        async def later(message):
            return direct(message)

        return later if awaitable else direct

    kwargs = dict(
        domain=DOMAIN,
        from_seq=7,
        previous_did_key=DID,
        new_did_key=OTHER_DID,
        previous_signer=signer(SEED),
        new_signer=signer(OTHER_SEED),
    )
    sent = await capture_call("rotate_namespace_with_previous_key", **kwargs)
    claims = dict(
        domain=DOMAIN,
        operation="rotate_namespace_controller",
        from_seq=7,
        previous_did_key=DID,
        new_did_key=OTHER_DID,
    )
    assert (sent.method, str(sent.url)) == ("POST", ORIGIN + rotate_path(DOMAIN))
    assert sent.content == rotate_body(
        DOMAIN, rotate_claims(from_seq=7, previous_did_key=DID, new_did_key=OTHER_DID)
    )
    for header, expected in (
        ("Authorization", DID),
        ("X-AWEB-New-Key-Authorization", OTHER_DID),
    ):
        assert (
            await verify_controller_json_request(
                http_request(
                    dict(sent.headers),
                    body=sent.content,
                    path=sent.url.raw_path.decode(),
                ),
                payload_dict=claims,
                authorization_header=header,
            )
            == expected
        )
    for role, wrong in (
        ("previous_signer", signer(OTHER_SEED)),
        ("new_signer", signer(SEED)),
    ):
        async with recording_client() as (client, requests):
            with pytest.raises(
                ValueError, match="key other than the one named for its role"
            ):
                await client.rotate_namespace_with_previous_key(
                    **{**kwargs, role: wrong}
                )
            assert requests == []


def http_request(
    headers,
    *,
    body=b"",
    path="/v1/namespaces",
    method="POST",
    origins=(ORIGIN,),
    root_path="",
):
    raw_path, _, query = path.partition("?")
    origin = urlsplit(origins[0] if origins else ORIGIN)

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(
        {
            "type": "http",
            "method": method,
            "path": unquote(raw_path),
            "scheme": origin.scheme,
            "server": (origin.hostname, origin.port or 443),
            "raw_path": raw_path.encode("ascii"),
            "root_path": root_path,
            "query_string": query.encode("ascii"),
            "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
            "app": SimpleNamespace(state=SimpleNamespace(awid_public_origins=origins)),
        },
        receive,
    )


def covering_headers(body, path, *, operation="create_team", claims=None):
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = covering_payload(
        aud=ORIGIN,
        path=path,
        domain=DOMAIN,
        operation=operation,
        body=body,
        timestamp=timestamp,
        claims=claims,
    )
    return {
        "Authorization": f"DIDKey {DID} {sign_message(SEED, payload)}",
        "X-AWEB-Timestamp": timestamp,
        "X-AWEB-Signed-Payload": base64.urlsafe_b64encode(payload)
        .rstrip(b"=")
        .decode(),
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change", ["body", "path", "method", "audience", "empty-envelope"]
)
async def test_covering_sdk_bytes_bind_the_request_and_do_not_downgrade(change):
    path = f"/v1/namespaces/{DOMAIN}/teams"
    body = canonical_json_bytes(
        {"name": TEAM, "team_did_key": OTHER_DID, "visibility": "private"}
    )
    claims = {"domain": DOMAIN, "name": TEAM, "operation": "create_team"}
    headers = covering_headers(body, path, claims={"name": TEAM})
    assert (
        await verify_controller_json_request(
            http_request(headers, body=body, path=path), payload_dict=claims
        )
        == DID
    )
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
        await verify_controller_json_request(
            http_request(headers, **options), payload_dict=claims
        )
    assert refused.value.status_code == 401


@pytest.mark.asyncio
async def test_covering_target_includes_external_mount_encoding_and_query():
    path = f"/registry/v1/namespaces/{DOMAIN}/teams?cursor=a%2Fb"
    body = canonical_json_bytes({"name": TEAM, "team_did_key": OTHER_DID})
    headers = covering_headers(body, path, claims={"name": TEAM})
    claims = {"domain": DOMAIN, "name": TEAM, "operation": "create_team"}
    assert (
        await verify_controller_json_request(
            http_request(headers, body=body, path=path, root_path="/registry"),
            payload_dict=claims,
        )
        == DID
    )
    with pytest.raises(HTTPException) as refused:
        await verify_controller_json_request(
            http_request(
                headers,
                body=body,
                path=path.replace("a%2Fb", "a/b"),
                root_path="/registry",
            ),
            payload_dict=claims,
        )
    assert refused.value.status_code == 401


def test_team_server_object_signature_is_not_a_generic_json_or_controller_request_signature():
    now = datetime(2026, 11, 15, tzinfo=timezone.utc)
    record = build_team_server_record(
        f"{TEAM}:{DOMAIN}", DID, "https://coord.example/api", now
    )
    signature = sign_team_server_record(SEED, record)
    verified = verify_team_server_record(
        record, signature, team_id=f"{TEAM}:{DOMAIN}", current_team_did_key=DID, now=now
    )
    assert verified.server_url == "https://coord.example/api"
    assert record_signing_bytes(
        record
    ) == b"aweb.team-server/1\n" + canonical_json_bytes(record)
    with pytest.raises(ValueError):
        verify_did_key_signature(
            did_key=DID, payload=canonical_json_bytes(record), signature_b64=signature
        )
    with pytest.raises(TeamServerRecordError):
        verify_team_server_record(
            record,
            sign_message(SEED, canonical_json_bytes(record)),
            team_id=f"{TEAM}:{DOMAIN}",
            current_team_did_key=DID,
            now=now,
        )


@pytest.mark.asyncio
async def test_a_registry_without_public_origins_names_the_setting_it_needs():
    case = next(case for case in CASES if case.call == "register_team")
    sent = await capture_call(case.call, **case.kwargs)
    with pytest.raises(HTTPException) as unavailable:
        await verify_controller_json_request(
            http_request(
                dict(sent.headers),
                body=sent.content,
                path=sent.url.raw_path.decode(),
                origins=(),
            ),
            payload_dict={"domain": DOMAIN, **case.claims},
        )
    assert unavailable.value.status_code == 503
    assert "AWID_PUBLIC_ORIGINS" in unavailable.value.detail
