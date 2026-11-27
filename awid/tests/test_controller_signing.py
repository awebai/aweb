"""Typed controller boundary: real signatures and existing wire canonicalizers."""

import base64
import asyncio
import copy
import hashlib
import json

import pytest
from nacl.signing import SigningKey
import httpx

from awid.controller_signing import (
    ControllerDescriptor,
    ControllerSigningError,
    build_controller_payload,
    parse_controller_object,
    parse_controller_request,
    sign_controller_object,
    controller_http_plan,
)
from awid.did import did_key_from_signing_key
from awid.id_certificates import id_certificate_signing_bytes, verify_id_certificate
from awid.id_tree_requests import covering_payload, rotate_body, rotate_claims
from awid.signing import canonical_json_bytes
from awid.registry import RegistryClient

SEED = bytes(range(32))
KEY = did_key_from_signing_key(SEED)
NEW_SEED = bytes(range(1, 33))
NEW_KEY = did_key_from_signing_key(NEW_SEED)
TS = "2026-11-16T00:00:00Z"
ORIGIN = "https://registry.example"
CONTROLLER = ControllerDescriptor("namespace", "example.com", KEY, "namespace-1", 3)


def request(operation="team_register", **parameters):
    if operation == "team_register":
        parameters = {
            "name": "team",
            "display_name": "Team",
            "team_did_key": NEW_KEY,
            "visibility": "private",
            **parameters,
        }
    return parse_controller_request(
        {"operation": operation, "domain": "example.com", **parameters}
    )


def payload(req, controller=CONTROLLER, role="controller"):
    return build_controller_payload(
        req, controller=controller, role=role, timestamp=TS, registry_origin=ORIGIN
    )


def test_team_bytes_cover_the_body_and_the_audience():
    # The team key, visibility and display name are in the signed bytes, and
    # the signature names the one registry it is for.
    assert payload(request()) == covering_payload(
        aud=ORIGIN,
        method="POST",
        path="/v1/namespaces/example.com/teams",
        domain="example.com",
        operation="create_team",
        body=canonical_json_bytes(request().parameters),
        timestamp=TS,
        claims={"name": "team"},
    )


@pytest.mark.parametrize(
    "fields",
    [
        {"operation": "sign", "domain": "example.com", "payload": "anything"},
        {"operation": "team_register", "domain": "example.com", "path": "/arbitrary"},
        {"operation": "namespace_delete", "domain": "example.com/elsewhere"},
        {"operation": "namespace_delete", "domain": ".."},
        {"operation": "namespace_delete", "domain": "EXAMPLE.COM"},
        {"operation": "team_delete", "domain": "example.com", "name": "../x"},
        {
            "operation": "team_visibility",
            "domain": "example.com",
            "name": "t",
            "visibility": "hidden",
        },
    ],
)
def test_untyped_or_unshaped_operation_refuses(fields):
    with pytest.raises(ControllerSigningError):
        parse_controller_request(fields)


def test_request_freezes_nested_input_and_returns_detached_parameters():
    fields = {
        "operation": "team_rotate",
        "domain": "example.com",
        "name": "team",
        "new_team_did_key": NEW_KEY,
        "resigned_records": {"team_custodians": []},
    }
    req = parse_controller_request(fields)
    before = req.parameters
    fields["resigned_records"]["team_custodians"].append({"untrusted": True})
    req.parameters["resigned_records"]["team_custodians"].append({"also": "detached"})
    assert req.parameters == before


def test_continuity_keeps_distinct_old_new_roles_and_current_epoch():
    req = request(
        "namespace_rotate", from_seq=2, previous_did_key=KEY, new_did_key=NEW_KEY
    )
    claims = rotate_claims(from_seq=2, previous_did_key=KEY, new_did_key=NEW_KEY)
    want = covering_payload(
        aud=ORIGIN,
        path="/v1/namespaces/example.com/rotate",
        domain="example.com",
        operation="rotate_namespace_controller",
        body=rotate_body("example.com", claims),
        timestamp=TS,
        claims=claims,
    )
    assert payload(req) == want
    new = ControllerDescriptor("namespace", "example.com", NEW_KEY, "next", 4)
    assert payload(req, new, "new_controller") == want
    with pytest.raises(ControllerSigningError, match="controller_mismatch"):
        payload(req, new)


def test_team_authority_is_not_namespace_authority():
    req = request("team_visibility", name="team", visibility="public")
    with pytest.raises(ControllerSigningError, match="controller_scope"):
        payload(req)
    team = ControllerDescriptor("team", "example.com", KEY, "team-1", 0, team="team")
    assert json.loads(payload(req, team))["team_name"] == "team"


def id_request(kind="human"):
    return parse_controller_object(
        {
            "operation": "namespace_id_issue",
            "domain": "example.com",
            "kind": kind,
            "certificate": {
                "v": 1,
                "type": "aweb.id-certificate",
                "id": "did:aw:2Uq51iFVLnqmgbVY3vLZtMD5PR87",
                "domain": "example.com",
                "parent": {"kind": "namespace", "id": "example.com"},
                "kind": "human",
                "issuer_key": KEY,
                "issued_at": TS,
            },
        }
    )


@pytest.mark.asyncio
async def test_typed_object_signer_receives_operation_and_returns_checked_artifact():
    seen = []

    async def signer(context):
        seen.append(context)
        assert context.request.operation == "namespace_id_issue"
        assert context.controller.key_reference == "namespace-1"
        return KEY, SigningKey(SEED).sign(context.signing_bytes()).signature

    req = id_request()
    result = await sign_controller_object(req, controller=CONTROLLER, signer=signer)
    verify_id_certificate(result, issuer_key=KEY)
    assert seen[0].signing_bytes() == id_certificate_signing_bytes(
        result["certificate"]
    )


def test_agent_request_cannot_issue_a_human_certificate():
    with pytest.raises(ControllerSigningError, match="object_invalid"):
        id_request("agent")


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ["key", "signature", "shape"])
async def test_wrong_signer_answer_returns_no_artifact(fault):
    def signer(context):
        if fault == "shape":
            return b"not a typed answer"
        return (
            NEW_KEY if fault == "key" else KEY,
            SigningKey(NEW_SEED).sign(context.signing_bytes()).signature,
        )

    with pytest.raises(ControllerSigningError, match="signer_answer"):
        await sign_controller_object(id_request(), controller=CONTROLLER, signer=signer)


@pytest.mark.asyncio
async def test_replacement_is_an_application_object_with_exact_existing_bytes():
    fields = {
        "address": "example.com/person",
        "controller_did": KEY,
        "old_did": KEY,
        "new_did": NEW_KEY,
        "timestamp": TS,
    }
    req = parse_controller_object(
        {"operation": "address_replacement", "domain": "example.com", **fields}
    )

    def signer(context):
        assert context.signing_bytes() == canonical_json_bytes(fields)
        return KEY, SigningKey(SEED).sign(context.signing_bytes()).signature

    result = await sign_controller_object(req, controller=CONTROLLER, signer=signer)
    assert result["announcement"] == fields
    assert len(base64.b64decode(result["signature"] + "==")) == 64


@pytest.mark.asyncio
async def test_input_mutation_across_await_cannot_change_signed_object():
    req = id_request()
    before = copy.deepcopy(req.parameters)

    async def signer(context):
        context.request.parameters["certificate"]["kind"] = "agent"
        return KEY, SigningKey(SEED).sign(context.signing_bytes()).signature

    result = await sign_controller_object(req, controller=CONTROLLER, signer=signer)
    assert result["certificate"] == before["certificate"]


class Captured(Exception):
    pass


@pytest.mark.asyncio
async def test_owned_transport_pins_destination_and_checks_exact_wire_before_send():
    sent = []

    async def transport(outgoing):
        sent.append(outgoing)
        raise Captured()

    async def forbidden_discovery(domain):
        pytest.fail("controller transport must not discover its destination")

    client = RegistryClient(
        ORIGIN,
        transport=httpx.MockTransport(transport),
        domain_registry_resolver=forbidden_discovery,
    )

    def signer(context):
        assert context.registry_origin == ORIGIN
        return KEY, SigningKey(SEED).sign(context.signing_bytes()).signature

    try:
        with pytest.raises(Captured):
            await client.controller_request(
                request(), controllers={"controller": CONTROLLER}, signer=signer
            )
    finally:
        await client.aclose()
    assert len(sent) == 1
    assert str(sent[0].url) == ORIGIN + "/v1/namespaces/example.com/teams"
    # The bytes sent are the bytes signed.
    assert sent[0].content == canonical_json_bytes(request().parameters)
    signed = base64.urlsafe_b64decode(sent[0].headers["x-aweb-signed-payload"] + "==")
    assert (
        json.loads(signed)["body_sha256"] == hashlib.sha256(sent[0].content).hexdigest()
    )
    assert json.loads(signed)["aud"] == ORIGIN


@pytest.mark.asyncio
async def test_bad_signature_and_missing_role_refuse_before_transport():
    async def transport(outgoing):
        pytest.fail("a local refusal must send nothing")

    client = RegistryClient(ORIGIN, transport=httpx.MockTransport(transport))
    try:
        for controllers in ({}, {"controller": CONTROLLER}):
            with pytest.raises(ControllerSigningError):
                await client.controller_request(
                    request(),
                    controllers=controllers,
                    signer=lambda ctx: (KEY, bytes(64)),
                )
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_lost_mutation_answer_is_ambiguous_and_never_retried():
    from awid.controller_signing import ControllerRequestUncertain

    sent = []

    async def transport(outgoing):
        sent.append(outgoing)
        raise httpx.ReadError("lost answer")

    client = RegistryClient(ORIGIN, transport=httpx.MockTransport(transport))
    req = request()
    try:
        with pytest.raises(ControllerRequestUncertain) as failure:
            await client.controller_request(
                req,
                controllers={"controller": CONTROLLER},
                signer=lambda ctx: (
                    KEY,
                    SigningKey(SEED).sign(ctx.signing_bytes()).signature,
                ),
            )
        assert failure.value.request_digest == req.digest
        assert failure.value.operation == req.operation
    finally:
        await client.aclose()
    assert len(sent) == 1


def test_parent_role_keeps_its_distinct_proof_and_domain():
    child = ControllerDescriptor("namespace", "child.example.com", NEW_KEY, "child", 0)
    req = parse_controller_request(
        {
            "operation": "namespace_register",
            "domain": child.domain,
            "controller_did": NEW_KEY,
            "parent_domain": "example.com",
        }
    )
    assert payload(req, CONTROLLER, "parent") == covering_payload(
        aud=ORIGIN,
        method="POST",
        path="/v1/namespaces",
        domain=child.domain,
        operation="authorize_subdomain_registration",
        body=canonical_json_bytes({"domain": child.domain, "controller_did": NEW_KEY}),
        timestamp=TS,
        claims={"child_domain": child.domain, "controller_did": NEW_KEY},
    )
    with pytest.raises(ControllerSigningError, match="controller_scope"):
        payload(req, child, "parent")


@pytest.mark.asyncio
async def test_atomic_claim_checks_subject_proof_before_controller_signature():
    from awid.atomic_claim import (
        AtomicAddressClaimFields,
        atomic_address_claim_identity_canonical,
        atomic_address_claim_identity_proof_hash,
        atomic_address_claim_namespace_canonical,
    )
    from awid.did import stable_id_from_did_key
    from awid.signing import sign_message

    f = AtomicAddressClaimFields(
        "claim_identity_address",
        "example.com",
        "person",
        stable_id_from_did_key(NEW_KEY),
        NEW_KEY,
        ORIGIN,
        TS,
        False,
        "self",
        "self",
    )
    proof = sign_message(NEW_SEED, atomic_address_claim_identity_canonical(f))
    fields = {
        "operation": "address_claim_proof",
        "domain": "example.com",
        "address_name": "person",
        "did_aw": f.did_aw,
        "current_did_key": NEW_KEY,
        "timestamp": TS,
        "dry_run": False,
        "identity_custody": "self",
        "namespace_custody": "self",
        "identity_signature": proof,
    }
    seen = []

    def signer(context):
        seen.append(context)
        expected = atomic_address_claim_namespace_canonical(
            f,
            atomic_address_claim_identity_proof_hash(
                atomic_address_claim_identity_canonical(f), proof
            ),
        )
        assert context.signing_bytes() == expected
        return KEY, SigningKey(SEED).sign(expected).signature

    await sign_controller_object(
        parse_controller_object(fields),
        controller=CONTROLLER,
        signer=signer,
        registry_origin=ORIGIN,
    )
    assert len(seen) == 1

    with pytest.raises(ValueError):
        await sign_controller_object(
            parse_controller_object({**fields, "dry_run": True}),
            controller=CONTROLLER,
            signer=signer,
            registry_origin=ORIGIN,
        )
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_upper_case_member_alias_survives_issue_register_and_member_read():
    team = ControllerDescriptor("team", "example.com", KEY, "team", 0, team="team")
    c = {
        "version": 1,
        "certificate_id": "00000000-0000-4000-8000-000000000001",
        "team_id": "team:example.com",
        "team_did_key": KEY,
        "member_did_key": NEW_KEY,
        "alias": "Member_One",
        "identity_scope": "local",
        "issued_at": TS,
    }
    artifact = await sign_controller_object(
        parse_controller_object(
            {
                "operation": "team_certificate_issue",
                "domain": "example.com",
                "name": "team",
                "certificate": c,
            }
        ),
        controller=team,
        signer=lambda ctx: (KEY, SigningKey(SEED).sign(ctx.signing_bytes()).signature),
    )
    registered = controller_http_plan(
        request(
            "certificate_register",
            name="team",
            certificate=artifact["encoded_certificate"],
        )
    )
    assert json.loads(registered.body)["alias"] == "Member_One"
    read = controller_http_plan(request("member_read", name="team", alias="Member_One"))
    assert read.path.endswith("/members/Member_One")


@pytest.mark.parametrize(
    "operation",
    ["address_register", "address_update", "address_delete", "address_reassign"],
)
@pytest.mark.parametrize(
    "name", ["Member_One", "Person.Name+tag", "A" * 256, "A B/?#%"]
)
def test_address_names_keep_registry_acceptance_and_stay_one_encoded_segment(
    operation, name
):
    from urllib.parse import unquote

    fields = {"name": name}
    if operation in ("address_register", "address_reassign"):
        fields.update(
            did_aw="did:aw:2Uq51iFVLnqmgbVY3vLZtMD5PR87", current_did_key=NEW_KEY
        )
    plan = controller_http_plan(request(operation, **fields))
    if operation == "address_register":
        assert json.loads(plan.body)["name"] == name
    else:
        segment = plan.path.removesuffix("/reassign").rsplit("/", 1)[-1]
        assert unquote(segment) == name
        assert "?" not in segment and "#" not in segment


@pytest.mark.asyncio
@pytest.mark.parametrize("answer", [500, 502, 504, "late_2xx", 401, 403, 409, 429])
async def test_real_http_failure_and_budget_answers_keep_honest_write_outcomes(
    answer, monkeypatch
):
    """HTTP error producer only; the native control separately proves a commit."""
    import awid.registry as registry
    from awid.controller_signing import ControllerRequestUncertain
    from awid.registry import RegistryError

    clock = [0.0]
    if answer == "late_2xx":
        monkeypatch.setattr(registry, "_read_retry_now", lambda: clock[0])
    calls = []

    async def respond(reader, writer):
        headers = await reader.readuntil(b"\r\n\r\n")
        calls.append(headers.split(b"\r\n", 1)[0])
        status = 200 if answer == "late_2xx" else answer
        if answer == "late_2xx":
            clock[0] = 2.0
        body = b"{}"
        writer.write(
            f"HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n".encode()
            + body
        )
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(respond, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    client = RegistryClient(f"http://127.0.0.1:{port}", timeout_seconds=1)
    req = request("team_delete", name="team")
    try:
        expected = (
            ControllerRequestUncertain
            if answer == "late_2xx" or answer >= 500
            else RegistryError
        )
        with pytest.raises(expected) as failure:
            await client.controller_request(
                req,
                controllers={"controller": CONTROLLER},
                signer=lambda ctx: (
                    KEY,
                    SigningKey(SEED).sign(ctx.signing_bytes()).signature,
                ),
            )
        if expected is RegistryError:
            assert type(failure.value) is RegistryError
            assert failure.value.status_code == answer
        else:
            assert failure.value.operation == "team_delete"
            assert failure.value.request_digest == req.digest
        assert calls == [b"DELETE /v1/namespaces/example.com/teams/team HTTP/1.1"]
    finally:
        await client.aclose()
        server.close()
        await server.wait_closed()
