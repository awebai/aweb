"""Typed controller boundary: real signatures and existing wire canonicalizers."""

import base64
import copy
import json

import pytest
from nacl.signing import SigningKey

from awid.controller_signing import (
    ControllerDescriptor,
    ControllerSigningError,
    build_controller_payload,
    parse_controller_object,
    parse_controller_request,
    sign_controller_object,
)
from awid.did import did_key_from_signing_key
from awid.id_certificates import id_certificate_signing_bytes, verify_id_certificate
from awid.id_tree_requests import covering_payload, rotate_body, rotate_claims
from awid.signing import canonical_json_bytes

SEED = bytes(range(32))
KEY = did_key_from_signing_key(SEED)
NEW_SEED = bytes(range(1, 33))
NEW_KEY = did_key_from_signing_key(NEW_SEED)
TS = "2026-11-16T00:00:00Z"
ORIGIN = "https://registry.example"
CONTROLLER = ControllerDescriptor("namespace", "example.com", KEY, "namespace-1", 3)


def request(operation="team_register", **parameters):
    if operation == "team_register":
        parameters = {"name": "team", "display_name": "Team", "team_did_key": NEW_KEY,
                      "visibility": "private", **parameters}
    return parse_controller_request({"operation": operation, "domain": "example.com", **parameters})


def payload(req, controller=CONTROLLER, role="controller"):
    return build_controller_payload(req, controller=controller, role=role,
                                    timestamp=TS, registry_origin=ORIGIN)


def test_legacy_team_bytes_are_existing_claims_not_a_body_or_audience_claim():
    assert payload(request()) == canonical_json_bytes({
        "domain": "example.com", "operation": "create_team", "name": "team", "timestamp": TS,
    })


@pytest.mark.parametrize("fields", [
    {"operation": "sign", "domain": "example.com", "payload": "anything"},
    {"operation": "team_register", "domain": "example.com", "path": "/arbitrary"},
    {"operation": "namespace_delete", "domain": "example.com/elsewhere"},
    {"operation": "namespace_delete", "domain": ".."},
    {"operation": "namespace_delete", "domain": "EXAMPLE.COM"},
    {"operation": "team_delete", "domain": "example.com", "name": "../x"},
    {"operation": "team_visibility", "domain": "example.com", "name": "t", "visibility": "hidden"},
])
def test_untyped_or_unshaped_operation_refuses(fields):
    with pytest.raises(ControllerSigningError):
        parse_controller_request(fields)


def test_request_freezes_nested_input_and_returns_detached_parameters():
    fields = {"operation": "team_rotate", "domain": "example.com", "name": "team",
              "new_team_did_key": NEW_KEY, "resigned_records": {"team_custodians": []}}
    req = parse_controller_request(fields)
    before = req.parameters
    fields["resigned_records"]["team_custodians"].append({"untrusted": True})
    req.parameters["resigned_records"]["team_custodians"].append({"also": "detached"})
    assert req.parameters == before


def test_continuity_keeps_distinct_old_new_roles_and_current_epoch():
    req = request("namespace_rotate", from_seq=2, previous_did_key=KEY, new_did_key=NEW_KEY)
    claims = rotate_claims(from_seq=2, previous_did_key=KEY, new_did_key=NEW_KEY)
    want = covering_payload(aud=ORIGIN, path="/v1/namespaces/example.com/rotate",
                            domain="example.com", operation="rotate_namespace_controller",
                            body=rotate_body("example.com", claims), timestamp=TS, claims=claims)
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
    return parse_controller_object({
        "operation": "namespace_id_issue", "domain": "example.com", "kind": kind,
        "certificate": {"v": 1, "type": "aweb.id-certificate",
                        "id": "did:aw:2Uq51iFVLnqmgbVY3vLZtMD5PR87", "domain": "example.com",
                        "parent": {"kind": "namespace", "id": "example.com"},
                        "kind": "human", "issuer_key": KEY, "issued_at": TS},
    })


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
    assert seen[0].signing_bytes() == id_certificate_signing_bytes(result["certificate"])


def test_agent_request_cannot_issue_a_human_certificate():
    with pytest.raises(ControllerSigningError, match="object_invalid"):
        id_request("agent")


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ["key", "signature", "shape"])
async def test_wrong_signer_answer_returns_no_artifact(fault):
    def signer(context):
        if fault == "shape":
            return b"not a typed answer"
        return (NEW_KEY if fault == "key" else KEY,
                SigningKey(NEW_SEED).sign(context.signing_bytes()).signature)

    with pytest.raises(ControllerSigningError, match="signer_answer"):
        await sign_controller_object(id_request(), controller=CONTROLLER, signer=signer)


@pytest.mark.asyncio
async def test_replacement_is_an_application_object_with_exact_existing_bytes():
    fields = {"address": "example.com/person", "controller_did": KEY,
              "old_did": KEY, "new_did": NEW_KEY, "timestamp": TS}
    req = parse_controller_object({"operation": "address_replacement", "domain": "example.com", **fields})

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
