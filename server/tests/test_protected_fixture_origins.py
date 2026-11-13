"""A real requester proof follows the fixture's selected external origin."""

import base64
import json
from types import SimpleNamespace

import pytest
from aweb_naapp.runtime.protected_signer import ProtectedKeyContext
from nacl.signing import SigningKey

from tests.test_independent_protected_signer import DOMAIN, ORIGIN, SERVICE, TEAM, did, proof_request


@pytest.mark.parametrize("origin", [ORIGIN, "http://127.0.0.1:31415"])
def test_request_proof_uses_the_worlds_external_origin(origin):
    key = SigningKey.generate()
    context = ProtectedKeyContext(SERVICE, "team_controller", TEAM, DOMAIN, "did:aw:human", DOMAIN, 1)
    world = SimpleNamespace(root=key, context=context, request_origin=origin)
    request = proof_request(world, body=b"{}")
    encoded = request.headers["x-aweb-signed-payload"]
    raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    assert json.loads(raw)["aud"] == origin
    scheme, issuer, signature = request.headers["authorization"].split()
    assert scheme == "DIDKey" and issuer == did(key)
    key.verify_key.verify(raw, base64.b64decode(signature + "=" * (-len(signature) % 4)))


@pytest.mark.asyncio
async def test_policy_read_fixture_signs_the_minimal_scope_and_exact_query():
    from awid.protected_request import verify_protected_request
    from starlette.requests import Request

    from tests.test_protected_admission_native import headers

    key = SigningKey.generate()
    context = ProtectedKeyContext(SERVICE, "team_controller", TEAM, DOMAIN, "did:aw:human", DOMAIN, 1)
    world = SimpleNamespace(root=key, root_id="did:aw:root", context=context, request_origin=ORIGIN)
    path = "/protected-admission-policies?team_id=" + TEAM.replace(":", "%3A")
    values = headers(SimpleNamespace(w=world), path=path, method="GET", label="protected_admission_policy_read")

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    route, _, query = path.partition("?")
    request = Request({"type": "http", "method": "GET", "path": route, "raw_path": route.encode(),
        "query_string": query.encode(), "headers": [(k.lower().encode(), v.encode()) for k, v in values.items()]}, receive)
    assert await verify_protected_request(request, operation="protected_admission_policy_read", request_origin=ORIGIN,
        service_id=SERVICE, domain=DOMAIN, scope={"service_id": SERVICE, "team_id": TEAM}) == did(key)


@pytest.mark.asyncio
async def test_the_native_proof_helper_distinguishes_prepare_and_valid_execute():
    from awid.protected_request import verify_protected_request
    from fastapi import HTTPException

    key = SigningKey.generate()
    context = ProtectedKeyContext(SERVICE, "team_controller", TEAM, DOMAIN, "did:aw:human", DOMAIN, 1)
    world = SimpleNamespace(root=key, context=context, request_origin=ORIGIN)
    arguments = dict(operation="protected_operation_execute", request_origin=ORIGIN, service_id=SERVICE,
        domain=DOMAIN, scope=context.fields())
    with pytest.raises(HTTPException) as rejected:
        await verify_protected_request(proof_request(world), **arguments)
    assert rejected.value.status_code == 401
    request = proof_request(world, operation="protected_operation_execute", path="/protected-operations/operation/execute", body=b"")
    assert await verify_protected_request(request, **arguments) == did(key)
