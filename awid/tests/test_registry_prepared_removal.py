"""Prepared removal sends only an exact existing controller revocation proof."""

import base64
from contextlib import aclosing
from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from nacl.signing import SigningKey
from starlette.requests import Request

from awid.controller_request import verify_controller_json_request
from awid.did import did_from_public_key
from awid.id_tree_requests import covering_payload
from awid.registry import RegistryClient, RegistryError
from awid.signing import canonical_json_bytes

DOMAIN, TEAM, ORIGIN = "customer.example", "engineering", "https://registry.customer.example"


def proof(*, changed=None):
    key = SigningKey.generate()
    certificate_id = str(uuid4())
    claims = {"team_name": TEAM, "certificate_id": certificate_id, **(changed or {})}
    raw = covering_payload(aud=ORIGIN, path=f"/v1/namespaces/{DOMAIN}/teams/{TEAM}/certificates/revoke",
        domain=DOMAIN, operation="revoke_certificate", body=canonical_json_bytes({"certificate_id": certificate_id}),
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), claims=claims)
    return dict(certificate_id=certificate_id, controller_did=did_from_public_key(bytes(key.verify_key)),
        signing=raw, signature=key.sign(raw).signature)


@pytest.mark.asyncio
async def test_a_prepared_revocation_passes_the_actual_registry_controller_verifier():
    selected = proof()
    calls = []

    async def upstream(request):
        calls.append(request)
        async def receive():
            return {"type": "http.request", "body": request.content, "more_body": False}
        scope = {"type": "http", "method": request.method, "path": request.url.path,
            "raw_path": request.url.raw_path, "query_string": b"", "headers": [(k.lower(), v) for k, v in request.headers.raw],
            "app": SimpleNamespace(state=SimpleNamespace(awid_public_origins=(ORIGIN,)))}
        issuer = await verify_controller_json_request(Request(scope, receive), payload_dict={"domain": DOMAIN,
            "operation": "revoke_certificate", "team_name": TEAM, "certificate_id": selected["certificate_id"]})
        assert issuer == selected["controller_did"]
        assert request.content == canonical_json_bytes({"certificate_id": selected["certificate_id"]})
        assert base64.urlsafe_b64decode(request.headers["X-AWEB-Signed-Payload"] + "=" * (-len(request.headers["X-AWEB-Signed-Payload"]) % 4)) == selected["signing"]
        return httpx.Response(200, json={"revoked": True, "certificate_id": selected["certificate_id"]})

    async with aclosing(RegistryClient(registry_url=ORIGIN, transport=httpx.MockTransport(upstream))) as client:
        await client.revoke_team_certificate_with_proof(DOMAIN, TEAM, **selected)
    assert len(calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["certificate", "key", "signature", "body", "extra"])
async def test_a_prepared_removal_never_transports_another_target_or_invalid_proof(change):
    selected = proof(changed={"unexpected": "member"}) if change == "extra" else proof()
    if change == "certificate":
        selected["certificate_id"] = str(uuid4())
    elif change == "key":
        selected["controller_did"] = proof()["controller_did"]
    elif change == "signature":
        selected["signature"] = b"x" * 64
    elif change == "body":
        selected["signing"] += b" "
    def upstream(request):
        raise AssertionError("an invalid prepared proof must send nothing")
    async with aclosing(RegistryClient(registry_url=ORIGIN, transport=httpx.MockTransport(upstream))) as client:
        with pytest.raises(ValueError):
            await client.revoke_team_certificate_with_proof(DOMAIN, TEAM, **selected)


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [429, 503])
async def test_a_prepared_revocation_is_one_attempt_even_when_the_answer_is_unavailable(status):
    calls = []
    def upstream(request):
        calls.append(request)
        return httpx.Response(status, json={"detail": "unavailable"}, headers={"Retry-After": "1"})
    async with aclosing(RegistryClient(registry_url=ORIGIN, transport=httpx.MockTransport(upstream))) as client:
        with pytest.raises(RegistryError) as caught:
            await client.revoke_team_certificate_with_proof(DOMAIN, TEAM, **proof())
        assert caught.value.status_code == status
    assert len(calls) == 1
