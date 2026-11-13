"""Prepare availability on the real mount, without a database or effect.

Only the limiter and provisioned requester-key port are supplied here. The
SDK verifies the actual covering proof; registry/current authority and B2/B3
execution are separately qualified native boundaries, not claims of this test.
"""

import base64
import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType, SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from awid.did import did_from_public_key, stable_id_from_public_key
from awid.protected_request import verify_protected_request
from awid.signing import canonical_json_bytes, sign_message
from fastapi import FastAPI
from nacl.signing import SigningKey

from aweb_naapp.runtime.protected_signer import ProtectedKeyContext, ProtectedSigner, RestrictedRequester
from aweb_naapp.runtime.protected_signer import catalog
from aweb_naapp.runtime.protected_signer.http import ProtectedOperationsHTTP

CASES = json.loads((Path(__file__).resolve().parents[3] / "docs/vectors/protected-operation-availability-v1.json").read_bytes())["scenarios"]
ORIGIN = "https://request.example"


class NoStore:
    def __getattr__(self, name):
        raise AssertionError("unserved prepare must not access the operation store: " + name)


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
async def test_prepare_availability_before_any_pending_state(case, monkeypatch):
    root, human, child = [SigningKey.generate() for _ in range(3)]
    root_id = stable_id_from_public_key(bytes(root.verify_key))
    human_id = stable_id_from_public_key(bytes(human.verify_key))
    key = did_from_public_key(bytes(root.verify_key))
    context = ProtectedKeyContext("service", "team_controller", "team:example.org", "example.org", human_id, "example.org", 1)
    body = {"operation_id": str(uuid4()), "operation": "human-role.revoke", "variant": "default",
        "scope": context.fields(), "audience": "https://registry.example",
        "subject": {"app_id": "app", "installation_id": str(uuid4()), "role": "app.owner", "principal": human_id}}
    if case["change"].get("operation") == "team.agent.admit":
        body["subject"] = {"team_id": context.authority_id, "root_id": root_id, "root_key": key,
            "child_id": None, "child_key": did_from_public_key(bytes(child.verify_key)), "member_alias": "child",
            "admission_policy_digest": "sha256:" + "0" * 64, "expected_policy_version": 1}
    body.update(case["change"])
    if case.get("disable_definition"):
        definitions = dict(catalog.OPERATIONS)
        definitions[(body["operation"], body["variant"])] = replace(
            definitions[(body["operation"], body["variant"])], consumer_available=False)
        monkeypatch.setattr(catalog, "OPERATIONS", MappingProxyType(definitions))

    signer = object.__new__(ProtectedSigner)
    signer.db, signer.admission, signer.custody = NoStore(), None, NoStore()
    signer.passkeys = SimpleNamespace(rp=SimpleNamespace(origin="https://human.example"))
    checks = []

    async def requester(request, operation):
        actual = await verify_protected_request(request, operation="protected_operation_prepare",
            request_origin=ORIGIN, service_id=context.service_id, domain=context.authority_domain, scope=context.fields())
        assert actual == key
        checks.append(actual)
        return RestrictedRequester(root_id, context)

    async def reader(*args):
        raise AssertionError("prepare must not read a receipt")

    class Limiter:
        async def admit(self, *args, **kwargs):
            pass

    app = FastAPI()
    app.include_router(ProtectedOperationsHTTP(signer, request_origin=ORIGIN, requester=requester,
        reader=reader, limiter=Limiter()).api_router())
    raw = canonical_json_bytes(body)
    stamp = datetime.now(UTC).isoformat()
    proof = canonical_json_bytes({"v": 2, "type": "aweb.awid-controller-request", "aud": ORIGIN,
        "operation": "protected_operation_prepare", "domain": context.authority_domain, "timestamp": stamp,
        "method": "POST", "path": "/protected-operations", "body_sha256": hashlib.sha256(raw).hexdigest(),
        "service_id": context.service_id, "scope_sha256": hashlib.sha256(canonical_json_bytes(context.fields())).hexdigest()})
    headers = {"Content-Type": "application/json", "Authorization": f"DIDKey {key} {sign_message(bytes(root), proof)}",
        "X-AWEB-Timestamp": stamp, "X-AWEB-Signed-Payload": base64.urlsafe_b64encode(proof).rstrip(b"=").decode()}
    if case.get("host"):
        headers["Host"] = case["host"]
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN) as client:
        response = await client.post("/protected-operations", content=raw, headers=headers)
    assert response.status_code == case["expected"]["status"], response.text
    assert response.json() == {"detail": case["expected"]["detail"]}
    assert len(checks) == case["expected"]["requester_checks"]
