"""Real customer registry/PG proof of root and exact-member removal.

Native bodies run only through the authorized VM lane. Shared helpers build
the same supported bootstrap, live root endorsement and bounded admission.
"""

import asyncio
import base64
import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from aweb_naapp.runtime.protected_signer import CatalogOperation, SignerRefused
from awid.signing import canonical_json_bytes, sign_message
from awid.registry_types import RegistryError
from nacl.signing import SigningKey

from tests.test_independent_protected_signer import DOMAIN, TEAM, did
from tests.test_protected_admission_native import (
    admission_world,
    admit_operation,
    endorse,
    execute,
    headers,
    prepare,
)

pytest_plugins = ("tests.test_protected_admission_native",)


def removal(a, certificate, *, self_remove=False, **changes):
    subject = {"team_id": TEAM,
        "root_id_or_self": "self" if self_remove else a.w.root_id,
        "member_id": certificate.get("member_did_aw") or certificate["member_did_key"],
        "certificate_id": certificate["certificate_id"],
        "expected_membership": {field: certificate.get(field) for field in (
            "member_did_key", "member_did_aw", "member_address", "alias", "identity_scope")}, **changes}
    return CatalogOperation(str(uuid4()), a.w.context, a.w.registry.registry_url,
        "team.agent.remove", "default", subject)


async def admitted(a, *, registered=False):
    key = SigningKey.generate()
    child = (await a.w.registry.register_did(did(key), bytes(key))).did_aw if registered else None
    operation = admit_operation(a, child_id=child, child_key=did(key))
    assert (await prepare(a, operation)).status_code == 200
    response = await execute(a, operation)
    assert response.status_code == 200 and response.json()["state"] == "committed", response.text
    result = response.json()["result"]
    certificate = json.loads(base64.b64decode(result["signing"], validate=True))
    certificate["signature"] = base64.b64encode(base64.b64decode(result["signature"], validate=True)).rstrip(b"=").decode()
    return key, certificate


def self_headers(a, key, certificate, operation, *, body=b"", purpose="prepare", envelope_changes=None):
    path = "/protected-operations" if purpose == "prepare" else "/protected-operations/" + operation.operation_id
    if purpose == "execute":
        path += "/execute"
    method = "GET" if purpose == "receipt" else "POST"
    stamp = datetime.now(UTC).isoformat()
    payload = {"v": 2, "aud": a.w.request_origin, "method": method, "path": path, "team_id": TEAM,
        "timestamp": stamp, "body_sha256": hashlib.sha256(body).hexdigest(),
        "operation": "protected_operation_" + purpose, "service_id": operation.context.service_id,
        "scope_sha256": hashlib.sha256(canonical_json_bytes(operation.context.fields())).hexdigest(),
        **(envelope_changes or {})}
    raw = canonical_json_bytes(payload)
    return path, {"Authorization": f"DIDKey {did(key)} {sign_message(bytes(key), raw)}",
        "X-AWEB-Timestamp": stamp, "X-AWEB-Signed-Payload": base64.urlsafe_b64encode(raw).rstrip(b"=").decode(),
        "X-AWID-Team-Certificate": base64.b64encode(canonical_json_bytes(certificate)).decode(),
        "Content-Type": "application/json"}


async def self_call(a, key, certificate, operation, *, purpose="prepare", envelope_changes=None, extra_headers=None):
    body = canonical_json_bytes(operation.intent()) if purpose == "prepare" else b""
    path, proof = self_headers(a, key, certificate, operation, body=body, purpose=purpose, envelope_changes=envelope_changes)
    proof.update(extra_headers or {})
    return await a.client.request("GET" if purpose == "receipt" else "POST", path, content=body, headers=proof)


async def signature_count(a, operation):
    return await a.w.db.fetch_value("SELECT count(*) FROM {{tables.protected_local_audit}} "
        "WHERE kind='protected_operation_signed' AND subject=$1", operation.operation_id)


@pytest.mark.asyncio
async def test_root_removal_releases_active_capacity_only_after_actual_registry_confirmation(world, tmp_path):
    async with admission_world(world, tmp_path, bounds={"max_active": 2, "rate_window_seconds": 3600, "max_per_window": 10}) as a:
        await endorse(a)
        _, first = await admitted(a)
        await admitted(a)
        full = admit_operation(a)
        assert (await prepare(a, full)).status_code == 200
        assert (await execute(a, full)).json() == {"state": "refused", "code": "admission_limit_reached"}
        operation = removal(a, first)
        response = await prepare(a, operation)
        assert response.status_code == 200, response.text
        frozen = response.json()
        assert frozen["payload"]["request"]["requester_key"] == did(a.w.root)
        artifact = frozen["payload"]["request"]["artifact"]
        assert set(artifact) == {"controller_did", "request"}
        assert artifact["request"]["operation"] == "revoke_certificate"
        result = await execute(a, operation)
        assert result.status_code == 200 and result.json()["state"] == "committed", result.text
        records = await a.w.registry.list_team_certificates_fresh(DOMAIN, "engineering", active_only=False)
        assert next(r for r in records if r.certificate_id == first["certificate_id"]).revoked_at is not None
        assert await a.w.db.fetch_value("SELECT state FROM {{tables.protected_root_admissions}} WHERE certificate_id=$1", first["certificate_id"]) == "removed"
        assert (await prepare(a, operation)).json() == frozen
        assert (await execute(a, operation)).json() == result.json()
        assert await signature_count(a, operation) == 1
        # Change a valid field under the owned UUID; ingress still verifies the original root.
        changed = removal(a, first, expected_membership={**operation.intent()["subject"]["expected_membership"], "alias": "changed"})
        changed = replace(changed, operation_id=operation.operation_id)
        assert (await prepare(a, changed)).status_code == 409
        await admitted(a)
        # Removal never erases admission history (the finite rate bucket).
        assert await a.w.db.fetch_value("SELECT count(*) FROM {{tables.protected_root_admissions}}") == 3
        assert await a.w.db.fetch_value("SELECT count(*) FROM {{tables.protected_local_audit}} WHERE kind='protected_member_removed' AND subject=$1", operation.operation_id) == 1


@pytest.mark.asyncio
async def test_removal_does_not_reset_the_roots_rate_history(admissions):
    a = admissions
    await endorse(a)
    _, first = await admitted(a)
    await admitted(a)
    operation = removal(a, first)
    assert (await prepare(a, operation)).status_code == 200
    assert (await execute(a, operation)).json()["state"] == "committed"
    third = admit_operation(a)
    assert (await prepare(a, third)).status_code == 200
    assert (await execute(a, third)).json() == {"state": "refused", "code": "admission_limit_reached"}


@pytest.mark.asyncio
@pytest.mark.parametrize("registered", [False, True])
async def test_exact_self_member_can_leave_without_a_root_requester_grant(admissions, registered):
    a = admissions
    await endorse(a)
    key, certificate = await admitted(a, registered=registered)
    operation = removal(a, certificate, self_remove=True)
    assert not await a.w.db.fetch_value("SELECT EXISTS(SELECT 1 FROM {{tables.protected_requester_bindings}} WHERE principal=$1)", operation.intent()["subject"]["member_id"])
    prepared = await self_call(a, key, certificate, operation)
    assert prepared.status_code == 200, prepared.text
    result = await self_call(a, key, certificate, operation, purpose="execute")
    assert result.status_code == 200 and result.json()["state"] == "committed", result.text
    # Revoked membership authorizes only this original owned recovery path.
    assert (await self_call(a, key, certificate, operation, purpose="receipt")).json() == result.json()
    assert (await self_call(a, key, certificate, operation)).json() == prepared.json()
    assert (await self_call(a, key, certificate, operation, purpose="execute")).json() == result.json()
    new = replace(operation, operation_id=str(uuid4()))
    assert (await self_call(a, key, certificate, new)).status_code == 403
    assert await signature_count(a, operation) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("change", [
    {"v": 1}, {"aud": "https://other.example"}, {"operation": "protected_operation_execute"},
    {"scope_sha256": "0" * 64}, {"service_id": "other"}, {"team_id": "other:customer.example"},
    {"body_sha256": "0" * 64}, {"extra": "not permitted"},
])
async def test_self_proof_refuses_other_envelopes_without_creating_an_operation(admissions, change):
    a = admissions
    await endorse(a)
    key, certificate = await admitted(a)
    operation = removal(a, certificate, self_remove=True)
    response = await self_call(a, key, certificate, operation, envelope_changes=change)
    assert response.status_code in {401, 403}, response.text
    assert await a.w.app.signer.lookup_context(operation.operation_id) is None
    assert await signature_count(a, operation) == 0


@pytest.mark.asyncio
async def test_self_proof_cannot_remove_a_neighbour_or_mix_a_root_credential(admissions):
    a = admissions
    await endorse(a)
    key, certificate = await admitted(a)
    _, neighbour = await admitted(a)
    operation = removal(a, neighbour, self_remove=True)
    assert (await self_call(a, key, certificate, operation)).status_code == 403
    own = removal(a, certificate, self_remove=True)
    assert (await self_call(a, key, certificate, own, extra_headers={"X-AWEB-DID-AW": a.w.root_id})).status_code in {401, 403}
    assert await a.w.app.signer.lookup_context(own.operation_id) is None


@pytest.mark.asyncio
async def test_lost_revocation_answer_keeps_capacity_until_read_reconciliation_and_never_replays(admissions, monkeypatch):
    a = admissions
    await endorse(a)
    key, certificate = await admitted(a)
    operation = removal(a, certificate, self_remove=True)
    custody = a.w.app.authority.custody
    original, attempts = custody.remove_member, []

    async def lost(*args):
        attempts.append(1)
        await original(*args)  # Actual registry mutation commits before the answer is dropped.
        raise SignerRefused("receipt_unavailable")

    monkeypatch.setattr(custody, "remove_member", lost)
    assert (await self_call(a, key, certificate, operation)).status_code == 200
    assert (await self_call(a, key, certificate, operation, purpose="execute")).status_code == 503
    assert await a.w.db.fetch_value("SELECT state FROM {{tables.protected_root_admissions}} WHERE certificate_id=$1", certificate["certificate_id"]) == "active"
    receipt = await self_call(a, key, certificate, operation, purpose="receipt")
    assert receipt.status_code == 200 and receipt.json()["state"] == "committed", receipt.text
    assert await a.w.db.fetch_value("SELECT state FROM {{tables.protected_root_admissions}} WHERE certificate_id=$1", certificate["certificate_id"]) == "removed"
    assert (await self_call(a, key, certificate, operation, purpose="execute")).json() == receipt.json()
    assert attempts == [1] and await signature_count(a, operation) == 1


@pytest.mark.asyncio
async def test_root_and_self_concurrent_removal_do_not_free_or_charge_the_bucket_twice(admissions, monkeypatch):
    a = admissions
    await endorse(a)
    key, certificate = await admitted(a)
    root, own = removal(a, certificate), removal(a, certificate, self_remove=True)
    assert (await prepare(a, root)).status_code == 200
    assert (await self_call(a, key, certificate, own)).status_code == 200
    frozen = {op.operation_id: await a.w.db.fetch_one(
        "SELECT intent,expires_at FROM {{tables.protected_signer_operations}} WHERE operation_id=$1", op.operation_id)
        for op in (root, own)}
    custody = a.w.app.authority.custody
    original, entered, attempts, registry_answers = custody.remove_member, asyncio.Event(), [], []

    async def overlap(registry, operation, artifact, result):
        attempts.append(operation.operation_id)
        if len(attempts) == 2:
            entered.set()
        # Both have observed the active record and retained their own signature
        # and delivery claim before either real registry mutation is released.
        await entered.wait()
        try:
            await original(registry, operation, artifact, result)
            registry_answers.append(200)
        except RegistryError as error:
            registry_answers.append(error.status_code)
            raise

    monkeypatch.setattr(custody, "remove_member", overlap)
    responses = await asyncio.wait_for(asyncio.gather(
        execute(a, root), self_call(a, key, certificate, own, purpose="execute")), timeout=30)
    assert sorted(registry_answers) == [200, 409]
    assert sorted(response.status_code for response in responses) == [200, 503]
    for operation, response in zip((root, own), responses, strict=True):
        if response.status_code == 503:
            if operation is own:
                response = await self_call(a, key, certificate, own, purpose="receipt")
            else:
                path = "/protected-operations/" + root.operation_id
                response = await a.client.get(path, headers=headers(a, path=path, method="GET", label="protected_operation_receipt"))
        assert response.status_code == 200 and response.json()["state"] == "committed", response.text
        assert await signature_count(a, operation) == 1
        retained = await a.w.db.fetch_one(
            "SELECT intent,expires_at FROM {{tables.protected_signer_operations}} WHERE operation_id=$1", operation.operation_id)
        assert retained == frozen[operation.operation_id]
    assert sorted(attempts) == sorted([root.operation_id, own.operation_id])
    records = await a.w.registry.list_team_certificates_fresh(DOMAIN, "engineering", active_only=False)
    assert next(r for r in records if r.certificate_id == certificate["certificate_id"]).revoked_at is not None
    assert await a.w.db.fetch_value("SELECT count(*) FROM {{tables.protected_root_admissions}} WHERE state='removed'") == 1
    assert await a.w.db.fetch_value("SELECT count(*) FROM {{tables.protected_root_admissions}}") == 1


@pytest.mark.asyncio
async def test_changed_binding_policy_refuses_removal_without_releasing_capacity(admissions):
    a = admissions
    await endorse(a)
    _, certificate = await admitted(a)
    operation = removal(a, certificate)
    assert (await prepare(a, operation)).status_code == 200
    await a.w.db.execute("UPDATE {{tables.protected_authorizer_bindings}} SET policy_version=policy_version+1")
    result = await execute(a, operation)
    assert result.status_code == 200 and result.json() == {"state": "refused", "code": "policy_changed"}, result.text
    assert await signature_count(a, operation) == 0
    assert await a.w.db.fetch_value("SELECT state FROM {{tables.protected_root_admissions}} WHERE certificate_id=$1", certificate["certificate_id"]) == "active"


@pytest.mark.asyncio
async def test_self_read_proof_cannot_read_another_members_receipt_or_admission_policy(admissions):
    a = admissions
    await endorse(a)
    key, certificate = await admitted(a)
    _, neighbour = await admitted(a)
    other = removal(a, neighbour)
    assert (await prepare(a, other)).status_code == 200
    response = await self_call(a, key, certificate, other, purpose="receipt")
    assert response.status_code in {401, 403}
    _, proof = self_headers(a, key, certificate, removal(a, certificate, self_remove=True), purpose="receipt")
    response = await a.client.get("/protected-admission-policies?team_id=" + TEAM.replace(":", "%3A"), headers=proof)
    assert response.status_code in {401, 403}


@pytest.mark.asyncio
async def test_root_cannot_remove_a_human_membership_or_an_untracked_legacy_member(admissions):
    a = admissions
    await endorse(a)
    for key, member_id, alias, code in (
        (a.w.human_key, a.w.context.human_id, "human", "subject_ineligible"),
        (SigningKey.generate(), None, "untracked", "scope_refused"),
    ):
        certificate = {"version": 1, "certificate_id": str(uuid4()), "team_id": TEAM,
            "team_did_key": did(a.w.controller), "member_did_key": did(key),
            "alias": alias, "identity_scope": "global" if member_id else "local",
            "issued_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")}
        if member_id:
            certificate["member_did_aw"] = member_id
        certificate["signature"] = sign_message(bytes(a.w.controller), canonical_json_bytes(certificate))
        await a.w.registry.register_team_certificate(DOMAIN, "engineering",
            team_controller_signing_key=bytes(a.w.controller), certificate_id=certificate["certificate_id"],
            member_did_key=did(key), member_did_aw=member_id, member_address=None, alias=alias,
            identity_scope=certificate["identity_scope"], certificate=base64.b64encode(canonical_json_bytes(certificate)).decode())
        operation = removal(a, certificate)
        response = await prepare(a, operation)
        assert response.status_code == 403 and response.json() == {"detail": code}, response.text
        assert await a.w.app.signer.lookup_context(operation.operation_id) is None
        assert await signature_count(a, operation) == 0


@pytest.mark.asyncio
async def test_original_revoke_request_freshness_caps_execution_without_freeing_capacity(admissions):
    a = admissions
    await endorse(a)
    _, certificate = await admitted(a)
    operation = removal(a, certificate)
    prepared = await prepare(a, operation)
    assert prepared.status_code == 200, prepared.text
    frozen = prepared.json()
    request = frozen["payload"]["request"]["artifact"]["request"]
    stamp = datetime.fromisoformat(request["timestamp"].replace("Z", "+00:00"))
    expires = datetime.fromisoformat(frozen["expires_at"].replace("Z", "+00:00"))
    assert expires <= stamp + timedelta(seconds=300)
    a.w.app.signer.clock = lambda: expires + timedelta(seconds=1)
    result = await execute(a, operation)
    assert result.status_code == 200 and result.json() == {"state": "refused", "code": "operation_expired"}, result.text
    assert await signature_count(a, operation) == 0
    assert await a.w.db.fetch_value("SELECT state FROM {{tables.protected_root_admissions}} WHERE certificate_id=$1", certificate["certificate_id"]) == "active"


@pytest.mark.asyncio
async def test_removal_confirmation_audit_failure_rolls_back_quota_and_receipt_together(admissions, monkeypatch):
    a = admissions
    await endorse(a)
    _, certificate = await admitted(a)
    operation = removal(a, certificate)
    assert (await prepare(a, operation)).status_code == 200
    audit, original = a.w.app.audit, a.w.app.audit.emit

    async def unavailable(event, transaction):
        if event.kind.value == "protected_member_removed":
            raise RuntimeError("audit unavailable")
        return await original(event, transaction)

    monkeypatch.setattr(audit, "emit", unavailable)
    with pytest.raises(RuntimeError, match="audit unavailable"):
        await execute(a, operation)
    assert await a.w.db.fetch_value("SELECT result FROM {{tables.protected_signer_operations}} WHERE operation_id=$1", operation.operation_id) is None
    assert await a.w.db.fetch_value("SELECT state FROM {{tables.protected_root_admissions}} WHERE certificate_id=$1", certificate["certificate_id"]) == "active"
    monkeypatch.setattr(audit, "emit", original)
    path = "/protected-operations/" + operation.operation_id
    response = await a.client.get(path, headers=headers(a, path=path, method="GET", label="protected_operation_receipt"))
    assert response.status_code == 200 and response.json()["state"] == "committed", response.text
    assert await signature_count(a, operation) == 1
    assert await a.w.db.fetch_value("SELECT state FROM {{tables.protected_root_admissions}} WHERE certificate_id=$1", certificate["certificate_id"]) == "removed"
