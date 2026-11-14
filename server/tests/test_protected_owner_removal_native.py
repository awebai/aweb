"""Actual registry + B2/B3 owner removal; VM-only native qualification."""

import base64
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from aweb_naapp.runtime.protected_signer import CatalogOperation, SignerRefused
from awid.id_certificates import sign_id_certificate
from awid.registry_types import RegistryError
from awid.signing import canonical_json_bytes, sign_message
from nacl.signing import SigningKey

from tests.test_independent_protected_signer import DOMAIN, TEAM, did
from tests.test_protected_admission_native import endorse, execute, headers, prepare, registered_identity
from tests.test_protected_removal_native import admitted, signature_count

pytest_plugins = ("tests.test_protected_admission_native",)


def owner_removal(a, certificate):
    return CatalogOperation(str(uuid4()), a.w.context, a.w.registry.registry_url,
        "team.agent.remove", "owner_approved", {"team_id": TEAM,
            "member_id": certificate.get("member_did_aw") or certificate["member_did_key"],
            "certificate_id": certificate["certificate_id"],
            "expected_membership": {name: certificate.get(name) for name in (
                "member_did_key", "member_did_aw", "member_address", "alias", "identity_scope")}})


async def legacy_member(a, kind, *, alias="service-or-legacy-member"):
    key = SigningKey.generate()
    member = None
    if kind == "unknown":
        member = (await a.w.registry.register_did(did(key), bytes(key))).did_aw
    elif kind != "local":
        member = await registered_identity(a, key, kind=kind)
    certificate = {"version": 1, "certificate_id": str(uuid4()), "team_id": TEAM,
        "team_did_key": did(a.w.controller), "member_did_key": did(key),
        "alias": alias, "identity_scope": "global" if member else "local",
        "issued_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")}
    if member:
        certificate["member_did_aw"] = member
    certificate["signature"] = sign_message(bytes(a.w.controller), canonical_json_bytes(certificate))
    await a.w.registry.register_team_certificate(DOMAIN, "engineering",
        team_controller_signing_key=bytes(a.w.controller), certificate_id=certificate["certificate_id"],
        member_did_key=did(key), member_did_aw=member, member_address=None, alias=certificate["alias"],
        identity_scope=certificate["identity_scope"], certificate=base64.b64encode(canonical_json_bytes(certificate)).decode())
    return key, certificate


async def owner_proof(a, operation):
    options = await a.w.app.signer.approval_options(operation.operation_id, human=a.w.human)
    return a.w.device.get(dict(options))


async def owner_execute(a, operation, proof=None):
    if proof is None:
        proof = await owner_proof(a, operation)
    return await a.w.app.signer.execute(operation.operation_id, proof, human=a.w.human)


async def records(a, operation):
    return await a.w.db.fetch_one("SELECT intent,expires_at,result,signed_result,delivery_claim FROM {{tables.protected_signer_operations}} WHERE operation_id=$1", operation.operation_id)


async def revoked(a, certificate):
    rows = await a.w.registry.list_team_certificates_fresh(DOMAIN, "engineering", active_only=False)
    return next(row for row in rows if row.certificate_id == certificate["certificate_id"]).revoked_at is not None


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["local", "agent", "unknown"])
async def test_owner_removes_untracked_service_or_legacy_member_without_root_endorsement(admissions, kind):
    a = admissions
    _, certificate = await legacy_member(a, kind)
    operation = owner_removal(a, certificate)
    response = await prepare(a, operation)
    assert response.status_code == 200, response.text
    request = response.json()["payload"]["request"]
    assert request["target_kind"] == ("kind not verified" if kind == "unknown" else "agent")
    assert request["requester_key"] == did(a.w.root)
    assert await a.w.db.fetch_value("SELECT count(*) FROM {{tables.protected_root_admissions}}") == 0
    no_uv = await execute(a, operation)
    assert no_uv.status_code == 403 and no_uv.json() == {"detail": "live_approval_required"}
    assert await signature_count(a, operation) == 0
    result = await owner_execute(a, operation)
    assert result.state == "committed" and await revoked(a, certificate)
    assert await signature_count(a, operation) == 1
    assert await a.w.db.fetch_value("SELECT count(*) FROM {{tables.protected_root_admissions}}") == 0


@pytest.mark.asyncio
async def test_owner_agent_removal_refuses_verified_human(admissions):
    a = admissions
    _, certificate = await legacy_member(a, "human")
    operation = owner_removal(a, certificate)
    response = await prepare(a, operation)
    assert response.status_code == 403 and response.json() == {"detail": "subject_ineligible"}
    assert await a.w.app.signer.lookup_context(operation.operation_id) is None
    assert not await revoked(a, certificate)


@pytest.mark.asyncio
async def test_owner_can_remove_an_admission_after_its_root_grants_are_retired(admissions):
    a = admissions
    await endorse(a)
    _, certificate = await admitted(a)
    operation = owner_removal(a, certificate)
    assert (await prepare(a, operation)).status_code == 200
    await a.w.db.execute("UPDATE {{tables.protected_requester_bindings}} SET active=false WHERE principal=$1", a.w.root_id)
    result = await owner_execute(a, operation)
    assert result.state == "committed" and await revoked(a, certificate)
    assert await a.w.db.fetch_value("SELECT state FROM {{tables.protected_root_admissions}} WHERE certificate_id=$1", certificate["certificate_id"]) == "removed"


@pytest.mark.asyncio
@pytest.mark.parametrize("tracked", [False, True])
async def test_owner_lost_answer_recovers_same_signature_and_one_mutation(admissions, monkeypatch, tracked):
    a = admissions
    if tracked:
        await endorse(a)
        _, certificate = await admitted(a)
    else:
        _, certificate = await legacy_member(a, "local")
    operation = owner_removal(a, certificate)
    assert (await prepare(a, operation)).status_code == 200
    original = a.w.app.authority.custody.remove_member
    attempts = []

    async def lost(*args):
        attempts.append(operation.operation_id)
        await original(*args)
        raise RegistryError("answer lost", status_code=503)

    monkeypatch.setattr(a.w.app.authority.custody, "remove_member", lost)
    with pytest.raises(SignerRefused, match="evidence_unavailable"):
        await owner_execute(a, operation)
    saved = await records(a, operation)
    assert saved["result"] is None and saved["signed_result"] is not None and saved["delivery_claim"] is not None
    assert await revoked(a, certificate)
    path = "/protected-operations/" + operation.operation_id
    response = await a.client.get(path, headers=headers(a, path=path, method="GET", label="protected_operation_receipt"))
    assert response.status_code == 200 and response.json()["state"] == "committed", response.text
    recovered = await records(a, operation)
    for field in ("intent", "expires_at", "signed_result", "delivery_claim"):
        assert recovered[field] == saved[field]
    assert attempts == [operation.operation_id] and await signature_count(a, operation) == 1
    assert await a.w.db.fetch_value("SELECT count(*) FROM {{tables.protected_root_admissions}} WHERE certificate_id=$1 AND state='removed'", certificate["certificate_id"]) == int(tracked)


async def enroll_as_human(a, certificate):
    member = certificate["member_did_aw"]
    leaf = await sign_id_certificate({"v": 1, "type": "aweb.id-certificate", "id": member,
        "domain": DOMAIN, "parent": {"kind": "identity", "id": a.w.context.human_id},
        "kind": "human", "issuer_key": did(a.w.human_key),
        "issued_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")},
        signer=lambda raw: (did(a.w.human_key), a.w.human_key.sign(raw).signature))
    # Possession of the member's registered key is needed by AWID; the test
    # keeps it separately rather than substituting the held controller.
    return leaf


@pytest.mark.asyncio
@pytest.mark.parametrize("after_signing", [False, True])
async def test_unknown_becoming_human_cannot_reuse_frozen_owner_approval(admissions, monkeypatch, after_signing):
    a = admissions
    key, certificate = await legacy_member(a, "unknown")
    operation = owner_removal(a, certificate)
    assert (await prepare(a, operation)).json()["payload"]["request"]["target_kind"] == "kind not verified"
    provider = a.w.app.signer.owner_removal
    original = provider.observe
    calls = 0

    async def changed(selected, actor, *, purpose):
        nonlocal calls
        calls += 1
        if calls == (2 if after_signing else 1):
            leaf = await enroll_as_human(a, certificate)
            await a.w.registry.register_id_certificate(
                {"v": 1, "type": "aweb.id-chain", "certificates": [a.w.human_certificate, leaf]},
                signer=lambda raw: (did(key), key.sign(raw).signature), expected_head=None, invitation_id=None)
        return await original(selected, actor, purpose=purpose)

    monkeypatch.setattr(provider, "observe", changed)
    result = await owner_execute(a, operation)
    assert result.state == ("pending" if after_signing else "refused")
    if not after_signing:
        assert result.code == "subject_ineligible"
    assert not await revoked(a, certificate)
    assert await signature_count(a, operation) == int(after_signing)
    row = await records(a, operation)
    assert row["delivery_claim"] is None and row["result"] is None


@pytest.mark.asyncio
async def test_former_owner_cannot_approve_even_with_the_requester_key(admissions):
    a = admissions
    _, certificate = await legacy_member(a, "local")
    operation = owner_removal(a, certificate)
    assert (await prepare(a, operation)).status_code == 200
    wrong = replace(a.w.human, principal=a.w.root_id)
    with pytest.raises(SignerRefused, match="scope_refused"):
        await a.w.app.signer.approval_options(operation.operation_id, human=wrong)
    assert await signature_count(a, operation) == 0 and not await revoked(a, certificate)


@pytest.mark.asyncio
@pytest.mark.parametrize("tracked", [False, True])
async def test_owner_audit_failure_rolls_back_only_local_confirmation_then_recovers(admissions, monkeypatch, tracked):
    a = admissions
    if tracked:
        await endorse(a)
        _, certificate = await admitted(a)
    else:
        _, certificate = await legacy_member(a, "local")
    operation = owner_removal(a, certificate)
    assert (await prepare(a, operation)).status_code == 200
    audit, emit = a.w.app.audit, a.w.app.audit.emit
    markers, attempts = [], []
    custody, release = a.w.app.authority.custody, a.w.app.authority.custody.remove_member

    async def fail(event, tx):
        if event.kind.value == "protected_member_removed":
            markers.append(event.subject)
            raise RuntimeError("audit unavailable")
        return await emit(event, tx)

    async def delivered(*args):
        attempts.append(operation.operation_id)
        return await release(*args)

    monkeypatch.setattr(audit, "emit", fail)
    monkeypatch.setattr(custody, "remove_member", delivered)
    # This helper calls the signer directly; the mounted HTTP route's 503
    # mapping is independently covered by the existing default-removal test.
    with pytest.raises(RuntimeError, match="audit unavailable"):
        await owner_execute(a, operation)
    assert markers == [operation.operation_id] and await revoked(a, certificate)
    saved = await records(a, operation)
    assert saved["result"] is None and saved["signed_result"] is not None and saved["delivery_claim"] is not None
    assert await a.w.db.fetch_value("SELECT count(*) FROM {{tables.protected_root_admissions}} WHERE certificate_id=$1 AND state='active'", certificate["certificate_id"]) == int(tracked)
    assert await a.w.db.fetch_value("SELECT count(*) FROM {{tables.protected_local_audit}} WHERE kind='protected_member_removed' AND subject=$1", operation.operation_id) == 0
    monkeypatch.setattr(audit, "emit", emit)
    result = await a.w.app.signer.receipt(operation.operation_id, reader=a.w.human)
    assert result.state == "committed" and await signature_count(a, operation) == 1
    recovered = await records(a, operation)
    assert all(recovered[name] == saved[name] for name in ("intent", "expires_at", "signed_result", "delivery_claim"))
    assert attempts == [operation.operation_id]
    assert await a.w.db.fetch_value("SELECT count(*) FROM {{tables.protected_root_admissions}} WHERE certificate_id=$1 AND state='removed'", certificate["certificate_id"]) == int(tracked)
    assert await a.w.db.fetch_value("SELECT count(*) FROM {{tables.protected_local_audit}} WHERE kind='protected_member_removed' AND subject=$1", operation.operation_id) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("withdrawal", ["uv_expiry", "credential", "binding"])
async def test_owner_release_rechecks_live_authority_after_signature(admissions, monkeypatch, withdrawal):
    a = admissions
    _, certificate = await legacy_member(a, "local")
    operation = owner_removal(a, certificate)
    assert (await prepare(a, operation)).status_code == 200
    provider, calls = a.w.app.signer.owner_removal, 0
    original = provider.observe
    original_clock = a.w.app.signer.clock

    async def withdrawn(selected, actor, *, purpose):
        nonlocal calls
        calls += 1
        observation = await original(selected, actor, purpose=purpose)
        if calls == 2:
            if withdrawal == "uv_expiry":
                expired = original_clock() + timedelta(seconds=301)
                monkeypatch.setattr(a.w.app.signer, "clock", lambda: expired)
            elif withdrawal == "credential":
                await a.w.db.execute("UPDATE {{tables.passkey_credentials}} SET revoked_at=now() WHERE subject=$1", a.w.human.subject)
            else:
                await a.w.db.execute("UPDATE {{tables.protected_authorizer_bindings}} SET active=false WHERE b3_scope=$1", a.w.scope)
        return observation

    monkeypatch.setattr(provider, "observe", withdrawn)
    if withdrawal == "uv_expiry":
        result = await owner_execute(a, operation)
        assert result.state == "unknown" and result.code == "external_effect_unresolved"
    else:
        with pytest.raises(SignerRefused, match="approval_spent|authority_changed"):
            await owner_execute(a, operation)
    assert await signature_count(a, operation) == 1 and not await revoked(a, certificate)
    row = await records(a, operation)
    assert row["delivery_claim"] is None and row["result"] is None and row["signed_result"] is not None
