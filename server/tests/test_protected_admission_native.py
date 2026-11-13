"""Real PG/customer AWID/B2/B3 proof for the OATS three-operation slice.

Native bodies require the coordinator's VM placement. No local DB fallback.
"""

import asyncio
import base64
import json
from dataclasses import replace
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
import pytest_asyncio
from aweb_naapp.runtime.protected_signer import AdmittedHuman, CatalogOperation, SignerRefused
from aweb_naapp_testing.webauthn import SoftAuthenticator
from awid.did import did_from_public_key, generate_keypair
from awid.id_certificates import ID_CERTIFICATE_PREFIX
from awid.signing import canonical_json_bytes
from awid.team_certificate import check_team_certificate
from fastapi import FastAPI

from aweb.protected_signing.admission import provision_policy
from aweb.protected_signing.bootstrap import initialise, prepare_completion
from aweb.protected_signing.composition import IndependentProtectedSigner
from aweb.protected_signing.custody import ProtectedControllerCustody
from aweb.protected_signing.group import ProtectedSignerGroup
from tests.test_independent_protected_signer import DOMAIN, HUMAN_ORIGIN, ORIGIN, TEAM, did, proof_request

pytest_plugins = ("tests.test_independent_protected_signer",)


@pytest_asyncio.fixture
async def admissions(world, tmp_path):
    w = world
    public = {"version": 1, "teams": [TEAM],
        "root_selector": {"kind": "service_endorsed_root", "service_id": w.context.service_id},
        "subject_kinds": ["local_agent", "registered_agent"], "member_role": "member",
        "bounds": {"max_active": 2, "rate_window_seconds": 3600, "max_per_window": 2}}
    policy = await provision_policy(w.app, public)
    context = replace(w.context, authority_kind="human_identity", authority_id=w.context.human_id)
    directory = tmp_path / "human-custody"
    directory.mkdir(mode=0o700)
    key = directory / "signing.key"
    key.write_text(bytes(w.human_key).hex()+"\n")
    key.chmod(0o400)
    custody = ProtectedControllerCustody(service_id=context.service_id, team_id=context.authority_id,
        domain=DOMAIN, key_file=key, worker_uids=frozenset({65534}), authority_kind="human_identity")
    groups = []

    async def proof_context(scope, *, tx):
        return await groups[0].context_for_scope(scope, tx=tx)

    team = IndependentProtectedSigner(w.db, context=w.context, registry=w.registry, custody=w.app.authority.custody,
        human_origin=HUMAN_ORIGIN, request_origin=ORIGIN, delivery=w.delivery, proof_context=proof_context)
    human = IndependentProtectedSigner(w.db, context=context, registry=w.registry, custody=custody,
        human_origin=HUMAN_ORIGIN, request_origin=ORIGIN, delivery=w.delivery, proof_context=proof_context)
    group = ProtectedSignerGroup([team, human], selected=team)
    groups.append(group)
    w.app = team
    await human.migrate()
    # Supported operator bootstrap and its original B3 completion fence; no
    # synthetic human authority, enrollment row or test-only key writer here.
    await initialise(human, requester=w.root_id, contact="operator@customer.example")
    token = w.delivery.enrolment
    device = SoftAuthenticator(HUMAN_ORIGIN)
    credential = device.create(await human.passkeys.enrolment_options(token))
    approver = await human.passkeys.complete_enrolment(token, credential, fence=await prepare_completion(human, token))
    login = await human.passkeys.verify_login(approver.scope, device.get(await human.passkeys.login_options(approver.scope)))
    actor = AdmittedHuman(context.human_id, login.subject, approver.scope, context)

    class Limiter:
        async def admit(self, *args, **kwargs):
            pass  # This suite exercises authority; real limiter journey stays separate.

    api = FastAPI()
    api.include_router(group.operations_http(limiter=Limiter()).api_router())
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=api), base_url=ORIGIN) as client:
        yield SimpleNamespace(w=w, human=human, actor=actor, device=device, group=group, client=client, policy=policy)


def headers(a, *, body=b"", path="/protected-operations", method="POST", label="protected_operation_prepare", context=None):
    return {**dict(proof_request(a.w, body=body, path=path, method=method, operation=label, context=context).headers),
        "X-AWEB-DID-AW": a.w.root_id, "Content-Type": "application/json"}


async def prepare(a, operation):
    raw = canonical_json_bytes(operation.intent())
    return await a.client.post("/protected-operations", content=raw, headers=headers(a, body=raw, context=operation.context))


async def execute(a, operation):
    path = f"/protected-operations/{operation.operation_id}/execute"
    return await a.client.post(path, content=b"", headers=headers(a, path=path, label="protected_operation_execute", context=operation.context))


def root_operation(a):
    return CatalogOperation(str(uuid4()), a.human.context, a.w.registry.registry_url, "identity.root.endorse", "default",
        {"domain": DOMAIN, "root_id": a.w.root_id, "root_key": did(a.w.root), "teams": [TEAM], "deployment_label": "oats-root"})


async def endorse(a):
    operation = root_operation(a)
    response = await prepare(a, operation)
    assert response.status_code == 200, response.text
    frozen = response.json()
    assert frozen["payload"]["request"]["admission_policy"] == a.policy
    options = await a.human.signer.approval_options(operation.operation_id, human=a.actor)
    result = await a.human.signer.execute(operation.operation_id, a.device.get(dict(options)), human=a.actor)
    assert result.state == "committed"
    signing = base64.b64decode(result.result["signing"], validate=True)
    assert signing.startswith(ID_CERTIFICATE_PREFIX)
    leaf = {"certificate": json.loads(signing[len(ID_CERTIFICATE_PREFIX):]),
        "signature": base64.urlsafe_b64encode(base64.b64decode(result.result["signature"], validate=True)).rstrip(b"=").decode()}
    await a.w.registry.register_id_certificate(
        {"v": 1, "type": "aweb.id-chain", "certificates": [a.w.human_certificate, leaf]},
        signer=lambda payload: (did(a.w.root), a.w.root.sign(payload).signature), expected_head=None, invitation_id=None)
    return operation, result


def admit_operation(a, *, registered=None, **changes):
    _, public = generate_keypair()
    subject = {"team_id": TEAM, "root_id": a.w.root_id, "root_key": did(a.w.root),
        "child_id": None, "child_key": did_from_public_key(public), "member_alias": "agent-"+uuid4().hex[:12],
        "admission_policy_digest": a.policy["digest"], "expected_policy_version": a.policy["version"], **changes}
    if registered is not None:
        subject["child_id"], subject["child_key"] = registered
    return CatalogOperation(str(uuid4()), a.w.context, a.w.registry.registry_url, "team.agent.admit", "default", subject)


@pytest.mark.asyncio
async def test_actual_operator_endorsement_then_unattended_admission_registers_one_certificate(admissions):
    a = admissions
    await endorse(a)
    operation = admit_operation(a)
    before = await a.w.db.fetch_value("SELECT count(*) FROM {{tables.approvals}}")
    prepared = await prepare(a, operation)
    assert prepared.status_code == 200, prepared.text
    original = prepared.json()
    response = await execute(a, operation)
    assert response.status_code == 200 and response.json()["state"] == "committed", response.text
    assert await a.w.db.fetch_value("SELECT count(*) FROM {{tables.approvals}}") == before
    result = response.json()["result"]
    artifact = json.loads(base64.b64decode(result["signing"]))
    signature = base64.b64encode(base64.b64decode(result["signature"])).rstrip(b"=").decode()
    certificate = {**artifact, "signature": signature}
    records = await a.w.registry.list_team_certificates_fresh(DOMAIN, "engineering", active_only=True)
    current_key = await a.w.registry.get_team_public_key_fresh(DOMAIN, "engineering")
    checked = check_team_certificate(base64.b64encode(canonical_json_bytes(certificate)).decode(),
        subject_did_key=artifact["member_did_key"], team_did_key=current_key,
        revoked_certificate_ids=set(), registered_certificate_ids={r.certificate_id for r in records})
    assert checked["identity_scope"] == "local" and "member_did_aw" not in checked
    assert [r.certificate_id for r in records].count(artifact["certificate_id"]) == 1
    assert (await prepare(a, operation)).json() == original
    assert (await execute(a, operation)).json() == response.json()
    assert await a.w.db.fetch_value("SELECT count(*) FROM {{tables.protected_root_admissions}} WHERE root_id=$1", a.w.root_id) == 1
    assert await a.w.db.fetch_value("SELECT count(*) FROM {{tables.protected_local_audit}} WHERE kind='protected_operation_signed' AND subject=$1", operation.operation_id) == 1
    assert await a.w.db.fetch_value("SELECT approval_id FROM {{tables.protected_signer_operations}} WHERE operation_id=$1", operation.operation_id) is None


@pytest.mark.asyncio
async def test_policy_read_is_available_before_endorsement_but_creates_no_operation(admissions):
    a = admissions
    path = "/protected-admission-policies?team_id=" + TEAM.replace(":", "%3A")
    before = await a.w.db.fetch_value("SELECT count(*) FROM {{tables.protected_signer_operations}}")
    response = await a.client.get(path, headers=headers(a, path=path, method="GET", label="protected_admission_policy_read"))
    assert response.status_code == 200, response.text
    assert response.json()["policy"] == a.policy
    assert await a.w.db.fetch_value("SELECT count(*) FROM {{tables.protected_signer_operations}}") == before


@pytest.mark.asyncio
async def test_missing_policy_refuses_endorse_before_any_pending_record(admissions):
    a = admissions
    await a.w.db.execute("DELETE FROM {{tables.protected_admission_policies}}")
    response = await prepare(a, root_operation(a))
    assert response.status_code == 403 and response.json() == {"detail": "admission_policy_missing"}
    assert await a.w.db.fetch_value("SELECT count(*) FROM {{tables.protected_signer_operations}}") == 0


@pytest.mark.asyncio
async def test_unendorsed_root_cannot_use_unattended_admission_or_execute_a_live_act(admissions):
    a = admissions
    response = await prepare(a, admit_operation(a))
    assert response.status_code == 403 and response.json()["detail"] == "subject_ineligible"
    root = root_operation(a)
    assert (await prepare(a, root)).status_code == 200
    response = await execute(a, root)
    assert response.status_code == 403 and response.json() == {"detail": "live_approval_required"}
    assert await a.w.db.fetch_value("SELECT result FROM {{tables.protected_signer_operations}} WHERE operation_id=$1", root.operation_id) is None


@pytest.mark.asyncio
async def test_registration_answer_loss_is_reconciled_without_another_signature_or_mutation(admissions, monkeypatch):
    a = admissions
    await endorse(a)
    custody = a.w.app.authority.custody
    original, attempts = custody.register_admission, []

    async def lost(*args):
        attempts.append(1)
        await original(*args)
        raise SignerRefused("receipt_unavailable")

    monkeypatch.setattr(custody, "register_admission", lost)
    operation = admit_operation(a)
    assert (await prepare(a, operation)).status_code == 200
    assert (await execute(a, operation)).status_code == 503
    path = "/protected-operations/"+operation.operation_id
    response = await a.client.get(path, headers=headers(a, path=path, method="GET", label="protected_operation_receipt"))
    assert response.status_code == 200 and response.json()["state"] == "committed", response.text
    assert attempts == [1]
    assert (await execute(a, operation)).json() == response.json()
    assert attempts == [1]
    assert await a.w.db.fetch_value("SELECT count(*) FROM {{tables.protected_local_audit}} WHERE kind='protected_operation_signed' AND subject=$1", operation.operation_id) == 1


@pytest.mark.asyncio
async def test_concurrent_admissions_obey_the_same_root_active_and_rate_bounds(admissions):
    a = admissions
    await endorse(a)
    operations = [admit_operation(a) for _ in range(3)]
    for op in operations:
        assert (await prepare(a, op)).status_code == 200
    responses = await asyncio.gather(*(execute(a, op) for op in operations))
    assert sum(r.status_code == 200 and r.json()["state"] == "committed" for r in responses) == 2
    assert sum(r.status_code == 200 and r.json() == {"state": "refused", "code": "admission_limit_reached"} for r in responses) == 1
    assert await a.w.db.fetch_value("SELECT count(*) FROM {{tables.protected_root_admissions}}") == 2


@pytest.mark.asyncio
async def test_registered_agent_retains_global_fields_and_a_human_is_refused(admissions):
    a = admissions
    await endorse(a)
    seed, public = generate_keypair()
    child = await a.w.registry.register_did(did_from_public_key(public), seed)
    op = admit_operation(a, registered=(child.did_aw, did_from_public_key(public)))
    assert (await prepare(a, op)).status_code == 200
    response = await execute(a, op)
    assert response.status_code == 200 and response.json()["state"] == "committed", response.text
    certificate = json.loads(base64.b64decode(response.json()["result"]["signing"]))
    assert certificate["identity_scope"] == "global" and certificate["member_did_aw"] == child.did_aw
    refused = await prepare(a, admit_operation(a, registered=(a.w.context.human_id, did(a.w.human_key))))
    assert refused.status_code == 403 and refused.json()["detail"] == "subject_ineligible"


@pytest.mark.asyncio
async def test_changed_same_id_admission_conflicts_before_new_target_observations(admissions):
    a = admissions
    await endorse(a)
    op = admit_operation(a)
    prepared = await prepare(a, op)
    assert prepared.status_code == 200
    # These are valid typed inputs but deliberately fail current target checks.
    # An owned UUID binds its original body before those checks are revisited.
    for changes in (
        {"child_id": a.w.context.human_id, "child_key": did(a.w.human_key)},
        {"expected_policy_version": 99},
        {"admission_policy_digest": "sha256:"+"a"*64},
        {"root_id": a.w.context.human_id, "root_key": did(a.w.human_key)},
    ):
        changed = replace(op, subject={**op.intent()["subject"], **changes})
        response = await prepare(a, changed)
        assert response.status_code == 409 and response.json() == {"detail": "operation_conflict"}, response.text
    assert (await prepare(a, op)).json() == prepared.json()
    assert await a.w.db.fetch_value("SELECT count(*) FROM {{tables.protected_root_admissions}}") == 0


@pytest.mark.asyncio
async def test_a_policy_change_after_prepare_cannot_use_the_old_live_endorsement(admissions):
    from aweb_naapp.runtime.protected_signer.admission_policy import AdmissionPolicy

    a = admissions
    op = root_operation(a)
    assert (await prepare(a, op)).status_code == 200
    options = await a.human.signer.approval_options(op.operation_id, human=a.actor)
    proof = a.device.get(dict(options))
    unsigned = {name: value for name, value in a.policy.items() if name != "digest"}
    unsigned["version"] += 1
    updated = AdmissionPolicy.from_unsigned(unsigned, service_id=a.w.context.service_id)
    await a.w.db.execute("UPDATE {{tables.protected_admission_policies}} SET version=$1,digest=$2,policy=$3::jsonb",
        updated.version, updated.digest, json.dumps(updated.fields()))
    refused = await a.human.signer.execute(op.operation_id, proof, human=a.actor)
    assert refused.state == "refused" and refused.code == "policy_changed"
    row = await a.w.db.fetch_one("SELECT refusal_code FROM {{tables.protected_signer_operations}} WHERE operation_id=$1", op.operation_id)
    assert row["refusal_code"] == "policy_changed"
    assert await a.w.db.fetch_value("SELECT count(*) FROM {{tables.protected_root_endorsements}}") == 0
    assert await a.w.db.fetch_value("SELECT result FROM {{tables.protected_signer_operations}} WHERE operation_id=$1", op.operation_id) is None


@pytest.mark.asyncio
async def test_last_audit_wait_cannot_extend_the_roots_original_registry_observation(admissions, monkeypatch):
    from time import monotonic

    a = admissions
    await endorse(a)
    adapter = a.w.app.signer.admission
    clock = [monotonic()]
    adapter.timer = lambda: clock[0]
    op = admit_operation(a)
    assert (await prepare(a, op)).status_code == 200
    emit = a.w.app.signer._emit

    async def waited(*args, **kwargs):
        await emit(*args, **kwargs)
        clock[0] += 61

    monkeypatch.setattr(a.w.app.signer, "_emit", waited)
    response = await execute(a, op)
    assert response.status_code == 503 and response.json() == {"detail": "receipt_unavailable"}
    row = await a.w.db.fetch_one("SELECT signed_result,result FROM {{tables.protected_signer_operations}} WHERE operation_id=$1", op.operation_id)
    assert row["signed_result"] is None and row["result"] is None
    assert await a.w.db.fetch_value("SELECT count(*) FROM {{tables.protected_root_admissions}}") == 0


@pytest.mark.asyncio
async def test_runnable_host_serves_both_private_authorities_and_the_same_three_operations(admissions, tmp_path):
    from aweb.protected_signing.host import create_app
    from tests.test_independent_protected_http import profile_for
    from tests.test_protected_host_native import host_settings_for
    from tests.test_protected_signer_host import CapturedMail

    a = admissions
    settings = host_settings_for(a.w, tmp_path)
    fields = profile_for(a.w).fields()
    fields["bindings"].append({"scope": a.human.context.fields(), "authority_key_did": did(a.w.human_key),
        "policy": {"ref": "aweb.human-assurance/1", "version": 1}})
    settings.profile_file.write_text(json.dumps(fields))
    human_key = settings.controller_key_file.parent / "human.key"
    human_key.write_text(bytes(a.w.human_key).hex()+"\n")
    human_key.chmod(0o400)
    manifest = tmp_path / "controller-keys.json"
    manifest.write_text(json.dumps({did(a.w.controller): str(settings.controller_key_file), did(a.w.human_key): str(human_key)}))
    settings.controller_keys_file = manifest
    host = create_app(settings, mailer=CapturedMail(), registry_transport=a.w.host.transport)
    async with host.api_app.router.lifespan_context(host.api_app):
        group = host.api_app.state.composition
        assert len(group.components) == 2
        assert group.db is group.components[0].db is group.components[1].db
        a.human = group.component(a.human.context)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=host), base_url=ORIGIN) as client:
            a.client = client
            path = "/protected-admission-policies?team_id=" + TEAM.replace(":", "%3A")
            response = await client.get(path, headers=headers(a, path=path, method="GET", label="protected_admission_policy_read"))
            assert response.status_code == 200 and response.json()["policy"] == a.policy
            await endorse(a)
            operation = admit_operation(a)
            assert (await prepare(a, operation)).status_code == 200
            response = await execute(a, operation)
            assert response.status_code == 200 and response.json()["state"] == "committed", response.text


@pytest.mark.asyncio
async def test_expired_root_uv_is_a_final_receipt_before_the_longer_operation_expiry(admissions, monkeypatch):
    from datetime import UTC, datetime, timedelta

    from aweb_naapp.runtime.audit import AuditKind

    a = admissions
    op = root_operation(a)
    assert (await prepare(a, op)).status_code == 200
    options = await a.human.signer.approval_options(op.operation_id, human=a.actor)
    emit = a.human.signer._emit

    async def failed(kind, *args, **kwargs):
        if kind is AuditKind.PROTECTED_OPERATION_SIGNED:
            raise RuntimeError("audit unavailable")
        return await emit(kind, *args, **kwargs)

    monkeypatch.setattr(a.human.signer, "_emit", failed)
    with pytest.raises(RuntimeError, match="audit unavailable"):
        await a.human.signer.execute(op.operation_id, a.device.get(dict(options)), human=a.actor)
    future = datetime.now(UTC) + timedelta(seconds=301)
    a.human.signer.clock = lambda: future
    path = "/protected-operations/"+op.operation_id
    response = await a.client.get(path, headers=headers(a, path=path, method="GET", label="protected_operation_receipt", context=op.context))
    assert response.status_code == 200 and response.json() == {"state": "refused", "code": "approval_expired"}, response.text
    assert await a.w.db.fetch_value("SELECT count(*) FROM {{tables.protected_root_endorsements}}") == 0
    row = await a.w.db.fetch_one("SELECT result,refusal_code,expires_at FROM {{tables.protected_signer_operations}} WHERE operation_id=$1", op.operation_id)
    assert row["result"] is None and row["refusal_code"] == "approval_expired" and row["expires_at"] > future


@pytest.mark.asyncio
async def test_two_pending_root_endorsements_do_not_create_two_committed_signatures(admissions):
    a = admissions
    first, second = root_operation(a), root_operation(a)
    assert (await prepare(a, first)).status_code == 200
    assert (await prepare(a, second)).status_code == 200
    for operation, expected in ((first, "committed"), (second, "refused")):
        options = await a.human.signer.approval_options(operation.operation_id, human=a.actor)
        receipt = await a.human.signer.execute(operation.operation_id, a.device.get(dict(options)), human=a.actor)
        assert receipt.state == expected
        if expected == "refused":
            assert receipt.code == "operation_mismatch"
    assert await a.w.db.fetch_value("SELECT count(*) FROM {{tables.protected_root_endorsements}}") == 1
    assert await a.w.db.fetch_value("SELECT count(*) FROM {{tables.protected_local_audit}} WHERE kind='protected_operation_signed'") == 1
