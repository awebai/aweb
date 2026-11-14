"""Authorized receipt GETs observe history, never start or release an effect.

Native bodies use real PG/customer AWID/requester proofs. The catalog matrix
seeds historical result projections after genuine preparation; it does not
claim those seeded rows were produced by an executor. Separate controls use
actual lost-answer execution and UV approval to exercise permitted settlement.
"""

import base64
import json
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from aweb_naapp.runtime.audit import AuditKind
from aweb_naapp.runtime.protected_signer import SignerRefused, catalog
from aweb_naapp.runtime.protected_signer.codecs import signing_bytes
from aweb_naapp.runtime.protected_signer.execution_intent import materialize_artifact
from aweb_naapp.runtime.protected_signer.types import owner_act_operation
from awid.registry_types import RegistryError
from nacl.signing import SigningKey
from tests.protected_consumer_support import ready_owner_act_consumer
from tests.test_independent_protected_signer import did, proof_request
from tests.test_protected_admission_native import (
    admit_operation,
    endorse,
    execute,
    headers,
    prepare,
    root_operation,
)
from tests.test_protected_owner_removal_native import legacy_member, owner_removal
from tests.test_protected_removal_native import admitted, removal

pytest_plugins = ("tests.test_protected_admission_native",)

SELECTORS = (
    ("identity.root.endorse", "default"),
    ("team.agent.admit", "default"),
    ("team.agent.remove", "default"),
    ("team.agent.remove", "owner_approved"),
    ("human-role.revoke", "default"),
)
TABLES = (
    "protected_signer_operations", "approval_requests", "approvals",
    "approval_candidates", "approval_links", "protected_root_admissions",
    "protected_root_endorsements", "protected_local_audit",
)


def test_status_matrix_names_every_served_definition():
    assert set(SELECTORS) == {key for key, spec in catalog.OPERATIONS.items() if spec.consumer_available}


async def snapshot(db):
    # Full rows include original bytes, issued artifact, candidate links,
    # evidence, retained bundle, release claim and every deadline, not counts alone.
    return {table: sorted(row["value"] for row in await db.fetch_all(
        "SELECT to_jsonb(t)::text AS value FROM {{tables." + table + "}} t")) for table in TABLES}


async def operation_row(a, operation):
    return dict(await a.w.db.fetch_one(
        "SELECT * FROM {{tables.protected_signer_operations}} WHERE operation_id=$1", operation.operation_id))


def settled_history_only(before, after, *, quota=False):
    """Every preexisting audit event and every other operation stays exact."""
    original = {json.loads(row)["operation_id"]: json.loads(row) for row in before["protected_signer_operations"]}
    current = {json.loads(row)["operation_id"]: json.loads(row) for row in after["protected_signer_operations"]}
    assert original.keys() == current.keys()
    changed = [key for key in original if original[key] != current[key]]
    assert len(changed) == 1
    assert set(before["protected_local_audit"]) < set(after["protected_local_audit"])
    assert len(after["protected_local_audit"]) == len(before["protected_local_audit"]) + 1
    for table in TABLES:
        allowed = {"protected_signer_operations", "protected_local_audit"}
        if quota:
            allowed.add("protected_root_admissions")
        if table not in allowed:
            assert after[table] == before[table]


def forbid_effects(a, monkeypatch):
    """Leave confirmation/authentication reads installed; fail any effect call."""
    calls = []

    def forbidden(*args, **kwargs):
        calls.append("new effect")
        raise AssertionError("receipt read attempted preparation, execution, signing or delivery")

    for component in a.group.components:
        for name in ("prepare", "execute", "execute_request", "_sign_artifact", "_retain_authorized_effect"):
            monkeypatch.setattr(component.signer, name, forbidden)
        custody = component.authority.custody
        for name in ("sign_owner_act", "sign_operation", "register_admission", "remove_member",
                     "retain_authorized_effect", "deliver_retained"):
            if hasattr(custody, name):
                monkeypatch.setattr(custody, name, forbidden)
        for name in ("admission", "owner_removal"):
            provider = getattr(component.signer, name, None)
            if provider is not None:
                monkeypatch.setattr(provider, "register", forbidden)
    return calls


async def read(a, operation, *, context=None):
    path = "/protected-operations/" + operation.operation_id
    return await a.client.get(path, headers=headers(a, path=path, method="GET",
        label="protected_operation_receipt", context=context or operation.context))


@asynccontextmanager
async def selected_operation(a, selector, tmp_path, test_db_factory):
    if selector == ("human-role.revoke", "default"):
        async with ready_owner_act_consumer(a.w, tmp_path, test_db_factory):
            yield owner_act_operation(a.w.operation)
        return
    if selector == ("identity.root.endorse", "default"):
        operation = root_operation(a)
    elif selector == ("team.agent.remove", "owner_approved"):
        _, certificate = await legacy_member(a, "local")
        operation = owner_removal(a, certificate)
    else:
        await endorse(a)
        if selector == ("team.agent.admit", "default"):
            operation = admit_operation(a)
        else:
            _, certificate = await admitted(a)
            operation = removal(a, certificate)
    yield operation


@pytest.mark.asyncio
@pytest.mark.parametrize("selector", SELECTORS, ids=["/".join(value) for value in SELECTORS])
@pytest.mark.parametrize("state", ["pending", "committed", "refused", "signed", "expired_unresolved"])
async def test_status_twice_preserves_stable_history_for_every_definition(
    admissions, tmp_path, test_db_factory, monkeypatch, selector, state
):
    a = admissions
    async with selected_operation(a, selector, tmp_path, test_db_factory) as operation:
        response = await prepare(a, operation)
        assert response.status_code == 200, response.text
        signer = a.group.component(operation.context).signer
        row = await operation_row(a, operation)
        pending_reason = "awaiting_execute" if row["approval_id"] is None else "awaiting_human"
        expected = {"state": "pending", "reason": pending_reason,
            "expires_at": row["expires_at"].isoformat().replace("+00:00", "Z")}
        if state == "committed":
            # Historical projection fixture. No receipt verification or effect
            # acceptance is inferred from this deliberately opaque stored result.
            result = {"signing": "c2lnbmVk", "signature": "c2lnbmF0dXJl"}
            await a.w.db.execute("UPDATE {{tables.protected_signer_operations}} SET result=$2::jsonb WHERE operation_id=$1",
                operation.operation_id, json.dumps(result))
            expected = {"state": "committed", "result": result}
        elif state == "refused":
            await a.w.db.execute("UPDATE {{tables.protected_signer_operations}} SET refusal_code='human_refused' WHERE operation_id=$1",
                operation.operation_id)
            expected = {"state": "refused", "code": "human_refused"}
        elif state in ("signed", "expired_unresolved"):
            request = json.loads(row["request"])
            artifact = (materialize_artifact(operation, request["artifact"], signer.clock())
                if operation.spec.needs_human else request["artifact"])
            signing = signing_bytes(operation, artifact)
            key = a.w.human_key if operation.context.authority_kind == "human_identity" else a.w.controller
            signed = {"signing": base64.b64encode(signing).decode(),
                "signature": base64.b64encode(key.sign(signing).signature).decode()}
            await a.w.db.execute("UPDATE {{tables.protected_signer_operations}} SET signed_result=$2::jsonb,issued_artifact=$3::jsonb WHERE operation_id=$1",
                operation.operation_id, json.dumps(signed), json.dumps(artifact))
            # A historical sign-only row whose old confirmation port is no
            # longer installed still has a readable receipt. This must not
            # install a provider, infer application or restart its deadline.
            for name in ("admission", "owner_removal"):
                monkeypatch.setattr(signer, name, None)
            expected = {"state": "pending", "reason": "effect_in_progress", "expires_at": expected["expires_at"]}
            if state == "expired_unresolved":
                signer.clock = lambda: row["expires_at"] + timedelta(seconds=1)
                expected = {"state": "unknown", "code": "external_effect_unresolved"}
        before = await snapshot(a.w.db)
        calls = forbid_effects(a, monkeypatch)
        for _ in range(2):
            response = await read(a, operation)
            assert response.status_code == 200, response.text
            assert response.json() == expected
            assert await snapshot(a.w.db) == before
        assert calls == []


@pytest.mark.asyncio
async def test_status_can_confirm_a_lost_admission_once_without_releasing_again(admissions, monkeypatch):
    a = admissions
    await endorse(a)
    custody = a.w.app.authority.custody
    original = custody.register_admission
    sends = []

    async def lost(*args):
        sends.append(1)
        await original(*args)
        raise SignerRefused("receipt_unavailable")

    monkeypatch.setattr(custody, "register_admission", lost)
    operation = admit_operation(a)
    assert (await prepare(a, operation)).status_code == 200
    assert (await execute(a, operation)).status_code == 503
    before, original_row = await snapshot(a.w.db), await operation_row(a, operation)
    assert original_row["signed_result"] is not None and original_row["delivery_claim"] is not None
    assert original_row["result"] is None
    calls = forbid_effects(a, monkeypatch)
    response = await read(a, operation)
    assert response.status_code == 200 and response.json()["state"] == "committed", response.text
    after, settled = await snapshot(a.w.db), await operation_row(a, operation)
    assert {key for key in settled if settled[key] != original_row[key]} == {"result", "committed_at"}
    settled_history_only(before, after, quota=True)
    assert len(after["protected_root_admissions"]) == len(before["protected_root_admissions"])
    quota_before = [json.loads(value) for value in before["protected_root_admissions"]]
    quota_after = [json.loads(value) for value in after["protected_root_admissions"]]
    assert [{**value, "state": "active"} for value in quota_before] == quota_after
    for table in TABLES:
        if table not in ("protected_signer_operations", "protected_local_audit", "protected_root_admissions"):
            assert after[table] == before[table]
    again = await read(a, operation)
    assert again.status_code == 200 and again.json() == response.json()
    assert await snapshot(a.w.db) == after
    assert calls == [] and sends == [1]


@pytest.mark.asyncio
async def test_status_settles_an_expired_approved_uv_once_without_signing(admissions, monkeypatch):
    a = admissions
    operation = root_operation(a)
    assert (await prepare(a, operation)).status_code == 200
    options = await a.human.signer.approval_options(operation.operation_id, human=a.actor)
    emit = a.human.signer._emit

    async def failed(kind, *args, **kwargs):
        if kind is AuditKind.PROTECTED_OPERATION_SIGNED:
            raise RuntimeError("audit unavailable")
        return await emit(kind, *args, **kwargs)

    monkeypatch.setattr(a.human.signer, "_emit", failed)
    with pytest.raises(RuntimeError, match="audit unavailable"):
        await a.human.signer.execute(operation.operation_id, a.device.get(dict(options)), human=a.actor)
    future = datetime.now(UTC) + timedelta(seconds=301)
    a.human.signer.clock = lambda: future
    before, original_row = await snapshot(a.w.db), await operation_row(a, operation)
    assert original_row["signed_result"] is None and original_row["evidence_ref"] is None
    calls = forbid_effects(a, monkeypatch)
    response = await read(a, operation)
    assert response.status_code == 200 and response.json() == {"state": "refused", "code": "approval_expired"}
    after, settled = await snapshot(a.w.db), await operation_row(a, operation)
    assert {key for key in settled if settled[key] != original_row[key]} <= {"refusal_code", "candidate_links"}
    assert json.loads(settled["candidate_links"]) == {} and settled["expires_at"] > a.human.signer.clock()
    settled_history_only(before, after)
    again = await read(a, operation)
    assert again.status_code == 200 and again.json() == response.json()
    assert await snapshot(a.w.db) == after and calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["malformed", "unknown", "wrong_scope", "other_requester", "unavailable", "retired_key"])
async def test_status_refusals_create_nothing_and_leave_history_unchanged(admissions, monkeypatch, case):
    a = admissions
    operation = root_operation(a)
    assert (await prepare(a, operation)).status_code == 200
    path = "/protected-operations/" + operation.operation_id
    context, key, principal = operation.context, a.w.root, a.w.root_id
    expected = (403, "scope_refused")
    if case == "malformed":
        path = "/protected-operations/not-an-operation-id"
        expected = (400, "request_invalid")
    elif case == "unknown":
        path = "/protected-operations/" + str(uuid4())
        expected = (404, "operation_not_found")
    elif case == "wrong_scope":
        context = replace(context, service_id="another-service")
        expected = (401, "requester_invalid")
    elif case == "other_requester":
        key = SigningKey.generate()
        principal = (await a.w.registry.register_did(
            did(key), bytes(key))).did_aw
    elif case == "unavailable":
        async def unavailable(*args, **kwargs):
            raise RegistryError("registry unavailable", status_code=503)
        monkeypatch.setattr(a.w.registry, "resolve_key_fresh", unavailable)
        expected = (503, "receipt_unavailable")
    elif case == "retired_key":
        replacement = SigningKey.generate()
        await a.w.registry.rotate_key(a.w.root_id, did(replacement), bytes(a.w.root), bytes(replacement))
        expected = (401, "requester_invalid")
    before = await snapshot(a.w.db)
    calls = forbid_effects(a, monkeypatch)
    proof = dict(proof_request(a.w, key=key, path=path, method="GET", operation="protected_operation_receipt", context=context).headers)
    proof["X-AWEB-DID-AW"] = principal
    for _ in range(2):
        response = await a.client.get(path, headers=proof)
        assert (response.status_code, response.json()) == (expected[0], {"detail": expected[1]})
        assert await snapshot(a.w.db) == before
    assert calls == []


@pytest.mark.asyncio
async def test_status_recovers_a_genuine_retained_effect_after_unknown_without_another_send(
    admissions, tmp_path, test_db_factory, monkeypatch
):
    a = admissions
    async with ready_owner_act_consumer(a.w, tmp_path, test_db_factory) as consumer:
        operation = owner_act_operation(a.w.operation)
        assert (await prepare(a, operation)).status_code == 200
        custody, signer = consumer.custody, a.w.app.signer
        confirm = custody.confirm_retained

        async def unavailable(*args):
            return None

        monkeypatch.setattr(custody, "confirm_retained", unavailable)
        options = await signer.approval_options(operation.operation_id, human=a.w.human)
        await signer.execute(operation.operation_id, a.w.device.get(dict(options)), human=a.w.human)
        original_row = await operation_row(a, operation)
        assert original_row["result"] is None and original_row["retained_effect"] is not None
        assert original_row["delivery_claim"] is not None
        assert await consumer.db.fetch_value("SELECT count(*) FROM holding") == 0
        consumer_before = {table: await consumer.db.fetch_all("SELECT * FROM " + table)
            for table in ("owner_act_nonces", "protected_effect_receipts")}
        assert len(consumer_before["owner_act_nonces"]) == len(consumer_before["protected_effect_receipts"]) == 1
        signer.clock = lambda: original_row["expires_at"] + timedelta(seconds=1)
        before = await snapshot(a.w.db)
        calls = forbid_effects(a, monkeypatch)
        for _ in range(2):
            response = await read(a, operation)
            assert response.status_code == 200 and response.json() == {
                "state": "unknown", "code": "external_effect_unresolved"}, response.text
            assert await snapshot(a.w.db) == before
        # The exact proof-gated historical receipt becomes available. This
        # read may settle application, but cannot mint/release another bundle.
        monkeypatch.setattr(custody, "confirm_retained", confirm)
        response = await read(a, operation)
        assert response.status_code == 200 and response.json()["state"] == "committed", response.text
        assert response.json()["result"]["delivery"]["state"] == "applied"
        settled = await operation_row(a, operation)
        assert {key for key in settled if settled[key] != original_row[key]} == {"result", "committed_at"}
        after = await snapshot(a.w.db)
        settled_history_only(before, after)
        again = await read(a, operation)
        assert again.status_code == 200 and again.json() == response.json()
        assert await snapshot(a.w.db) == after
        for table, rows in consumer_before.items():
            assert await consumer.db.fetch_all("SELECT * FROM " + table) == rows
        assert calls == []


@pytest.mark.asyncio
async def test_status_confirmation_expiry_rolls_back_result_quota_and_audit(admissions, monkeypatch):
    a = admissions
    await endorse(a)
    custody, signer = a.w.app.authority.custody, a.w.app.signer
    original = custody.register_admission

    async def lost(*args):
        await original(*args)
        raise SignerRefused("receipt_unavailable")

    monkeypatch.setattr(custody, "register_admission", lost)
    operation = admit_operation(a)
    assert (await prepare(a, operation)).status_code == 200
    assert (await execute(a, operation)).status_code == 503
    provider = signer.admission
    confirm = provider.confirm
    now = signer.clock()

    async def delayed(*args):
        # The actual confirmation quota write occurs before the original
        # read's 60-second observation expires; the final fence must roll it back.
        await confirm(*args)
        signer.clock = lambda: now + timedelta(seconds=61)

    monkeypatch.setattr(provider, "confirm", delayed)
    before = await snapshot(a.w.db)
    calls = forbid_effects(a, monkeypatch)
    response = await read(a, operation)
    assert response.status_code == 503 and response.json() == {"detail": "receipt_unavailable"}, response.text
    assert await snapshot(a.w.db) == before and calls == []
