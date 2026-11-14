"""Additive owner row: a closed target and the existing revocation wire."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from aweb_naapp.runtime.protected_signer import CatalogOperation, SignerRefused
from aweb_naapp.runtime.protected_signer.codecs import artifact_for, signing_bytes
from aweb_naapp.runtime.protected_signer.execution_intent import prepare_artifact_intent
from tests.runtime.test_protected_member_removal import CONTROLLER, operation, subject


def owner_operation(**changes):
    fields = subject()
    del fields["root_id_or_self"]
    fields.update(changes)
    return CatalogOperation(str(uuid4()), operation(fields).context, operation(fields).audience,
        "team.agent.remove", "owner_approved", fields)


def test_owner_removal_has_a_closed_subject_live_floor_and_existing_wire():
    op = owner_operation()
    assert op.spec.needs_human and not op.spec.supports_self_removal
    assert op.spec.effect.provider == "owner_removal"
    assert op.spec.prepared_fields == {"requester_key", "target_kind"}
    artifact = artifact_for(op, CONTROLLER, datetime.now(UTC))
    assert artifact["request"]["certificate_id"] == op.subject["certificate_id"]
    assert artifact["request"]["operation"] == "revoke_certificate"
    assert signing_bytes(op, artifact)
    assert "{/target_kind}" in " ".join(op.spec.display.consequences)


@pytest.mark.parametrize("changes", [{"root_id_or_self": "self"}, {"kind": "agent"}, {"owner_uv": True}])
def test_owner_subject_never_supplies_its_authority_or_classification(changes):
    with pytest.raises(SignerRefused, match="request_invalid"):
        owner_operation(**changes)


def test_generated_page_accepts_owner_removal_and_refuses_frozen_substitutions():
    import json
    import subprocess
    from pathlib import Path

    from aweb_naapp.runtime.protected_signer.catalog import presentation_catalog

    op = owner_operation()
    request = {**op.intent(), "artifact": prepare_artifact_intent(op, CONTROLLER, datetime.now(UTC).replace(microsecond=0), datetime.now(UTC).replace(microsecond=0) + timedelta(minutes=10)),
        "requester_key": CONTROLLER, "target_kind": "kind not verified"}
    script = r'''
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {validateProtectedPresentation} from './src/aweb_naapp/assets/protected-presentation.mjs';
import {coveredRequestDigest} from './src/aweb_naapp/assets/canonical-json.mjs';
const {request,table}=JSON.parse(readFileSync(0,'utf8'));
const state={mode:'governance',handoff_id:'handoff',state:'pending',operation_id:request.operation_id,
 expires_at:'2026-11-13T12:10:00Z',payload:{policy:{ref:'aweb.human-assurance/1',version:1},request}};
for (const kind of ['agent','kind not verified']) {
 state.payload.request.target_kind=kind;
 state.digest=await coveredRequestDigest(state.payload);
 await validateProtectedPresentation(state,'handoff',table);
}
for (const mutate of [
 r=>r.target_kind='human', r=>r.target_kind='service',
 r=>r.subject.expected_membership.owner=true,
 r=>delete r.subject.expected_membership.member_did_aw,
 r=>r.artifact.template.request.certificate_id='another',
 r=>r.artifact.template.request.body_sha256='0'.repeat(64),
 r=>r.artifact.template.request.path='/wrong', r=>r.artifact.template.request.aud='https://wrong.example',
]) {
 const changed=structuredClone(state); mutate(changed.payload.request);
 changed.digest=await coveredRequestDigest(changed.payload);
 await assert.rejects(validateProtectedPresentation(changed,'handoff',table));
}
'''
    result = subprocess.run(["node", "--input-type=module", "-e", script],
        input=json.dumps({"request": request, "table": presentation_catalog()}),
        cwd=Path(__file__).resolve().parents[2], capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.asyncio
async def test_requester_key_never_replaces_the_owner_live_floor():
    from aweb_naapp.runtime.protected_signer import ProtectedSigner, RestrictedRequester

    op = owner_operation()
    requester = RestrictedRequester("requester", op.context, CONTROLLER)
    service = object.__new__(ProtectedSigner)

    async def authorized(operation_id, actor, purpose):
        assert operation_id == op.operation_id and actor is requester and purpose == "execute"
        return {"request": op.intent()}

    service._authorized = authorized
    with pytest.raises(SignerRefused, match="live_approval_required"):
        await service._execute_request(op.operation_id, requester=requester)


@pytest.mark.asyncio
async def test_human_delivery_keeps_the_original_uv_deadline_not_the_retry_time():
    from datetime import timedelta
    from types import SimpleNamespace

    from aweb_naapp.runtime.protected_signer import ProtectedSigner

    issued = datetime(2026, 11, 13, 12, tzinfo=UTC)
    row = {"expires_at": issued + timedelta(hours=24), "evidence_ref": "retained",
        "approval_id": "exact", "digest": "frozen"}
    metadata = {"purpose": "approve", "approval_id": "exact", "request_sha256": "frozen",
        "challenge_issued_at": issued.isoformat(), "challenge_expires_at": (issued + timedelta(minutes=10)).isoformat()}

    async def retained(reference):
        assert reference == "retained"
        return SimpleNamespace(metadata=metadata)

    service = object.__new__(ProtectedSigner)
    service.passkeys = SimpleNamespace(retained_proof=retained)
    op = owner_operation()
    from aweb_naapp.runtime.protected_signer.execution_intent import (
        materialize_artifact,
        prepare_artifact_intent,
    )

    descriptor = prepare_artifact_intent(op, CONTROLLER, issued, row["expires_at"])
    row.update(request={**op.intent(), "artifact": descriptor},
        issued_artifact=materialize_artifact(op, descriptor, issued))
    assert await service._signed_deadline(row) == issued + timedelta(seconds=300)
    metadata["request_sha256"] = "another request"
    with pytest.raises(SignerRefused, match="evidence_unavailable"):
        await service._signed_deadline(row)


@pytest.mark.asyncio
@pytest.mark.parametrize("human_reader", [False, True])
@pytest.mark.parametrize("expired", [False, True])
async def test_composed_historical_receipt_guard_covers_owner_and_requester(human_reader, expired):
    import json
    from datetime import timedelta

    from aweb_naapp.runtime.protected_signer import AdmittedHuman, ProtectedSigner, ReceiptReader

    op = owner_operation()
    assert op.spec.effect.invalidates_membership is True
    actor = (AdmittedHuman(op.context.human_id, "owner-subject", "owner-scope", op.context)
        if human_reader else ReceiptReader("requester", op.context, CONTROLLER))
    now = datetime.now(UTC)
    row = {"operation_id": op.operation_id, "request": json.dumps(op.intent()),
        "result": None, "signed_result": {"retained": "historical row"}, "refusal_code": None,
        "retained_effect": None, "approval_id": None, "verification_claim": None,
        "expires_at": now + timedelta(seconds=-1 if expired else 60)}
    service = object.__new__(ProtectedSigner)
    service.clock = lambda: now
    service.owner_removal = None

    async def authorized(operation_id, reader, purpose, **kwargs):
        assert (operation_id, reader, purpose) == (op.operation_id, actor, "receipt")
        return row

    async def unavailable(*args, **kwargs):
        pytest.fail("absent-provider history must not enter reconciliation or delivery")

    service._authorized, service._reconcile_admission = authorized, unavailable
    receipt = await service.receipt(op.operation_id, reader=actor)
    assert (receipt.state, receipt.code) == (("unknown", "external_effect_unresolved")
        if expired else ("pending", "effect_in_progress"))
    assert receipt.result is None and row["result"] is None
