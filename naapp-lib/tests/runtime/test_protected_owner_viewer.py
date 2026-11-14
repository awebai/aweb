"""Session-derived presentation metadata; authority/SQL have native controls."""

from copy import deepcopy

import httpx
import pytest
from fastapi import FastAPI

from aweb_naapp.runtime.protected_signer import OperationReceipt, ProtectedSigner, SignerRefused
from aweb_naapp.runtime.protected_signer.http import ProtectedOperationsHTTP
from tests.runtime.test_protected_owner_initiation import initiation, owned_row


def inspection_ports(case):
    actor, op = initiation()
    row = owned_row(actor, op)
    if case == "requester":
        row["initiator_subject"] = row["initiator_scope"] = None
    if case == "other_subject":
        row["initiator_subject"] = "another-owner"
    if case == "other_scope":
        row["initiator_scope"] = "another-scope"
    engine = object.__new__(ProtectedSigner)
    calls = []

    async def authorized(operation_id, human, purpose, *, human_session=None):
        assert (operation_id, human, human_session) == (op.operation_id, actor.human, actor.session)
        assert purpose == "approval"
        calls.append(purpose)
        return row

    engine._authorized = authorized
    return engine, actor, op, row, calls


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["owner", "requester", "other_subject", "other_scope"])
async def test_requested_by_you_compares_private_initiator_with_the_current_session(case):
    engine, actor, op, row, calls = inspection_ports(case)
    before = deepcopy(row)
    result = await engine.requested_by_you(op.operation_id, human=actor.human, human_session=actor.session)
    assert result is (case == "owner")
    assert calls == ["approval"] and row == before


@pytest.mark.asyncio
async def test_viewer_label_requires_a_session_and_never_hides_unavailable_authority():
    engine, actor, op, _, calls = inspection_ports("owner")
    with pytest.raises(SignerRefused, match="console_session_required"):
        await engine.requested_by_you(op.operation_id, human=actor.human)
    assert calls == []

    async def unavailable(*args, **kwargs):
        raise SignerRefused("evidence_unavailable")

    engine._authorized = unavailable
    with pytest.raises(SignerRefused, match="evidence_unavailable"):
        await engine.requested_by_you(op.operation_id, human=actor.human, human_session=actor.session)


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["owner", "requester", "other_subject", "other_scope"])
async def test_human_state_adds_the_label_outside_the_frozen_request(case):
    engine, actor, op, row, calls = inspection_ports(case)

    async def receipt(operation_id, **kwargs):
        assert kwargs == {"reader": actor.human, "human_session": actor.session}
        return OperationReceipt(operation_id, "pending", code="awaiting_human", expires_at="2026-11-14T12:00:00Z")

    async def human(handoff_id, request):
        assert handoff_id == row["handoff_id"]
        return op.operation_id, actor.human, actor.session

    engine.receipt = receipt
    mount = object.__new__(ProtectedOperationsHTTP)
    mount.signer, mount._human = engine, human
    app = FastAPI()
    app.include_router(mount.human_router())
    before = deepcopy(row)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://human.example") as client:
        answer = await client.get(f'/handoff/{row["handoff_id"]}/governance')
    assert answer.status_code == 200, answer.text
    data = answer.json()
    assert data["requested_by_you"] is (case == "owner")
    assert data["payload"]["request"] == before["request"]
    assert data["digest"] == before["digest"] and row == before
    assert "requested_by_you" not in data["payload"]["request"]
    assert "initiator_subject" not in data and "initiator_scope" not in data
    assert calls == ["approval", "approval"]
