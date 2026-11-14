"""Owner expiry and signed-outcome projection port controls; native cases separate."""

from contextlib import asynccontextmanager
from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace

import pytest

from aweb_naapp.runtime.protected_signer import ProtectedSigner, SignerRefused
from tests.runtime.test_protected_identity_artifacts import NOW
from tests.runtime.test_protected_owner_initiation import initiation, owned_row


def ports(row, actor, *, unavailable=False):
    events, commits = [], []
    engine = object.__new__(ProtectedSigner)
    engine.clock = lambda: NOW + timedelta(hours=25)

    async def prepare(tx, human):
        assert human is actor.human

    async def check(tx, human):
        assert human is actor.human
        if unavailable:
            raise SignerRefused("evidence_unavailable")

    async def observe(*args, **kwargs):
        return SimpleNamespace(prepare=prepare, check=check, require_fresh=lambda: None)

    async def lock(tx, operation_id):
        assert operation_id == actor.operation_id
        return row

    async def hold(tx, human, session):
        assert human is actor.human and session is actor.session

    async def current(tx, session):
        assert session is actor.session

    async def emit(event, tx):
        events.append(event)

    async def update(query, *args):
        assert "refusal_code" in query and args[0] == actor.operation_id
        row["refusal_code"], row["candidate_links"] = "operation_expired", {}

    @asynccontextmanager
    async def transaction():
        saved, audit = deepcopy(row), len(events)
        try:
            yield SimpleNamespace(execute=update)
        except Exception:
            row.clear()
            row.update(saved)
            del events[audit:]
            raise
        else:
            commits.append(True)

    engine.db = SimpleNamespace(transaction=transaction)
    engine.authority, engine.audit = SimpleNamespace(observe=observe), SimpleNamespace(emit=emit)
    engine._lock, engine._hold_session, engine._check_session = lock, hold, current
    return engine, events, commits


@pytest.mark.asyncio
@pytest.mark.parametrize("state", ["unsigned", "signed", "retained", "issued", "claimed", "unavailable"])
async def test_only_an_authenticated_unsigned_expiry_becomes_a_stored_final_refusal(state):
    actor, op = initiation()
    actor = replace(actor, session=replace(actor.session, expires_at=NOW + timedelta(hours=48)))
    row = owned_row(actor, op)
    row.update(result=None, signed_result=None, retained_effect=None, issued_artifact=None, delivery_claim=None,
        refusal_code=None, approval_id="approval", candidate_links={actor.human.subject: "private"})
    column = {"signed": "signed_result", "retained": "retained_effect", "issued": "issued_artifact", "claimed": "delivery_claim"}.get(state)
    if column is not None:
        row[column] = {"original": "unresolved"}
    before = deepcopy(row)
    engine, events, commits = ports(row, actor, unavailable=state == "unavailable")
    if state == "unsigned":
        with pytest.raises(SignerRefused, match="operation_expired"):
            await engine.owner_prepared(actor)
        assert commits == [True]  # The refusal is committed before the 410 is raised.
        assert row["refusal_code"] == "operation_expired" and row["candidate_links"] == {}
        assert len(events) == 1 and events[0].kind.value == "protected_operation_refused"
        assert all(row[name] == before[name] for name in ("intent", "request", "digest", "expires_at", "initiation_selection"))
    elif state == "unavailable":
        with pytest.raises(SignerRefused, match="evidence_unavailable"):
            await engine.owner_prepared(actor)
        assert row == before and events == [] and commits == []
    else:
        assert (await engine.owner_prepared(actor)).operation_id == op.operation_id
        assert row == before and events == []


@pytest.mark.asyncio
async def test_a_fresh_pending_owner_selection_is_not_retired():
    actor, op = initiation()
    row = owned_row(actor, op)
    row.update(result=None, signed_result=None, retained_effect=None, issued_artifact=None, delivery_claim=None,
        refusal_code=None, approval_id="approval", candidate_links={})
    engine, events, _ = ports(row, actor)
    engine.clock = lambda: NOW
    assert (await engine.owner_prepared(actor)).payload == row["request"]
    assert row["refusal_code"] is None and events == []


@pytest.mark.asyncio
@pytest.mark.parametrize("code", ["operation_expired", "gesture_expired"])
async def test_expiry_after_a_retained_signature_is_unknown_even_while_the_human_wait_is_open(code):
    actor, op = initiation()
    row = owned_row(actor, op)
    row.update(result=None, signed_result={"signing": "retained", "signature": "retained"}, retained_effect=None,
        refusal_code=None, approval_id="approval", verification_claim=None)
    before = deepcopy(row)
    engine = object.__new__(ProtectedSigner)
    engine.clock = lambda: NOW + timedelta(seconds=301)

    async def checked(*args, **kwargs):
        pass

    async def observe(*args, **kwargs):
        return SimpleNamespace(prepare=checked, check=checked, require_fresh=lambda: None)

    async def route(*args):
        return {"request": row["request"]}

    async def lock(*args):
        return row

    async def authorized(*args, **kwargs):
        return row

    @asynccontextmanager
    async def transaction():
        yield object()

    engine.db = SimpleNamespace(fetch_one=route, transaction=transaction)
    engine.authority = SimpleNamespace(observe=observe)
    engine._lock, engine._authorized = lock, authorized
    receipt = await engine._execution_refusal(op.operation_id, actor.human, SignerRefused(code))
    assert (receipt.state, receipt.code) == ("unknown", "external_effect_unresolved")
    assert row == before
