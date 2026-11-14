"""Pure initiation-port and saved-selection controls; no session or UV shortcuts."""

from dataclasses import replace
from datetime import timedelta
from uuid import uuid4

import pytest
from awid.did import did_from_public_key
from nacl.signing import SigningKey

from aweb_naapp.console import ConsoleSession
from aweb_naapp.runtime.protected_signer import AdmittedHuman, SignerRefused
from tests.runtime.test_protected_identity_artifacts import NOW
from tests.runtime.test_protected_owner_removal import owner_operation


def initiation():
    from aweb_naapp.runtime.protected_signer.owner_initiation import _admitted_owner_initiation

    op = owner_operation()
    human = AdmittedHuman(op.context.human_id, "owner-subject", "owner-scope", op.context)
    session = ConsoleSession(human.subject, human.b3_scope, "login-evidence", NOW + timedelta(hours=24), b"t" * 32)
    selection = {"operation_id": op.operation_id, "operation": op.operation, "variant": op.variant,
        "team_id": op.context.authority_id, "certificate_id": op.subject["certificate_id"]}
    key = did_from_public_key(bytes(SigningKey.generate().verify_key))
    return _admitted_owner_initiation(selection, human=human, session=session, host_key_did=key), op


def test_owner_port_binds_the_session_selection_and_host_provenance_without_a_grant():
    from aweb_naapp.runtime.protected_signer.owner_initiation import _checked_owner_initiation

    actor, op = initiation()
    assert _checked_owner_initiation(actor, operation=op) is actor
    assert actor.principal == actor.key_did and actor.context == actor.human.context
    assert actor.selection["certificate_id"] == op.subject["certificate_id"]
    copied = actor.selection
    copied["certificate_id"] = str(uuid4())
    assert actor.selection["certificate_id"] == op.subject["certificate_id"]
    with pytest.raises(SignerRefused, match="operation_conflict"):
        _checked_owner_initiation(actor, operation=replace(op, operation_id=str(uuid4())))


@pytest.mark.parametrize("change", ["extra", "foreign_team", "other_row", "missing", "bad_id", "other_subject", "other_scope"])
def test_owner_initiation_does_not_accept_json_authority_or_another_session_binding(change):
    from aweb_naapp.runtime.protected_signer.owner_initiation import _admitted_owner_initiation

    actor, _ = initiation()
    selection, session = actor.selection, actor.session
    if change == "extra":
        selection["owner_uv"] = True
    if change == "foreign_team":
        selection["team_id"] = "another:example.org"
    if change == "other_row":
        selection["variant"] = "default"
    if change == "missing":
        del selection["certificate_id"]
    if change == "bad_id":
        selection["operation_id"] = "bad"
    if change == "other_subject":
        session = replace(session, subject="another-owner")
    if change == "other_scope":
        session = replace(session, scope="another-scope")
    with pytest.raises(SignerRefused):
        _admitted_owner_initiation(selection, human=actor.human, session=session, host_key_did=actor.key_did)


def test_public_json_cannot_supply_a_sealed_initiator():
    from aweb_naapp.runtime.protected_signer.owner_initiation import _checked_owner_initiation

    actor, _ = initiation()
    assert _checked_owner_initiation(actor.selection) is None
    with pytest.raises(SignerRefused):
        _checked_owner_initiation(replace(actor, _seal=object()))


def owned_row(actor, op):
    from aweb_naapp.runtime.protected_signer.execution_intent import prepare_artifact_intent

    request = {**op.intent(), "artifact": prepare_artifact_intent(op, actor.key_did, NOW, NOW + timedelta(hours=24)),
        "requester": actor.principal, "requester_key": actor.key_did, "target_kind": "agent",
        "policy_ref": "aweb.human-assurance/1", "policy_version": 1}
    return {"operation_id": op.operation_id, "handoff_id": str(uuid4()), "digest": "a" * 64,
        "request": request, "requester": actor.principal, "intent": b"original-intent",
        "expires_at": NOW + timedelta(hours=24), "initiator_subject": actor.human.subject,
        "initiator_scope": actor.human.b3_scope, "initiation_selection": actor._selection}


@pytest.mark.parametrize("change", ["same", "selection", "subject", "scope", "restricted"])
def test_saved_owner_selection_is_bound_before_any_target_refresh(change):
    from aweb_naapp.runtime.protected_signer import ProtectedSigner, RestrictedRequester
    from aweb_naapp.runtime.protected_signer.owner_initiation import _admitted_owner_initiation

    actor, op = initiation()
    row = owned_row(actor, op)
    if change == "selection":
        selection = {**actor.selection, "certificate_id": str(uuid4())}
        actor = _admitted_owner_initiation(selection, human=actor.human, session=actor.session, host_key_did=actor.key_did)
    if change == "subject":
        actor = _admitted_owner_initiation(actor.selection, human=replace(actor.human, subject="new-owner"),
            session=replace(actor.session, subject="new-owner"), host_key_did=actor.key_did)
    if change == "scope":
        actor = _admitted_owner_initiation(actor.selection, human=replace(actor.human, b3_scope="other-scope"),
            session=replace(actor.session, scope="other-scope"), host_key_did=actor.key_did)
    if change == "restricted":
        actor = RestrictedRequester(actor.principal, actor.context, actor.key_did)
    engine = object.__new__(ProtectedSigner)
    if change == "same":
        engine._check_prepare_owner(row, actor, intent=b"a newly observed snapshot is not adopted")
    else:
        with pytest.raises(SignerRefused, match="operation_conflict" if change == "selection" else "scope_refused"):
            engine._check_prepare_owner(row, actor)


@pytest.mark.asyncio
async def test_owner_prepare_reuses_the_saved_intent_under_current_owner_and_session_checks():
    from contextlib import asynccontextmanager
    from types import SimpleNamespace

    from aweb_naapp.runtime.protected_signer import ProtectedSigner

    actor, op = initiation()
    row = owned_row(actor, op)
    calls = []

    async def prepare(tx, admitted):
        assert admitted is actor.human  # Host provenance is never checked as a grant.
        calls.append("owner")

    async def check(tx, admitted):
        assert admitted is actor.human
        calls.append("owner-current")

    async def observe(context, *, purpose):
        assert context == actor.context and purpose == "prepare"
        return SimpleNamespace(prepare=prepare, check=check, require_fresh=lambda: None)

    async def session(tx, admitted, current):
        assert admitted is actor.human and current is actor.session
        calls.append("session")

    async def current(tx, current):
        assert current is actor.session
        calls.append("session-current")

    async def lock(tx, operation_id):
        assert operation_id == op.operation_id
        return row

    async def no_target_refresh(*args, **kwargs):
        pytest.fail("an owned retry must not refresh its target or create another approval")

    @asynccontextmanager
    async def transaction():
        yield object()

    engine = object.__new__(ProtectedSigner)
    engine.clock = lambda: NOW
    engine.authority = SimpleNamespace(observe=observe)
    engine.db = SimpleNamespace(transaction=transaction)
    engine.custody = SimpleNamespace(sign_operation=lambda *args: pytest.fail("prepare must not sign"))
    engine.owner_removal = SimpleNamespace(observe=no_target_refresh)
    engine._hold_session, engine._check_session, engine._lock = session, current, lock
    result = await engine.prepare(op, requester=actor)
    assert result.payload == row["request"] and result.expires_at.endswith("Z")
    assert calls == ["owner", "session", "session-current", "owner-current"]
