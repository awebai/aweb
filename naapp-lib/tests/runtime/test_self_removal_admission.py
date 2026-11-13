"""A self-removal port carries one exact admitted request, never membership."""

from dataclasses import replace
from types import SimpleNamespace
from uuid import uuid4

import pytest

from aweb_naapp.runtime.protected_signer import (
    ProtectedKeyContext,
    ReceiptReader,
    RestrictedRequester,
    SignerRefused,
)
from aweb_naapp.runtime.protected_signer.types import _admitted_self_removal, _checked_self_removal

CONTEXT = ProtectedKeyContext("service", "team_controller", "team:example.org", "example.org", "did:aw:human", "example.org", 1)


def operation(**changes):
    intent = {"operation_id": str(uuid4()), "operation": "team.agent.remove", "variant": "default",
        "scope": CONTEXT.fields(), "audience": "https://registry.example.org",
        "subject": {"root_id_or_self": "self", "certificate_id": str(uuid4()), "member_id": "did:key:member"}, **changes}
    return SimpleNamespace(context=CONTEXT, operation_id=intent["operation_id"], intent=lambda: intent)


def test_a_valid_self_port_is_exact_request_bound_and_snapshots_the_body():
    op = operation()
    cap = _admitted_self_removal(op, principal="did:key:member", key_did="did:key:member", deadline=60.0)
    actor = RestrictedRequester("did:key:member", CONTEXT, key_did="did:key:member", self_removal=cap)
    assert _checked_self_removal(actor, operation=op) is cap
    reader = ReceiptReader(actor.principal, actor.context, key_did=actor.key_did, self_removal=cap)
    assert _checked_self_removal(reader, operation_id=op.operation_id) is cap
    op.intent()["subject"]["certificate_id"] = str(uuid4())
    with pytest.raises(SignerRefused, match="scope_refused"):
        _checked_self_removal(actor, operation=op)


@pytest.mark.parametrize("change", ["key", "principal", "context", "operation", "json"])
def test_self_evidence_cannot_be_reused_under_another_scope_key_or_operation(change):
    op = operation()
    cap = _admitted_self_removal(op, principal="did:key:member", key_did="did:key:member", deadline=60.0)
    actor = RestrictedRequester("did:key:member", CONTEXT, key_did="did:key:member", self_removal=cap)
    if change == "key":
        actor = replace(actor, key_did="did:key:other")
    elif change == "principal":
        actor = replace(actor, principal="did:aw:other")
    elif change == "context":
        actor = replace(actor, context=replace(CONTEXT, generation=2))
    elif change == "json":
        actor = replace(actor, self_removal={"operation_id": op.operation_id})
    else:
        op = operation()
    with pytest.raises(SignerRefused, match="scope_refused"):
        _checked_self_removal(actor, operation=op)


@pytest.mark.parametrize("name", ["team.agent.admit", "identity.root.endorse", "human-role.revoke"])
def test_self_admission_cannot_be_minted_for_a_different_effect(name):
    with pytest.raises(SignerRefused, match="scope_refused"):
        _admitted_self_removal(operation(operation=name), principal="did:key:member", key_did="did:key:member", deadline=60.0)


def test_the_released_two_argument_requester_and_reader_stay_source_compatible():
    assert _checked_self_removal(RestrictedRequester("did:aw:root", CONTEXT)) is None
    assert _checked_self_removal(ReceiptReader("did:aw:root", CONTEXT)) is None


@pytest.mark.parametrize("changes", [{"operation_id": str(uuid4())}, {"certificate_id": str(uuid4())}, {"deadline": float("nan")}])
def test_self_port_metadata_must_stay_consistent_with_its_snapshot(changes):
    op = operation()
    cap = _admitted_self_removal(op, principal="did:key:member", key_did="did:key:member", deadline=60.0)
    actor = RestrictedRequester("did:key:member", CONTEXT, key_did="did:key:member", self_removal=replace(cap, **changes))
    with pytest.raises(SignerRefused, match="scope_refused"):
        _checked_self_removal(actor, operation=op)
