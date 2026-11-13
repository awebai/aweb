"""One mount dispatches exact contexts to instances of the same executor."""

from dataclasses import replace
from types import SimpleNamespace

import pytest
from aweb_naapp.runtime.protected_signer import SignerRefused

from aweb.protected_signing.group import ProtectedSignerGroup
from tests.test_protected_admission_policy import CONTEXT


def component(context):
    class Engine:
        def __init__(self):
            self.db = DB
            self.passkeys = SimpleNamespace(_proof_context=None)
            self.policies = object()
            self.calls = []

        async def prepare(self, op, *, requester):
            self.calls.append((op, requester))
            return context

    engine = Engine()
    return SimpleNamespace(context=context, db=DB, passkeys=engine.passkeys, signer=engine,
        registry=object(), authority=object(), request_origin="https://signer.example.org")


DB = object()


@pytest.mark.asyncio
async def test_group_routes_only_the_exact_provisioned_context_to_the_shared_executor():
    other = replace(CONTEXT, authority_kind="human_identity", authority_id=CONTEXT.human_id)
    team, human = component(CONTEXT), component(other)
    group = ProtectedSignerGroup([team, human], selected=team)
    for c in (team, human):
        operation = SimpleNamespace(context=c.context)
        requester = SimpleNamespace(context=c.context)
        assert await group.signer.prepare(operation, requester=requester) == c.context
        assert c.signer.calls == [(operation, requester)]
    assert group.passkeys is team.passkeys
    changed = replace(CONTEXT, generation=CONTEXT.generation+1)
    with pytest.raises(SignerRefused, match="scope_refused"):
        await group.signer.prepare(SimpleNamespace(context=changed), requester=SimpleNamespace(context=changed))
    assert len(team.signer.calls) == 1


def test_group_refuses_a_component_from_another_database_or_origin():
    first, second = component(CONTEXT), component(replace(CONTEXT, authority_id="other:customer.example"))
    second.db = object()
    with pytest.raises(ValueError):
        ProtectedSignerGroup([first, second], selected=first)
    second.db = DB
    second.request_origin = "https://other.example.org"
    with pytest.raises(ValueError):
        ProtectedSignerGroup([first, second], selected=first)
