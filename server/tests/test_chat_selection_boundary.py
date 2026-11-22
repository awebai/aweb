"""Internal chat selection is a named value before any lookup can run."""

import pytest
from starlette.datastructures import State

from aweb.identity_auth_deps import MessagingAuth
from aweb.messaging.chat_models import CreateSessionRequest
from aweb.messaging.chat_send import (
    ChatSessionSelection,
    ChatTarget,
    resolve_chat_targets,
)
from aweb.messaging.runtime import messaging_runtime
from did_key_fixtures import named_did_key


class LookupReached(Exception):
    """The valid selector reached its first lookup; no database is involved."""


class LookupBoundary:
    def get_manager(self, name):
        raise LookupReached(name)


async def resolve_selection(selection):
    return await resolve_chat_targets(
        LookupBoundary(),
        MessagingAuth(did_key=named_did_key("sender"), did_aw=None, address=None),
        CreateSessionRequest(to_dids=[named_did_key("recipient")], message="hello"),
        messaging_runtime(State()),
        "unit",
        session_selection=selection,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("selection", [False, True, "reuse_pair", None, 0])
async def test_chat_resolver_refuses_unnamed_selection_before_any_read(selection):
    with pytest.raises(TypeError) as refused:
        await resolve_selection(selection)
    assert str(refused.value) == "Pass a named ChatSessionSelection value."


@pytest.mark.parametrize("selection", [False, True, "reuse_pair", None, 0])
def test_chat_target_uses_the_same_named_selection_guard(selection):
    with pytest.raises(TypeError) as refused:
        ChatTarget(recipients=[], source="unit", session_selection=selection)
    assert str(refused.value) == "Pass a named ChatSessionSelection value."


@pytest.mark.asyncio
@pytest.mark.parametrize("selection", list(ChatSessionSelection))
async def test_chat_resolver_accepts_each_named_selection_for_lookup(selection):
    with pytest.raises(LookupReached):
        await resolve_selection(selection)
