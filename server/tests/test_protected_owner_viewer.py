"""The grouped human route forwards viewer identity to its exact executor."""

from types import SimpleNamespace

import pytest

from aweb.protected_signing.group import _Executors


@pytest.mark.asyncio
@pytest.mark.parametrize("answer", [False, True])
async def test_group_forwards_the_actual_human_session_to_the_context_executor(answer):
    human, session = SimpleNamespace(context=object()), object()
    calls = []

    async def requested_by_you(operation_id, **kwargs):
        calls.append((operation_id, kwargs))
        return answer

    component = SimpleNamespace(signer=SimpleNamespace(requested_by_you=requested_by_you))

    def select(context):
        assert context is human.context
        return component

    executors = object.__new__(_Executors)
    executors.group = SimpleNamespace(component=select)
    assert await executors.requested_by_you("operation", human=human, human_session=session) is answer
    assert calls == [("operation", {"human": human, "human_session": session})]
