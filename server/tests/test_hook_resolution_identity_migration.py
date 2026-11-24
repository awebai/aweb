"""Own bindings answered for a binding from before installations carried an identity.

Migration 032 let a pending binding carry no installation id or generation, and
databases from then may still hold one; installs since migration 035 always
write both. The hook-resolution vector's answer for such a binding is checked
here, on the vector's scenario with that one row returned to its old state.
"""

import pytest
import pytest_asyncio

from tests.test_app_self_read_vectors import HOOKS, PRE_IDENTITY, check_hook_answer, env, hook_db  # noqa: F401

__all__ = ["env", "hook_db"]


@pytest_asyncio.fixture
async def pre_identity_db(hook_db):
    db, ids, _ = hook_db
    for label in PRE_IDENTITY:
        # unreachable-state: a pending binding written before installations carried an identity (migration 032)
        await db.execute(
            "UPDATE {{tables.app_hook_bindings}} SET installation_id = NULL, generation = NULL WHERE binding_id = $1",
            ids[label],
        )
    return hook_db


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "answer",
    [answer for answer in HOOKS["answers"] if PRE_IDENTITY & set(answer["labels"])],
    ids=lambda answer: answer["name"],
)
async def test_the_server_answers_a_binding_without_installation_identity(pre_identity_db, answer):
    await check_hook_answer(pre_identity_db, answer)
