"""Native writes retain their current policy decision until the row commits."""

import asyncio
from enum import Enum, auto

import asyncpg
import pytest

from aweb.inbound_modes import set_identity_inbound_mode
from aweb.application_state import application_registry_client
from aweb.lifecycle import (
    LifecycleActor,
    LifecycleCascadeRequest,
    apply_lifecycle_cascade,
)
from messaging_actor_support import admit_messaging_actor, set_messaging_inbound_mode
from test_dashboard_privacy import TEAM, privacy_app as privacy_app
from test_messages_http import _signed_team_headers
from test_delivery_contract_regressions import _send

__all__ = ["privacy_app"]


async def connect_policy_members(env):
    """Establish the positive current-admission premise through the real endpoint."""
    for alias in ("alice", "bob"):
        actor = env.actors[alias]
        content = b"{}"
        connected = await env.client.post(
            "/v1/connect",
            content=content,
            headers={
                **_signed_team_headers(
                    actor.sk, actor.did, TEAM, actor.certificate, content
                ),
                "Content-Type": "application/json",
            },
        )
        assert connected.status_code == 200, connected.text
        assert connected.json()["agent_id"] == str(actor.id)
        assert (
            await env.db.fetch_value(
                "SELECT accepted_team_did_key FROM {{tables.agents}} WHERE agent_id=$1",
                actor.id,
            )
            == env.team_did
        )


async def prepare_test_policy_members(env):
    await connect_policy_members(env)
    bob = await admit_messaging_actor(
        env, alias="bob", team_id=TEAM, signing_key=env.actors["bob"].sk
    )
    await set_messaging_inbound_mode(env, bob, "team_and_contacts")
    return bob


async def apply_test_policy_change(tx, env, change, bob):
    if change is PolicyChange.RECIPIENT_MODE:
        await set_identity_inbound_mode(tx, bob.stable_id, "contacts_only")
        return
    alice = env.actors["alice"]
    result = await apply_lifecycle_cascade(
        tx,
        env.redis,
        LifecycleCascadeRequest(
            operation="delete_local_workspace",
            actor=LifecycleActor(str(alice.id), "agent", "team_identity"),
            team_id=TEAM,
            target_agent_id=str(alice.id),
            target_workspace_ids=(str(alice.workspace),),
            require_identity_scope="local",
            mark_local_agent_deleted=True,
        ),
        registry_client=application_registry_client(env.app.state),
    )
    assert result.identity_deleted, result.errors


class MailPath(Enum):
    NEW_THREAD = auto()
    CONTINUATION = auto()


class PolicyChange(Enum):
    SENDER_RETIREMENT = auto()
    RECIPIENT_MODE = auto()


@pytest.mark.asyncio
@pytest.mark.parametrize("path", list(MailPath))
@pytest.mark.parametrize("change", list(PolicyChange))
async def test_native_mail_admission_stays_locked_through_the_actual_message_commit(
    privacy_app,
    path,
    change,
):
    env = privacy_app
    bob = await prepare_test_policy_members(env)
    payload = {"to_did": bob.did_key, "body": "Held native send"}
    count_before = 0
    if path is MailPath.CONTINUATION:
        initial = await _send(env, {"to_did": bob.did_key, "body": "Existing thread"})
        assert initial.status_code == 200, initial.text
        payload = {
            "conversation_id": initial.json()["conversation_id"],
            "body": "Held continuation",
        }
        count_before = 1
    events_before = list(env.dispatched)
    relation = (
        "aweb.messages" if path is MailPath.CONTINUATION else "aweb.conversations"
    )
    async with env.db.transaction() as blocker:
        if path is MailPath.CONTINUATION:
            await blocker.execute("LOCK TABLE {{tables.messages}} IN SHARE MODE")
        else:
            await blocker.execute("LOCK TABLE {{tables.conversations}} IN SHARE MODE")
        sending = asyncio.create_task(_send(env, payload))
        try:
            async with asyncio.timeout(5):
                while not await env.db.fetch_value(
                    "SELECT count(*) FROM pg_locks WHERE relation=$1::regclass "
                    "AND mode='RowExclusiveLock' AND NOT granted",
                    relation,
                ):
                    if sending.done():
                        raise AssertionError(
                            "Send ended before its actual INSERT barrier"
                        )
                    await asyncio.sleep(0.01)
            assert env.dispatched == events_before
            async with env.db.transaction() as changing:
                await changing.execute("SET LOCAL lock_timeout='200ms'")
                with pytest.raises(asyncpg.LockNotAvailableError):
                    await apply_test_policy_change(changing, env, change, bob)
        except BaseException:
            sending.cancel()
            await asyncio.gather(sending, return_exceptions=True)
            raise
    sent = await sending
    assert sent.status_code == 200, sent.text
    assert (
        await env.db.fetch_value("SELECT count(*) FROM {{tables.messages}}")
        == count_before + 1
    )
    assert len(env.dispatched) == len(events_before) + 1
    # The lock ends with the send; subsequent policy changes must take effect.
    async with env.db.transaction() as changing:
        await apply_test_policy_change(changing, env, change, bob)
    if change is PolicyChange.RECIPIENT_MODE:
        refused = await _send(env, payload)
        assert refused.status_code == 403, refused.text
        assert refused.json()["detail"].endswith(
            "Ask the recipient to add your exact address as a contact or check their inbound policy."
        )
        assert (
            await env.db.fetch_value("SELECT count(*) FROM {{tables.messages}}")
            == count_before + 1
        )
