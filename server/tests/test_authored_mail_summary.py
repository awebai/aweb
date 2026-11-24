"""Authored-mail summary shares native visibility and historical attribution."""

import json
from datetime import UTC, datetime
from unittest.mock import patch
from uuid import UUID, uuid4

import pytest
from nacl.signing import SigningKey

from awid.did import did_from_public_key, stable_id_from_did_key
from aweb.db import TransactionInfra
from aweb.identity_auth_deps import MessagingAuth
from aweb.lifecycle_agent import AgentDisposition, apply_agent_disposition_on
from aweb.messaging.conversations import ConversationParticipant, create_conversation
from aweb.messaging.kinds import MessagePriority
from aweb.messaging.mail_attribution import has_authored_mail
from aweb.messaging.mail_storage import (
    MailAttestation,
    MailRecipient,
    MailSender,
    MailStorageInput,
    PlaintextMailContent,
    store_mail,
)
from aweb.messaging.participant_succession import succeed_local_human_participant_on
from aweb_naapp_contracts_testing import Member
from aweb_naapp_contracts_testing.human_members import HumanNamespace
from test_dashboard_privacy import TEAM, privacy_app

__all__ = ["privacy_app"]


def _auth():
    key = did_from_public_key(bytes(SigningKey.generate().verify_key))
    return MessagingAuth(did_key=key, did_aw=stable_id_from_did_key(key), address=None)


async def _admit_human(env, alias):
    member = Member(
        team_id=TEAM,
        team_key=SigningKey(bytes(env.team_sk)),
        certificate_id=str(uuid4()),
        alias=alias,
    )
    authority = HumanNamespace(
        registry=env.registry,
        client=env.app.state.awid_registry_client,
        controller_seed=bytes(env.namespace_sk),
        controller_did=env.namespace_did,
        domain="example.test",
        authority=env.registry.namespace_authority,
    )
    registered = await authority.register(member)
    body = json.dumps({"agent_type": "human"}).encode()
    response = await env.client.post(
        "/v1/connect",
        content=body,
        headers={
            **member.headers(
                aud=str(env.client.base_url).rstrip("/"),
                method="POST",
                path="/v1/connect",
                body=body,
            ),
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 200, response.text
    agent_id = UUID(response.json()["agent_id"])
    assert (
        await env.db.fetch_value(
            "SELECT human_verified_key FROM {{tables.agents}} WHERE agent_id=$1",
            agent_id,
        )
        == member.did_key
    )
    return MessagingAuth(
        did_key=member.did_key, did_aw=registered.principal, address=None
    ), agent_id


async def _succeed(db, *, old, old_id, viewer):
    async with db.transaction() as tx:
        assert (
            await apply_agent_disposition_on(
                tx,
                agent_ids=[old_id],
                team_id=TEAM,
                disposition=AgentDisposition.RETIRED,
                deleted_at=datetime.now(UTC),
            )
            == 1
        )
        await succeed_local_human_participant_on(
            tx, predecessor_did=old.did_aw, successor_did=viewer.did_aw
        )


async def _thread(db, viewer, *, key=None):
    other = _auth()
    result = await create_conversation(
        TransactionInfra(None, db),
        conversation_type="mail",
        created_by_did=viewer.did_aw,
        initiator=ConversationParticipant(
            did=viewer.did_aw, current_did_key=key, transport_hint="local"
        ),
        recipients=[ConversationParticipant(did=other.did_aw, transport_hint="local")],
    )
    return UUID(result["conversation_id"]), other


async def _mail(db, sender, target, thread=None, *, body="mail"):
    # The storage owner preserves the admitted artifact's sender spelling. Both
    # the canonical ID and the historical thread-local key are read inputs here.
    await store_mail(
        TransactionInfra(None, db),
        message=MailStorageInput(
            sender=MailSender(did=sender),
            recipient=MailRecipient(did=target),
            content=PlaintextMailContent(subject="Authorship", body=body),
            attestation=MailAttestation(),
            priority=MessagePriority.NORMAL,
            conversation_id=thread,
        ),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "author", ["canonical", "thread-key", "predecessor", "predecessor-key"]
)
async def test_authored_summary_shares_readable_thread_attribution(privacy_app, author):
    env = privacy_app
    if author.startswith("predecessor"):
        viewer, _ = await _admit_human(env, "successor-author")
        old, old_id = await _admit_human(env, "original-author")
        thread, other = await _thread(env.db, old, key=old.did_key)
        sender = old.did_key if author == "predecessor-key" else old.did_aw
        await _mail(env.db, sender, other.did_aw, thread)
        await _succeed(env.db, old=old, old_id=old_id, viewer=viewer)
    else:
        viewer = _auth()
        thread, other = await _thread(env.db, viewer, key=viewer.did_key)
        sender = viewer.did_key if author == "thread-key" else viewer.did_aw
        await _mail(env.db, sender, other.did_aw, thread)
    assert await has_authored_mail(db=env.db, auth=viewer)


@pytest.mark.asyncio
async def test_incoming_unrelated_and_unthreaded_predecessor_are_not_authorship(
    privacy_app,
):
    env = privacy_app
    viewer, _ = await _admit_human(env, "successor-author")
    old, old_id = await _admit_human(env, "original-author")
    own_thread, other = await _thread(env.db, viewer)
    foreign_thread, foreign_other = await _thread(env.db, _auth())
    # No thread included the predecessor, so the product records the identity
    # succession without granting the viewer any additional thread history.
    await _succeed(env.db, old=old, old_id=old_id, viewer=viewer)
    await _mail(env.db, old.did_aw, other.did_aw, own_thread)
    await _mail(env.db, old.did_key, foreign_other.did_aw, foreign_thread)
    await _mail(env.db, old.did_aw, other.did_aw)
    await _mail(env.db, other.did_aw, viewer.did_aw, own_thread)
    await _mail(env.db, viewer.did_aw, foreign_other.did_aw, foreign_thread)
    assert not await has_authored_mail(db=env.db, auth=viewer)
    await _mail(env.db, viewer.did_aw, other.did_aw)
    assert await has_authored_mail(db=env.db, auth=viewer)


@pytest.mark.asyncio
async def test_large_mailbox_summary_is_one_existence_read(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    viewer, other = _auth(), _auth()
    async with db.transaction() as tx:
        for _ in range(2000):
            await _mail(tx, other.did_aw, viewer.did_aw, body="mail" * 512)
        await _mail(tx, viewer.did_aw, other.did_aw)
    with patch.object(db, "fetch_value", wraps=db.fetch_value) as observed:
        assert await has_authored_mail(db=db, auth=viewer)
    observed.assert_awaited_once()
