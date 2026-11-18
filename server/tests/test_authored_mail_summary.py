"""Authored-mail summary shares native visibility and historical attribution."""

from uuid import UUID, uuid4

import pytest
from nacl.signing import SigningKey

from awid.did import did_from_public_key, stable_id_from_did_key
from aweb.db import TransactionInfra
from aweb.identity_auth_deps import MessagingAuth
from aweb.messaging.conversations import ConversationParticipant, create_conversation
from aweb.messaging.mail_attribution import has_authored_mail


def _auth():
    key = did_from_public_key(bytes(SigningKey.generate().verify_key))
    return MessagingAuth(did_key=key, did_aw=stable_id_from_did_key(key), address=None)


async def _thread(db, viewer, *, key=None):
    other = _auth()
    result = await create_conversation(
        TransactionInfra(None, db), conversation_type="mail", created_by_did=viewer.did_aw,
        initiator=ConversationParticipant(did=viewer.did_aw, current_did_key=key),
        recipients=[ConversationParticipant(did=other.did_aw)],
    )
    return UUID(result["conversation_id"]), other


async def _mail(db, sender, target, thread=None):
    await db.execute(
        "INSERT INTO {{tables.messages}} (message_id,from_did,to_did,body,conversation_id) "
        "VALUES ($1,$2,$3,'mail',$4)", uuid4(), sender, target, thread,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("author", ["canonical", "thread-key", "predecessor", "predecessor-key"])
async def test_authored_summary_shares_readable_thread_attribution(aweb_cloud_db, author):
    db = aweb_cloud_db.aweb_db
    viewer, old = _auth(), _auth()
    thread, other = await _thread(db, viewer, key=viewer.did_key)
    if author.startswith("predecessor"):
        # Existing native succession evidence, scoped to this exact thread.
        await db.execute(
            "INSERT INTO {{tables.local_human_successions}} (predecessor_did,predecessor_did_key,successor_did) "
            "VALUES ($1,$2,$3)", old.did_aw, old.did_key, viewer.did_aw,
        )
        await db.execute(
            "INSERT INTO {{tables.conversation_participant_successions}} "
            "(conversation_id,predecessor_did,predecessor_alias) VALUES ($1,$2,'old')", thread, old.did_aw,
        )
    sender = {"canonical": viewer.did_aw, "thread-key": viewer.did_key,
              "predecessor": old.did_aw, "predecessor-key": old.did_key}[author]
    await _mail(db, sender, other.did_aw, thread)
    assert await has_authored_mail(db=db, auth=viewer)


@pytest.mark.asyncio
async def test_incoming_unrelated_and_unthreaded_predecessor_are_not_authorship(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    viewer, old, stranger = _auth(), _auth(), _auth()
    own_thread, other = await _thread(db, viewer)
    foreign_thread, foreign_other = await _thread(db, stranger)
    await db.execute(
        "INSERT INTO {{tables.local_human_successions}} (predecessor_did,predecessor_did_key,successor_did) "
        "VALUES ($1,$2,$3)", old.did_aw, old.did_key, viewer.did_aw,
    )
    # A global succession mapping alone grants no thread history.
    await _mail(db, old.did_aw, other.did_aw, own_thread)
    await _mail(db, old.did_key, foreign_other.did_aw, foreign_thread)
    await _mail(db, old.did_aw, other.did_aw)
    await _mail(db, other.did_aw, viewer.did_aw, own_thread)
    await _mail(db, viewer.did_aw, foreign_other.did_aw, foreign_thread)
    assert not await has_authored_mail(db=db, auth=viewer)
    await _mail(db, viewer.did_aw, other.did_aw)
    assert await has_authored_mail(db=db, auth=viewer)


@pytest.mark.asyncio
async def test_large_mailbox_summary_is_one_existence_read(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    viewer, other = _auth(), _auth()
    await db.execute(
        "INSERT INTO {{tables.messages}} (message_id,from_did,to_did,body) "
        "SELECT gen_random_uuid(),$1,$2,repeat('mail',2048) FROM generate_series(1,2000)",
        other.did_aw, viewer.did_aw,
    )
    await _mail(db, viewer.did_aw, other.did_aw)

    class CountedReads:
        def __init__(self):
            self.count = 0

        async def fetch_value(self, query, *args):
            self.count += 1
            return await db.fetch_value(query, *args)

    observed = CountedReads()
    assert await has_authored_mail(db=observed, auth=viewer)
    assert observed.count == 1
