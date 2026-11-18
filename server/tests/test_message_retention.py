"""Native ownership/interest retention; hosted plan classification is separate."""

import asyncio
import shutil
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from nacl.signing import SigningKey
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager

from awid.did import did_from_public_key
from aweb.db import TransactionInfra
from aweb.migrations import apply_native_migrations, native_migration_modules
from aweb.message_retention import (
    MessageReference, RetentionSweepScope, apply_team_message_retention,
    preview_team_message_retention, record_message_retention_owners,
)
from aweb.messaging.chat import ensure_session
from aweb.messaging.conversations import ConversationParticipant, create_conversation
from aweb.service_errors import ConflictError, ValidationError
from aweb.team_admission import admit_team


def _did():
    return did_from_public_key(bytes(SigningKey.generate().verify_key))


@pytest_asyncio.fixture
async def retained_pair(aweb_cloud_db):
    return await _pair(aweb_cloud_db.aweb_db)


async def _pair(db):
    left, right = _did(), _did()
    teams = ("short:retention.example", "long:retention.example")
    for team in teams:
        await admit_team(db=db, team_id=team, team_did_key=_did())
    infra = TransactionInfra(None, db)
    conversation = await create_conversation(
        infra, conversation_type="mail", created_by_did=left,
        initiator=ConversationParticipant(left), recipients=[ConversationParticipant(right)], team_id=teams[0],
    )
    session = await ensure_session(
        infra, team_id=teams[0], created_by=left,
        participant_rows=[{"did": left, "alias": "left"}, {"did": right, "alias": "right"}],
    )
    mail, chat = uuid4(), uuid4()
    received = datetime.now(timezone.utc) - timedelta(days=40)
    await db.execute(
        "INSERT INTO {{tables.messages}} (message_id,from_did,to_did,body,team_id,conversation_id,created_at) "
        "VALUES ($1,$2,$3,'retained mail',$4,$5,$6)", mail, left, right, teams[0],
        UUID(conversation["conversation_id"]), received,
    )
    await db.execute(
        "INSERT INTO {{tables.chat_messages}} (message_id,session_id,from_did,from_alias,body,created_at) "
        "VALUES ($1,$2,$3,'left','retained chat',$4)", chat, session, left, received,
    )
    references = (MessageReference("mail", mail), MessageReference("chat", chat))
    return db, teams, left, right, references


async def _classify(pair, *, right=True):
    db, teams, left_did, right_did, references = pair
    for ref in references:
        await record_message_retention_owners(db, message=ref, party_did=left_did, owner_team_ids=frozenset([teams[0]]))
        if right:
            await record_message_retention_owners(db, message=ref, party_did=right_did, owner_team_ids=frozenset([teams[1]]))


def _scope(team):
    return RetentionSweepScope(team_id=team, cutoff=datetime.now(timezone.utc) - timedelta(days=30))


async def _counts(db):
    return (
        await db.fetch_value("SELECT count(*) FROM {{tables.messages}}"),
        await db.fetch_value("SELECT count(*) FROM {{tables.chat_messages}}"),
    )


def test_cutoff_must_be_timezone_aware():
    with pytest.raises(ValidationError) as refused:
        RetentionSweepScope(team_id="short:retention.example", cutoff=datetime(2026, 1, 1))
    assert "Use a timezone-aware UTC cutoff, then retry." in str(refused.value)


@pytest.mark.asyncio
async def test_default_and_incomplete_party_coverage_retain_data(retained_pair):
    db, teams, _, _, _ = retained_pair
    absent = await preview_team_message_retention(db, scope=_scope(teams[0]))
    assert absent.unclassified_retained == 2
    assert (absent.mail_would_delete, absent.chat_would_delete) == (0, 0)
    await _classify(retained_pair, right=False)
    incomplete = await preview_team_message_retention(db, scope=_scope(teams[0]))
    assert incomplete.unclassified_retained == 2
    result = await apply_team_message_retention(db, preview=incomplete)
    assert (result.mail_interests_expired, result.chat_interests_expired) == (1, 1)
    assert (result.mail_deleted, result.chat_deleted) == (0, 0)
    assert await _counts(db) == (1, 1)


@pytest.mark.asyncio
async def test_first_team_sweep_preserves_other_team_then_preview_permits_last_delete(retained_pair):
    db, teams, _, _, _ = retained_pair
    await _classify(retained_pair)
    participants = await db.fetch_value("SELECT count(*) FROM {{tables.conversation_participants}}")
    receipts = await db.fetch_value("SELECT count(*) FROM {{tables.message_ingress_receipts}}")
    first = await preview_team_message_retention(db, scope=_scope(teams[0]))
    assert (first.mail_interests_expiring, first.chat_interests_expiring) == (1, 1)
    assert (first.mail_would_delete, first.chat_would_delete) == (0, 0)
    assert await db.fetch_value("SELECT count(*) FROM {{tables.message_retention_interests}} WHERE expired_at IS NOT NULL") == 0
    await apply_team_message_retention(db, preview=first)
    assert await _counts(db) == (1, 1)
    last = await preview_team_message_retention(db, scope=_scope(teams[1]))
    assert (last.mail_would_delete, last.chat_would_delete) == (1, 1)
    assert await _counts(db) == (1, 1)
    result = await apply_team_message_retention(db, preview=last)
    assert (result.mail_deleted, result.chat_deleted) == (1, 1)
    assert await _counts(db) == (0, 0)
    assert await db.fetch_value("SELECT count(*) FROM {{tables.conversation_participants}}") == participants
    assert await db.fetch_value("SELECT count(*) FROM {{tables.message_ingress_receipts}}") == receipts
    repeated = await apply_team_message_retention(db, preview=last)
    assert (repeated.mail_interests_expired, repeated.chat_interests_expired, repeated.mail_deleted, repeated.chat_deleted) == (0, 0, 0, 0)


@pytest.mark.asyncio
async def test_conflicting_owner_replacement_and_forged_preview_refuse_actionably(retained_pair):
    db, teams, left, _, references = retained_pair
    await _classify(retained_pair)
    with pytest.raises(ConflictError) as conflict:
        await record_message_retention_owners(db, message=references[0], party_did=left, owner_team_ids=frozenset([teams[1]]))
    assert str(conflict.value).endswith("Resolve the ownership transfer explicitly before retrying classification.")
    preview = await preview_team_message_retention(db, scope=_scope(teams[0]))
    with pytest.raises(ConflictError) as forged:
        await apply_team_message_retention(db, preview=replace(preview, scope=_scope(teams[1])))
    assert str(forged.value).endswith("Run a new retention preview for this team and cutoff, then try again.")
    assert await _counts(db) == (1, 1)


@pytest.mark.asyncio
@pytest.mark.parametrize("classify_new", [False, True])
async def test_new_history_party_after_preview_blocks_deletion(retained_pair, classify_new):
    db, teams, _, _, references = retained_pair
    await _classify(retained_pair)
    await apply_team_message_retention(db, preview=await preview_team_message_retention(db, scope=_scope(teams[0])))
    preview = await preview_team_message_retention(db, scope=_scope(teams[1]))
    assert preview.mail_would_delete == 1
    cid = await db.fetch_value("SELECT conversation_id FROM {{tables.messages}} WHERE message_id=$1", references[0].message_id)
    new_party = _did()
    await db.execute("INSERT INTO {{tables.conversation_participants}} (conversation_id,did,alias) VALUES ($1,$2,'new')", cid, new_party)
    if classify_new:
        await record_message_retention_owners(db, message=references[0], party_did=new_party, owner_team_ids=frozenset([teams[1]]))
    result = await apply_team_message_retention(db, preview=preview)
    assert (result.mail_deleted, result.chat_deleted) == (0, 1)
    assert result.unclassified_retained == (0 if classify_new else 1)


@pytest.mark.asyncio
async def test_concurrent_team_sweeps_do_not_delete_unpreviewed_rows(retained_pair):
    db, teams, _, _, _ = retained_pair
    await _classify(retained_pair)
    previews = [await preview_team_message_retention(db, scope=_scope(team)) for team in teams]
    results = await asyncio.gather(*(apply_team_message_retention(db, preview=preview) for preview in previews))
    assert sum(result.mail_deleted + result.chat_deleted for result in results) == 0
    assert await _counts(db) == (1, 1)
    final = await apply_team_message_retention(db, preview=await preview_team_message_retention(db, scope=_scope(teams[0])))
    assert (final.mail_deleted, final.chat_deleted) == (1, 1)


@pytest.mark.asyncio
async def test_legacy_absent_coverage_is_unknown_even_after_current_parties_are_classified(shared_test_pool, tmp_path):
    db = AsyncDatabaseManager(pool=shared_test_pool, schema="aweb")
    await db.execute('CREATE SCHEMA "aweb"')
    core = native_migration_modules()[0]
    retention_file = next(core.migrations_path.glob("*_message_retention.sql"))
    for source in core.migrations_path.glob("*.sql"):
        if source.name < retention_file.name:
            shutil.copy2(source, tmp_path / source.name)
    await AsyncMigrationManager(db, migrations_path=str(tmp_path), module_name=core.module_name).apply_pending_migrations()
    pair = await _pair(db)
    await apply_native_migrations(db)
    assert await db.fetch_value("SELECT count(*) FROM {{tables.message_retention_coverage}}") == 0
    await _classify(pair)
    for team in pair[1]:
        preview = await preview_team_message_retention(db, scope=_scope(team))
        assert preview.unclassified_retained == 2
        assert (preview.mail_would_delete, preview.chat_would_delete) == (0, 0)
        await apply_team_message_retention(db, preview=preview)
    assert await _counts(db) == (1, 1)


@pytest.mark.asyncio
async def test_pending_delivery_blocks_deletion_and_batches_are_explicit(retained_pair):
    db, teams, _, _, references = retained_pair
    await _classify(retained_pair)
    batch = await preview_team_message_retention(db, scope=_scope(teams[0]), limit=1)
    assert batch.batch_count == 1 and batch.next_after is not None
    following = await preview_team_message_retention(db, scope=_scope(teams[0]), limit=1, after=batch.next_after)
    assert following.batch_count == 1 and following.next_after is None
    await apply_team_message_retention(db, preview=batch)
    await apply_team_message_retention(db, preview=following)
    await db.execute(
        "INSERT INTO {{tables.federation_mutation_outbox}} (message_id,event_type,payload_json) VALUES ($1,'message.sent','{}'::jsonb)",
        references[0].message_id,
    )
    last = await preview_team_message_retention(db, scope=_scope(teams[1]))
    assert (last.mail_would_delete, last.chat_would_delete) == (0, 1)
    result = await apply_team_message_retention(db, preview=last)
    assert (result.mail_deleted, result.chat_deleted) == (0, 1)
    await db.execute("UPDATE {{tables.federation_mutation_outbox}} SET delivered_at=clock_timestamp()")
    delivered = await apply_team_message_retention(db, preview=await preview_team_message_retention(db, scope=_scope(teams[1])))
    assert (delivered.mail_deleted, delivered.chat_deleted) == (1, 0)
