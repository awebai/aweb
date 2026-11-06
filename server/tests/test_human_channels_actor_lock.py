"""Public actor projection locking and host presence CAS on real PostgreSQL.

Global rows here are explicit projection fixtures, not independent AWID proof.
The portable presence verifier and both concurrent database transactions are real.
"""

import asyncio
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
import hashlib
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from awid.did import stable_id_from_did_key
from awid.signing import canonical_json_bytes

from aweb.human_channels import authority
from aweb.human_channels.authority import NativeMessagingSubject
from aweb.human_channels.contract import ContractError, canonical_record, decode_record
from aweb.human_channels.presence import (
    PresenceCaller, PresenceIdentity, PresenceVerificationContext,
    sign_presence_record, verify_native_presence,
)
from test_messages_http import _build_test_app, _insert_agent, _insert_team, _make_keypair


def record(schema, value):
    return decode_record(schema, canonical_json_bytes(value))


@pytest_asyncio.fixture
async def actor_presence(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    team, other_team = 'presence:example.test', 'other:example.test'
    await _insert_team(db, team)
    await _insert_team(db, other_team)
    bindings, seeds = [], []
    for alias, global_actor in [('subject', False), ('owner', True)]:
        seed, _, key = _make_keypair()
        principal = stable_id_from_did_key(key) if global_actor else key
        actor_id = await _insert_agent(
            db, team_id=team, alias=alias, did_key=key,
            did_aw=principal if global_actor else None, address=None,
        )
        if not global_actor:
            await db.execute("UPDATE {{tables.agents}} SET identity_scope='local' WHERE agent_id=$1", UUID(actor_id))
        bindings.append(NativeMessagingSubject(principal, key, actor_id, team))
        seeds.append(seed)
    await db.execute('CREATE TABLE public.host_presence_activation (actor_id UUID PRIMARY KEY, signing_key TEXT, generation INTEGER)')
    now = datetime.now(UTC).replace(microsecond=0)
    subject = record('NativeParticipant', {'kind': 'native', 'did': bindings[0].principal})
    scope = record('PresenceScope', {'kind': 'platform'})
    intent = record('PresenceIntent', dict(
        version='aweb-presence-intent-v1', operation='register', subject=subject.value,
        platform='telegram', scope=scope.value, mode='native', audience='http://presence.test',
        expected_generation=0, request_id=str(uuid4()), authorization='subject',
        signer=bindings[0].principal, signing_key_id=bindings[0].signing_key_id,
        issued_at=now.isoformat().replace('+00:00', 'Z'),
        expires_at=(now + timedelta(minutes=5)).isoformat().replace('+00:00', 'Z'),
    ))
    yield SimpleNamespace(
        db=db, infra=_build_test_app(db, None).state.db, bindings=tuple(bindings),
        subject=subject, scope=scope, intent=intent,
        artifact=sign_presence_record(intent, seeds[0]), other_team=other_team,
    )


async def activate(env, tx, expected=None):
    # This is the host's transaction: the library only locks its own projection.
    facts = await authority.lock_native_actors(env.infra, tx.connection, expected or env.bindings)
    current = next(f for f in facts if f.actor_id == env.bindings[0].actor_id)
    identity = PresenceIdentity(current.principal, current.signing_key_id, True)
    checked = verify_native_presence(env.artifact, PresenceVerificationContext(
        subject=env.subject, subject_active=True, platform='telegram', scope=env.scope,
        mode='native', audience='http://presence.test', authorization_revision='policy-1',
        subject_identity=identity, caller=PresenceCaller(identity, True),
        expected_intent_hash='sha256:' + hashlib.sha256(canonical_record(env.intent)).hexdigest(),
        expected_generation=0, consumed_request_ids=frozenset(), now=datetime.now(UTC),
        max_ttl_seconds=300, max_clock_skew_seconds=30,
    ))
    assert checked.schema == 'VerifiedPresence'
    await tx.execute('INSERT INTO public.host_presence_activation VALUES ($1,$2,1)', UUID(current.actor_id), current.signing_key_id)
    return facts


async def assert_no_send_effects(db):
    for table in ('messages', 'conversations', 'chat_sessions', 'chat_messages',
                  'human_channel_sends', 'human_channel_ingress', 'human_channel_mutations'):
        assert await db.fetch_value('SELECT count(*) FROM {{tables.' + table + '}}') == 0


@pytest.mark.asyncio
async def test_actor_lock_returns_immutable_exact_local_and_global_facts_in_outer_transaction(actor_presence):
    env = actor_presence
    async with env.db.transaction() as tx:
        facts = await activate(env, tx, tuple(reversed(env.bindings)))
        assert isinstance(facts, tuple)
        assert set(facts) == set(env.bindings)
        with pytest.raises(FrozenInstanceError):
            facts[0].signing_key_id = env.bindings[1].signing_key_id
        # The primitive neither commits the host's write nor uses another connection.
        assert await env.db.fetch_value('SELECT count(*) FROM public.host_presence_activation') == 0
    assert await env.db.fetch_value('SELECT count(*) FROM public.host_presence_activation') == 1
    await assert_no_send_effects(env.db)


@pytest.mark.asyncio
async def test_actor_lock_does_not_commit_on_host_rollback(actor_presence):
    env = actor_presence
    class HostFailure(Exception):
        pass
    with pytest.raises(HostFailure):
        async with env.db.transaction() as tx:
            await activate(env, tx)
            raise HostFailure()
    assert await env.db.fetch_value('SELECT count(*) FROM public.host_presence_activation') == 0
    await assert_no_send_effects(env.db)


@pytest.mark.asyncio
@pytest.mark.parametrize('change,code', [
    ('key', 'stale'), ('principal', 'stale'), ('team', 'stale'),
    ('inactive', 'forbidden'), ('deleted', 'forbidden'), ('missing', 'forbidden'),
    ('unverified', 'stale'), ('actor', 'forbidden'),
])
async def test_actor_lock_refuses_changed_or_unavailable_bindings_before_presence_write(actor_presence, change, code):
    env = actor_presence
    local, global_actor = env.bindings
    expected = env.bindings
    if change == 'key':
        await env.db.execute('UPDATE {{tables.agents}} SET did_key=$1 WHERE agent_id=$2', _make_keypair()[2], UUID(local.actor_id))
    elif change == 'principal':
        await env.db.execute('UPDATE {{tables.agents}} SET did_aw=$1 WHERE agent_id=$2', stable_id_from_did_key(_make_keypair()[2]), UUID(global_actor.actor_id))
    elif change == 'team':
        await env.db.execute('UPDATE {{tables.agents}} SET team_id=$1 WHERE agent_id=$2', env.other_team, UUID(local.actor_id))
    elif change == 'inactive':
        await env.db.execute("UPDATE {{tables.agents}} SET status='retired' WHERE agent_id=$1", UUID(local.actor_id))
    elif change == 'deleted':
        await env.db.execute('UPDATE {{tables.agents}} SET deleted_at=now() WHERE agent_id=$1', UUID(local.actor_id))
    elif change == 'missing':
        await env.db.execute('DELETE FROM {{tables.agents}} WHERE agent_id=$1', UUID(local.actor_id))
    elif change == 'unverified':
        await env.db.execute('UPDATE {{tables.agents}} SET did_aw_verified_key=NULL WHERE agent_id=$1', UUID(global_actor.actor_id))
    elif change == 'actor':
        expected = (replace(local, actor_id=str(uuid4())), global_actor)
    with pytest.raises(ContractError) as error:
        async with env.db.transaction() as tx:
            await activate(env, tx, expected)
    assert error.value.code == code
    assert await env.db.fetch_value('SELECT count(*) FROM public.host_presence_activation') == 0
    await assert_no_send_effects(env.db)


@pytest.mark.asyncio
async def test_actor_lock_requires_an_open_transaction(actor_presence, shared_test_pool):
    env = actor_presence
    async with shared_test_pool.acquire() as connection:
        with pytest.raises(ContractError) as error:
            await authority.lock_native_actors(env.infra, connection, env.bindings)
        assert error.value.code == 'invalid'


async def wait_for_blocker(db, waiter, blocker, task):
    # Observe PostgreSQL's lock graph, not elapsed time or task scheduling.
    async with asyncio.timeout(5):
        while not await db.fetch_value('SELECT $1::int=ANY(pg_blocking_pids($2))', blocker, waiter):
            if task.done():
                await task
                pytest.fail('operation completed without waiting for its actor lock')
            await asyncio.sleep(0.01)


async def change_actor(tx, actor_id, change):
    if change == 'rotation':
        await tx.execute('UPDATE {{tables.agents}} SET did_key=$1 WHERE agent_id=$2', _make_keypair()[2], UUID(actor_id))
    else:
        await tx.execute("UPDATE {{tables.agents}} SET deleted_at=now(),status='deleted' WHERE agent_id=$1", UUID(actor_id))


@pytest.mark.asyncio
@pytest.mark.parametrize('change', ['rotation', 'deletion'])
async def test_actor_lock_serializes_rotation_or_deletion_after_presence_commit(actor_presence, change):
    env = actor_presence
    mutator_pid = asyncio.get_running_loop().create_future()
    async def mutate():
        async with env.db.transaction() as tx:
            mutator_pid.set_result(await tx.fetch_value('SELECT pg_backend_pid()'))
            await change_actor(tx, env.bindings[0].actor_id, change)
    task = None
    try:
        async with env.db.transaction() as tx:
            locker_pid = await tx.fetch_value('SELECT pg_backend_pid()')
            await activate(env, tx)
            task = asyncio.create_task(mutate())
            await wait_for_blocker(env.db, await mutator_pid, locker_pid, task)
            assert not task.done()
            assert await env.db.fetch_value('SELECT count(*) FROM public.host_presence_activation') == 0
        await asyncio.wait_for(task, 5)
        assert await env.db.fetch_value('SELECT count(*) FROM public.host_presence_activation') == 1
        # A later activation cannot reuse the pre-change projection.
        with pytest.raises(ContractError) as error:
            async with env.db.transaction() as tx:
                await activate(env, tx)
        assert error.value.code == ('stale' if change == 'rotation' else 'forbidden')
        await assert_no_send_effects(env.db)
    finally:
        if task is not None:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize('change', ['rotation', 'deletion'])
async def test_actor_lock_rechecks_change_that_commits_while_activation_waits(actor_presence, change):
    env = actor_presence
    activation_pid = asyncio.get_running_loop().create_future()
    async def activation():
        async with env.db.transaction() as tx:
            activation_pid.set_result(await tx.fetch_value('SELECT pg_backend_pid()'))
            await activate(env, tx)
    task = None
    try:
        async with env.db.transaction() as tx:
            mutator_pid = await tx.fetch_value('SELECT pg_backend_pid()')
            await change_actor(tx, env.bindings[0].actor_id, change)
            task = asyncio.create_task(activation())
            await wait_for_blocker(env.db, await activation_pid, mutator_pid, task)
        with pytest.raises(ContractError) as error:
            await asyncio.wait_for(task, 5)
        assert error.value.code == ('stale' if change == 'rotation' else 'forbidden')
        assert await env.db.fetch_value('SELECT count(*) FROM public.host_presence_activation') == 0
        await assert_no_send_effects(env.db)
    finally:
        if task is not None:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
