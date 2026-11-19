"""Supported embedding against real PostgreSQL and host-owned authority tables."""

import json
from copy import deepcopy
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from aweb.human_channels.contract import ContractError, canonical_record, decode_record
from aweb.human_channels.native import NativeMessagingService
from aweb.identity_auth_deps import MessagingAuth
from awid.signing import canonical_json_bytes, sign_message
from test_messages_http import (
    _build_test_app,
    _insert_agent,
    _insert_team,
    _make_keypair,
)


def dto(schema, value):
    return decode_record(schema, canonical_json_bytes(value))


class HostAuthority:
    """An embedding using only its own tables plus public input/output DTOs."""

    def __init__(self, db, service):
        self.db, self.service = db, service

    async def current(self, auth, subject):
        row = await self.db.fetch_one(
            "SELECT * FROM public.host_authority WHERE actor_id=$1",
            UUID(subject.actor_id),
        )
        if not row:
            raise ContractError("authority_unavailable", "host authority")
        optional = {}
        if row["encryption_assertion"]:
            optional["key_assertion"] = json.loads(row["encryption_assertion"])
        return dto(
            "AuthorityFacts",
            dict(
                **optional,
                principal={"kind": "native", "did": row["principal"]},
                signing_key_id=row["signing_key"],
                route=self.service.value,
                custody=row["custody"],
                active=row["active"],
                access="allowed",
                inbound="allowed",
                confidentiality="hosted_readable",
                authorization_revision=str(row["revision"]),
                capabilities=[],
                actor_id=str(row["actor_id"]),
                team_id=subject.team_id,
            ),
        )

    async def authorize_recovery(self, auth, key, transaction):
        row = await transaction.fetchrow(
            "SELECT * FROM public.host_authority WHERE actor_id=$1 FOR UPDATE",
            UUID(auth.agent_id),
        )
        if (
            not row
            or row["principal"] != (auth.did_aw or auth.did_key)
            or row["signing_key"] != auth.did_key
            or not row["active"]
        ):
            raise ContractError("forbidden", "current requester")

    async def lock_authority(self, auth, prepared, ingress_key, transaction):
        await self.authorize_recovery(auth, ingress_key, transaction)
        refs = [(auth.agent_id, prepared.value["authority_revision"])]
        refs += [
            (r["actor_id"], r["authorization_revision"])
            for r in prepared.value["recipients"]
        ]
        for actor, revision in refs:
            row = await transaction.fetchrow(
                "SELECT * FROM public.host_authority WHERE actor_id=$1 FOR UPDATE",
                UUID(actor),
            )
            if not row or not row["active"] or str(row["revision"]) != revision:
                raise ContractError("stale", "host binding revision")


@pytest_asyncio.fixture
async def native_send(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    team = "protocol:example.test"
    await _insert_team(db, team)
    a_sk, _, a_did = _make_keypair()
    b_sk, _, b_did = _make_keypair()
    a = await _insert_agent(
        db,
        team_id=team,
        alias="agent",
        did_key=a_did,
        did_aw="did:aw:agent",
        address=None,
    )
    b = await _insert_agent(
        db,
        team_id=team,
        alias="human",
        did_key=b_did,
        did_aw="did:aw:human",
        address=None,
    )
    await db.execute(
        "UPDATE {{tables.agents}} SET agent_type='human', human_verified_key=did_key WHERE agent_id=$1", UUID(b)
    )
    await db.execute(
        "CREATE TABLE public.host_authority (actor_id UUID PRIMARY KEY,principal TEXT,signing_key TEXT,custody TEXT,active BOOLEAN,revision INTEGER,encryption_assertion JSONB)"
    )
    for actor, did, principal, custody in (
        (a, a_did, "did:aw:agent", "self_custodial"),
        (b, b_did, "did:aw:human", "hosted_custodial"),
    ):
        await db.execute(
            "INSERT INTO public.host_authority (actor_id,principal,signing_key,custody,active,revision) VALUES ($1,$2,$3,$4,true,1)",
            UUID(actor),
            principal,
            did,
            custody,
        )
    await db.execute(
        "CREATE TABLE public.host_ingress (ingress_key TEXT PRIMARY KEY,result JSONB)"
    )
    await db.execute(
        "CREATE TABLE public.host_published (mutation_id UUID PRIMARY KEY,event_type TEXT,context JSONB)"
    )
    service_binding = dto(
        "ServiceBinding",
        {
            "service": "did:aw:service",
            "signing_key_id": a_did,
            "audience": "http://native.test",
        },
    )
    provider = HostAuthority(db, service_binding)
    # No publisher until explicitly recovered: simulates commit->process crash.
    service = NativeMessagingService(
        _build_test_app(db, None).state.db, authority=provider, service=service_binding
    )
    auth = MessagingAuth(
        did_key=a_did,
        did_aw="did:aw:agent",
        address=None,
        team_id=team,
        alias="agent",
        agent_id=a,
    )
    target = await service.resolve(
        auth,
        dto(
            "ResolveRequest",
            {"version": "aweb-human-resolve-v1", "team_id": team, "selector": "human"},
        ),
    )

    async def prepared(kind="mail", message_id=None, body="native send", caller=None):
        cid, mid = str(uuid4()), message_id or str(uuid4())
        payload = dict(
            type=kind,
            from_did=a_did,
            to="human",
            to_did=b_did,
            from_stable_id="did:aw:agent",
            to_stable_id="did:aw:human",
            subject="test",
            body=body,
            timestamp=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            message_id=mid,
            conversation_id=cid,
            **{"from": "agent"},
        )
        signed = canonical_json_bytes(payload).decode()
        envelope = canonical_json_bytes(
            {"signed_payload": signed, "signature": sign_message(a_sk, signed.encode())}
        ).decode()
        request = dto(
            "PrepareRequest",
            {
                "version": "aweb-human-prepare-v1",
                "kind": kind,
                "message_id": mid,
                "author": {"kind": "native", "did": "did:aw:agent"},
                "envelope": envelope,
                "format": "native_plaintext",
                "target": target.value,
                "conversation_id": cid,
            },
        )
        return await service.prepare(caller or auth, request)

    key = dto(
        "IngressKey",
        {
            "issuer": "did:aw:agent",
            "namespace": "host",
            "key": "event-1",
            "input_hash": "sha256:" + "11" * 32,
        },
    )
    return {
        "db": db,
        "service": service,
        "auth": auth,
        "key": key,
        "prepared": prepared,
        "a": a,
        "b": b,
        "provider": provider,
        "signing_key": a_sk,
        "recipient_key": b_sk,
        "recipient_did": b_did,
        "app": _build_test_app(db, None),
    }


async def complete(env, prepared, *, fail=None, key=None):
    key = key or env["key"]
    async with env["service"].unit_of_work(env["auth"]) as uow:
        prior = await uow.claim_ingress(key)
        if prior:
            return prior
        accepted = await uow.accept(prepared)
        result = dto(
            "IngressResult",
            {
                "version": "aweb-ingress-result-v1",
                "key": key.value,
                "accepted": accepted.value,
                "result": {"correlation": "host-owned"},
            },
        )
        await uow.transaction.execute(
            "INSERT INTO public.host_ingress VALUES ($1,$2::jsonb)",
            key.value["key"],
            canonical_record(result).decode(),
        )
        if fail == "own_write":
            raise RuntimeError("provider operation failed")
        await uow.finish_ingress(result)
        return result


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
async def test_native_send_and_host_result_commit_once(native_send, kind):
    env = native_send
    if kind == "chat":
        # D8: this is the valid agent-chat neighbour; mail still reaches a human.
        await env["db"].execute("UPDATE {{tables.agents}} SET agent_type='agent' WHERE agent_id=$1", UUID(env["b"]))

    prepared = await env["prepared"](kind)
    result = await complete(env, prepared)
    assert canonical_record(await complete(env, prepared)) == canonical_record(result)
    message_table = "messages" if kind == "mail" else "chat_messages"
    for table in (
        message_table,
        "human_channel_sends",
        "human_channel_ingress",
        "human_channel_mutations",
    ):
        assert (
            await env["db"].fetch_one("SELECT count(*) n FROM {{tables." + table + "}}")
        )["n"] == 1
    assert (await env["db"].fetch_one("SELECT count(*) n FROM public.host_ingress"))[
        "n"
    ] == 1
    assert (await env["db"].fetch_one("SELECT count(*) n FROM public.host_published"))[
        "n"
    ] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure", ["own_write", "unfinished", "host_changed", "message_failure"]
)
async def test_native_send_rolls_back_every_write(native_send, failure):
    env = native_send
    prepared = await env["prepared"]()
    if failure == "host_changed":
        await env["db"].execute(
            "UPDATE public.host_authority SET revision=revision+1 WHERE actor_id=$1",
            UUID(env["b"]),
        )
    if failure == "message_failure":
        # A real DB failure at the message insertion, after conversation writes.
        await env["db"].execute(
            "ALTER TABLE {{tables.messages}} ADD CHECK (body <> 'native send')"
        )
    from asyncpg import CheckViolationError

    expected, match = {
        "own_write": (RuntimeError, "provider operation failed"),
        "unfinished": (ContractError, "unfinished ingress"),
        "host_changed": (ContractError, "stale: host binding revision"),
        "message_failure": (CheckViolationError, "messages_body_check"),
    }[failure]
    with pytest.raises(expected, match=match):
        if failure == "unfinished":
            async with env["service"].unit_of_work(env["auth"]) as uow:
                await uow.claim_ingress(env["key"])
                await uow.accept(prepared)
                await uow.transaction.execute(
                    "INSERT INTO public.host_ingress VALUES ('unfinished','{}'::jsonb)"
                )
        else:
            await complete(env, prepared, fail=failure)
    for table in (
        "messages",
        "conversations",
        "human_channel_sends",
        "human_channel_ingress",
        "human_channel_mutations",
    ):
        assert (
            await env["db"].fetch_one("SELECT count(*) n FROM {{tables." + table + "}}")
        )["n"] == 0
    assert (await env["db"].fetch_one("SELECT count(*) n FROM public.host_ingress"))[
        "n"
    ] == 0


@pytest.mark.asyncio
async def test_original_recovery_authorized_before_disclosure_and_hash_conflict(
    native_send,
):
    env = native_send
    prepared = await env["prepared"]()
    original = await complete(env, prepared)
    changed = deepcopy(env["key"])
    changed.value["input_hash"] = "sha256:" + "22" * 32
    with pytest.raises(ContractError, match="replay_conflict"):
        await env["service"].ingress_result(env["auth"], changed)
    # Recovery still requires current authority, even for an exact key.
    await env["db"].execute(
        "UPDATE public.host_authority SET active=false WHERE actor_id=$1",
        UUID(env["a"]),
    )
    with pytest.raises(ContractError, match="forbidden"):
        await env["service"].ingress_result(env["auth"], env["key"])
    assert original.value["accepted"]["replayed"] is False


@pytest.mark.asyncio
async def test_committed_intent_recovers_without_second_message(native_send):
    env = native_send
    prepared = await env["prepared"]()
    await complete(env, prepared)

    async def publish(mutation_id, event_type, context):
        await env["db"].execute(
            "INSERT INTO public.host_published VALUES ($1,$2,$3::jsonb) ON CONFLICT DO NOTHING",
            UUID(mutation_id),
            event_type,
            json.dumps(context),
        )

    # Simulate process restart with no in-memory preparation. Recovery uses only
    # the public current-authority and durable receipt/publication interfaces.
    service = NativeMessagingService(
        env["service"].db,
        authority=env["provider"],
        service=env["service"].service,
        publisher=publish,
    )
    await service.publish_pending()
    await service.publish_pending()
    assert (await service.ingress_result(env["auth"], env["key"])).value["accepted"][
        "message_id"
    ] == prepared.value["message_id"]
    assert (await env["db"].fetch_one("SELECT count(*) n FROM public.host_published"))[
        "n"
    ] == 1
    assert (await env["db"].fetch_one("SELECT count(*) n FROM {{tables.messages}}"))[
        "n"
    ] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    ["wrong_issuer", "tampered_preparation", "wrong_result", "unknown_preparation"],
)
async def test_native_uow_rejects_binding_conflicts(native_send, failure):
    env = native_send
    prepared = await env["prepared"]()
    key = deepcopy(env["key"])
    if failure == "wrong_issuer":
        key.value["issuer"] = "did:aw:other"
    if failure == "tampered_preparation":
        prepared.value["authority_revision"] = "other"
    if failure == "unknown_preparation":
        prepared.value["prepared_id"] = str(uuid4())
    with pytest.raises(ContractError, match="forbidden|invalid"):
        if failure == "wrong_result":
            async with env["service"].unit_of_work(env["auth"]) as uow:
                await uow.claim_ingress(key)
                accepted = await uow.accept(prepared)
                altered = deepcopy(key)
                altered.value["input_hash"] = "sha256:" + "44" * 32
                await uow.finish_ingress(
                    dto(
                        "IngressResult",
                        {
                            "version": "aweb-ingress-result-v1",
                            "key": altered.value,
                            "accepted": accepted.value,
                            "result": {},
                        },
                    )
                )
        else:
            await complete(env, prepared, key=key)
    assert (await env["db"].fetch_one("SELECT count(*) n FROM {{tables.messages}}"))[
        "n"
    ] == 0
    assert (await env["db"].fetch_one("SELECT count(*) n FROM public.host_ingress"))[
        "n"
    ] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
async def test_prepared_native_v2_preserves_exact_envelope_and_hosted_label(
    native_send, kind
):
    from aweb.e2ee_messages import (
        encrypt_e2ee_chat,
        encrypt_e2ee_mail,
        generate_x25519_keypair,
    )
    from awid.e2ee_keys import build_encryption_key_assertion

    env = native_send
    if kind == "chat":
        # D8: this is the valid agent-chat neighbour; mail still reaches a human.
        await env["db"].execute("UPDATE {{tables.agents}} SET agent_type='agent' WHERE agent_id=$1", UUID(env["b"]))

    identities = []
    for actor, did, principal, sk, custody in (
        (env["a"], env["auth"].did_key, "did:aw:agent", env["signing_key"], "self"),
        (
            env["b"],
            env["recipient_did"],
            "did:aw:human",
            env["recipient_key"],
            "hosted_custodial",
        ),
    ):
        private, public = generate_x25519_keypair()
        assertion = build_encryption_key_assertion(
            signing_key=sk,
            identity_did=did,
            identity_stable_id=principal,
            encryption_public_key=public,
            custody=custody,
            now=datetime.now(UTC),
        )
        await env["db"].execute(
            "UPDATE public.host_authority SET encryption_assertion=$1::jsonb WHERE actor_id=$2",
            json.dumps(assertion),
            UUID(actor),
        )
        identities.append(
            {
                "did": did,
                "stable_id": principal,
                "signing_key": sk,
                "private_key": private,
                "encryption_key": assertion,
            }
        )
    mid, cid = str(uuid4()), str(uuid4())
    kwargs = {
        "sender": identities[0],
        "recipients": [identities[1]],
        "body": "private body",
        "message_id": mid,
        "conversation_id": cid,
        "created_at": datetime.now(UTC),
    }
    envelope = (
        encrypt_e2ee_mail(**kwargs, subject="private")
        if kind == "mail"
        else encrypt_e2ee_chat(**kwargs)
    )
    raw = canonical_json_bytes(envelope).decode()
    target = await env["service"].resolve(
        env["auth"],
        dto(
            "ResolveRequest",
            {
                "version": "aweb-human-resolve-v1",
                "team_id": env["auth"].team_id,
                "selector": "human",
            },
        ),
    )
    request = dto(
        "PrepareRequest",
        {
            "version": "aweb-human-prepare-v1",
            "kind": kind,
            "message_id": mid,
            "author": {"kind": "native", "did": "did:aw:agent"},
            "envelope": raw,
            "format": "native_encrypted_v2",
            "target": target.value,
            "conversation_id": cid,
        },
    )
    prepared = await env["service"].prepare(env["auth"], request)
    assert prepared.value["envelope"] == raw
    assert prepared.value["author"]["trust_status"] == "verified"
    assert prepared.value["author"]["confidentiality"] == "hosted_readable"
    await complete(env, prepared)
    table = "messages" if kind == "mail" else "chat_messages"
    stored = await env["db"].fetch_one(
        "SELECT encrypted_envelope,body FROM {{tables."
        + table
        + "}} WHERE message_id=$1",
        UUID(mid),
    )
    assert json.loads(stored["encrypted_envelope"]) == envelope
    assert stored["body"] == ""


@pytest.mark.asyncio
async def test_uow_host_lock_lasts_through_caller_result_commit(native_send):
    import asyncio

    env = native_send
    prepared = await env["prepared"]()
    update = None
    try:
        async with env["service"].unit_of_work(env["auth"]) as uow:
            await uow.claim_ingress(env["key"])
            accepted = await uow.accept(prepared)
            update = asyncio.create_task(
                env["db"].execute(
                    "UPDATE public.host_authority SET active=false WHERE actor_id=$1",
                    UUID(env["b"]),
                )
            )
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(asyncio.shield(update), 0.05)
            result = dto(
                "IngressResult",
                {
                    "version": "aweb-ingress-result-v1",
                    "key": env["key"].value,
                    "accepted": accepted.value,
                    "result": {},
                },
            )
            await uow.finish_ingress(result)
        await asyncio.wait_for(update, 2)
    finally:
        if update and not update.done():
            update.cancel()
            await asyncio.gather(update, return_exceptions=True)
    assert (await env["db"].fetch_one("SELECT count(*) n FROM {{tables.messages}}"))[
        "n"
    ] == 1


@pytest.mark.asyncio
async def test_returned_accepted_dto_cannot_rebind_committed_result(native_send):
    env = native_send
    prepared = await env["prepared"]()
    with pytest.raises(ContractError, match="exact ingress result"):
        async with env["service"].unit_of_work(env["auth"]) as uow:
            await uow.claim_ingress(env["key"])
            accepted = await uow.accept(prepared)
            accepted.value["message_id"] = str(uuid4())
            await uow.finish_ingress(
                dto(
                    "IngressResult",
                    {
                        "version": "aweb-ingress-result-v1",
                        "key": env["key"].value,
                        "accepted": accepted.value,
                        "result": {},
                    },
                )
            )
    assert (await env["db"].fetch_one("SELECT count(*) n FROM {{tables.messages}}"))[
        "n"
    ] == 0


@pytest.mark.asyncio
async def test_human_discovery_withholds_unverified_global_claim(native_send):
    from aweb.messaging.participants import messaging_participant_by_alias

    env = native_send
    await env["db"].execute(
        "UPDATE {{tables.agents}} SET did_aw_verified_key=NULL WHERE agent_id=$1",
        UUID(env["b"]),
    )
    row = await messaging_participant_by_alias(
        env["service"].db,
        team_id=env["auth"].team_id,
        selected_team_id=env["auth"].team_id,
        alias="human",
    )
    assert row["did_key"] == env["recipient_did"]
    assert row["did_aw"] is None
    assert row["address"] is None
    assert row["policy_did_aw"] == "did:aw:human"
    # The host's global assertion cannot repair an unverified OSS projection.
    with pytest.raises(ContractError, match="authority_unavailable"):
        await env["service"].resolve(
            env["auth"],
            dto("ResolveRequest", dict(
                version="aweb-human-resolve-v1", team_id=env["auth"].team_id,
                selector="human",
            )),
        )


@pytest.mark.asyncio
async def test_native_accept_rechecks_identity_wide_contacts_only(native_send):
    env = native_send
    prepared = await env["prepared"]()
    await _insert_team(env["db"], "other:example.test")
    await _insert_agent(
        env["db"], team_id="other:example.test", alias="other-human",
        did_key=env["recipient_did"], did_aw="did:aw:human", address=None,
        inbound_mode="contacts_only",
    )
    with pytest.raises(ContractError, match="forbidden"):
        await complete(env, prepared)
    for table in ("messages", "conversations", "human_channel_ingress", "human_channel_mutations"):
        assert (await env["db"].fetch_one(
            "SELECT count(*) n FROM {{tables." + table + "}}"
        ))["n"] == 0
    # A fresh exact contact is the valid neighbouring authority.
    from aweb.messaging.contacts import add_contact
    await add_contact(
        env["service"].db, owner_did="did:aw:human",
        contact_address="example.test/agent", contact_did_aw="did:aw:agent",
        binding_controller_did=env["auth"].did_key, label="agent",
    )
    from dataclasses import replace
    env["auth"] = replace(env["auth"], address="example.test/agent")
    await complete(env, await env["prepared"](caller=env["auth"]))
    assert (await env["db"].fetch_one("SELECT count(*) n FROM {{tables.messages}}"))["n"] == 1


@pytest.mark.asyncio
async def test_identity_policy_lock_spans_outer_commit(native_send):
    import asyncio

    env = native_send
    await _insert_team(env["db"], "other:example.test")
    other = await _insert_agent(
        env["db"], team_id="other:example.test", alias="other-human",
        did_key=env["recipient_did"], did_aw="did:aw:human", address=None,
    )
    prepared = await env["prepared"]()
    update = None
    try:
        async with env["service"].unit_of_work(env["auth"]) as uow:
            await uow.claim_ingress(env["key"])
            accepted = await uow.accept(prepared)
            update = asyncio.create_task(env["db"].execute(
                "UPDATE {{tables.agents}} SET inbound_mode='contacts_only' WHERE agent_id=$1",
                UUID(other),
            ))
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(asyncio.shield(update), 0.05)
            await uow.finish_ingress(dto("IngressResult", dict(
                version="aweb-ingress-result-v1", key=env["key"].value,
                accepted=accepted.value, result={},
            )))
        await asyncio.wait_for(update, 2)
    finally:
        if update and not update.done():
            update.cancel()
            await asyncio.gather(update, return_exceptions=True)


@pytest.mark.asyncio
async def test_native_facts_project_identity_in_endpoint_team(native_send):
    env = native_send
    await _insert_team(env['db'], 'partner:partner.test')
    other = await _insert_agent(env['db'], team_id='partner:partner.test', alias='same-human',
        did_key=env['recipient_did'], did_aw='did:aw:human', address='partner.test/same-human')
    # Even a valid projection elsewhere is not the endpoint team's admission context.
    row = await env['service']._row(actor_id=other)
    facts = await env['service']._facts(env['auth'], row)
    assert facts.value['principal'] == {'kind': 'native', 'did': 'did:aw:human'}
    assert facts.value['actor_id'] == env['b']
    assert facts.value['team_id'] == env['auth'].team_id
