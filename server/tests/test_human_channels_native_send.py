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
        "UPDATE {{tables.agents}} SET agent_type='human' WHERE agent_id=$1", UUID(b)
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

    async def prepared(kind="mail", message_id=None, body="native send", caller=None, via=None):
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
        if via is not None:
            payload["via"] = via
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


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
async def test_bridge_signer_without_via_keeps_custody_and_confidentiality(native_send, kind):
    env = native_send
    await env["db"].execute("UPDATE public.host_authority SET custody='bridge_custodial' WHERE actor_id=$1", UUID(env["a"]))
    labelled = (await env["prepared"](kind=kind, via="telegram")).value["author"]
    omitted = (await env["prepared"](kind=kind)).value["author"]
    assert labelled.pop("via") == "telegram"
    assert labelled == omitted
    assert omitted["trust_status"] == "verified_custodial"
    assert omitted["confidentiality"] == "server_readable"


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
@pytest.mark.parametrize("kind", ["mail", "chat"])
async def test_native_http_ingress_headers_recover_without_resend(native_send, kind):
    import httpx
    from aweb.identity_auth_deps import get_messaging_auth
    from aweb.routes.chat import router as chat_router
    from aweb.routes.messaging import router as messaging_router

    env = native_send
    app = env["app"]
    app.include_router(chat_router)
    app.include_router(messaging_router)
    app.state.human_channels_service = env["service"]

    async def auth():
        return env["auth"]

    app.dependency_overrides[get_messaging_auth] = auth
    prepared = await env["prepared"](kind)
    artifact = json.loads(prepared.value["envelope"])
    signed = json.loads(artifact["signed_payload"])
    payload = {
        "message_id": prepared.value["message_id"],
        "timestamp": signed["timestamp"],
        "signature": artifact["signature"],
        "signed_payload": artifact["signed_payload"],
        "from_did": env["auth"].did_key,
    }
    if kind == "mail":
        payload.update(
            to_alias="human",
            subject=signed["subject"],
            body=signed["body"],
            conversation_id=signed["conversation_id"],
        )
        path = "/v1/messages"
    else:
        payload.update(
            to_aliases=["human"],
            message=signed["body"],
            session_id=signed["conversation_id"],
        )
        path = "/v1/chat/sessions"
    headers = {
        "X-AWEB-Ingress-Namespace": "http",
        "X-AWEB-Ingress-Key": "event1",
        "X-AWEB-Ingress-Input-Hash": env["key"].value["input_hash"],
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        conflicts = (
            {"priority": "urgent", "timestamp": "2000-01-01T00:00:00Z"}
            if kind == "mail"
            else {"wait_seconds": 1, "leaving": True, "reply_to": str(uuid4())}
        )
        for field, value in conflicts.items():
            refusal = await client.post(
                path, json={**payload, field: value}, headers=headers
            )
            assert refusal.status_code == 422, refusal.text
            assert refusal.json()["detail"]["code"] == "invalid"
        assert (
            await env["db"].fetch_one(
                "SELECT count(*) n FROM {{tables.human_channel_ingress}}"
            )
        )["n"] == 0
        first = await client.post(path, json=payload, headers=headers)
        assert first.status_code == 200, first.text
        # Restart loses preparations; original result recovery needs none.
        env["service"]._preparations.clear()
        again = await client.post(path, json=payload, headers=headers)
        assert again.status_code == 200, again.text
        assert again.json()["message_id"] == first.json()["message_id"]
        lookup = await client.get(
            "/v1/messaging/ingress-results/http/event1",
            params={"input_hash": env["key"].value["input_hash"]},
        )
        assert lookup.status_code == 200, lookup.text
        assert lookup.json()["accepted"]["message_id"] == first.json()["message_id"]
        bad = {**payload, "message_id": str(uuid4())}
        new_signed = {**signed, "message_id": bad["message_id"]}
        bad["signed_payload"] = canonical_json_bytes(new_signed).decode()
        bad["signature"] = sign_message(
            env["signing_key"], bad["signed_payload"].encode()
        )
        refusal = await client.post(path, json=bad, headers=headers)
        assert refusal.status_code == 409, refusal.text
        assert refusal.json()["detail"]["code"] == "replay_conflict"
    table = "messages" if kind == "mail" else "chat_messages"
    assert (
        await env["db"].fetch_one("SELECT count(*) n FROM {{tables." + table + "}}")
    )["n"] == 1


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
@pytest.mark.parametrize("kind,options,expected_error", [
    ("mail", {}, None), ("chat", {}, None),
    ("mail", {"plaintext": False}, None),
    ("chat", {"plaintext": False}, None),
    ("mail", {"plaintext": False, "priority": "urgent"}, "unsupported"),
    ("chat", {"plaintext": False, "leaving": True}, "unsupported"),
    ("chat", {"plaintext": False, "hang_on": True}, "unsupported"),
    ("chat", {"plaintext": False, "wait": True, "wait_seconds": 1}, "unsupported"),
    ("chat", {"plaintext": False, "wait_seconds": 1}, "unsupported"),
    ("chat", {"to_did": "did:aw:agent"}, "invalid"),
    ("chat", {"plaintext": False, "to_did": "did:aw:agent"}, "invalid"),
])
async def test_real_mcp_native_ingress_commits_before_reply_and_replays(
    native_send, monkeypatch, kind, options, expected_error
):
    import httpx
    from identity_binding_support import seed_verified_bindings
    from aweb.internal_auth import build_internal_auth_header_value
    from aweb.mcp.server import create_mcp_app
    from aweb.mcp.signing import HostedMessageSigningResult, canonical_signed_payload

    env = native_send
    await env["db"].execute(
        "INSERT INTO {{tables.workspaces}} (workspace_id,team_id,agent_id,alias,workspace_type) VALUES ($1,$2,$3,'agent','hosted_mcp')",
        uuid4(),
        env["auth"].team_id,
        UUID(env["a"]),
    )
    await env["db"].execute(
        "UPDATE public.host_authority SET custody='hosted_custodial' WHERE actor_id=$1",
        UUID(env["a"]),
    )
    monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "1")
    monkeypatch.setenv("AWEB_INTERNAL_AUTH_SECRET", "native-mcp-test-secret")
    signatures = []
    encryptions = []
    from aweb.e2ee_messages import encrypt_e2ee_chat, encrypt_e2ee_mail, generate_x25519_keypair
    from awid.e2ee_keys import build_encryption_key_assertion
    from aweb.mcp.signing import HostedMessageEncryptionResult

    identities = []
    for actor, did, principal, sk in (
        (env["a"], env["auth"].did_key, "did:aw:agent", env["signing_key"]),
        (env["b"], env["recipient_did"], "did:aw:human", env["recipient_key"]),
    ):
        private, public = generate_x25519_keypair()
        assertion = build_encryption_key_assertion(
            signing_key=sk, identity_did=did, identity_stable_id=principal,
            encryption_public_key=public, custody="hosted_custodial", now=datetime.now(UTC),
        )
        await env["db"].execute(
            "UPDATE public.host_authority SET encryption_assertion=$1::jsonb WHERE actor_id=$2",
            json.dumps(assertion), UUID(actor),
        )
        identities.append(dict(did=did, stable_id=principal, signing_key=sk,
                               private_key=private, encryption_key=assertion))

    async def encryptor(**kwargs):
        payload = kwargs["payload"]
        encryptions.append(payload)
        inputs = dict(sender=identities[0], recipients=[identities[1]],
                      body=payload["body"], message_id=payload["message_id"],
                      conversation_id=payload["conversation_id"],
                      created_at=datetime.fromisoformat(payload["timestamp"].replace("Z", "+00:00")))
        envelope = (encrypt_e2ee_mail(**inputs, subject=payload["subject"])
                    if kind == "mail" else encrypt_e2ee_chat(**inputs))
        return HostedMessageEncryptionResult(encrypted_envelope=envelope)

    async def signer(**kwargs):
        from aweb.mcp.auth import get_auth

        assert get_auth().request.app is env["app"]
        signed = canonical_signed_payload(kwargs["payload"])
        signatures.append(signed)
        return HostedMessageSigningResult(
            from_did=env["auth"].did_key,
            signing_key_id=env["auth"].did_key,
            signed_payload=signed,
            signature=sign_message(env["signing_key"], signed.encode()),
        )

    mcp = create_mcp_app(
        db_infra=env["service"].db,
        hosted_signer=signer,
        hosted_encryptor=encryptor,
        human_channels_service=env["service"],
    )
    app = env["app"]
    # This port test supplies host identity preconditions, as the native MCP
    # parity fixture does. The CLI journey separately uses the real AWID app.
    app.state.awid_registry_client = object()
    seed_verified_bindings(
        app,
        ("did:aw:agent", env["auth"].did_key, ""),
        ("did:aw:human", env["recipient_did"], ""),
    )
    app.mount("/mcp", mcp)
    user = str(uuid4())
    headers = {
        "Accept": "application/json, text/event-stream",
        "X-Team-ID": env["auth"].team_id,
        "X-User-ID": user,
        "X-AWEB-Actor-ID": env["a"],
        "X-AWEB-Auth": build_internal_auth_header_value(
            secret="native-mcp-test-secret",
            team_id=env["auth"].team_id,
            principal_type="u",
            principal_id=user,
            actor_id=env["a"],
        ),
        "X-AWEB-Ingress-Namespace": "mcp",
        "X-AWEB-Ingress-Key": "event1",
        "X-AWEB-Ingress-Input-Hash": env["key"].value["input_hash"],
    }
    arguments = (
        {"to": "human", "body": "from real MCP", "plaintext": True}
        if kind == "mail"
        else {"to_alias": "human", "message": "from real MCP", "plaintext": True}
    )
    arguments.update(options)
    tool = "send_mail" if kind == "mail" else "chat_send"
    await mcp.startup()
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:

            async def call(arguments):
                response = await client.post(
                    "/mcp/",
                    headers=headers,
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {"name": tool, "arguments": arguments},
                    },
                )
                assert response.status_code == 200, response.text
                reply = response.json()
                assert "error" not in reply, reply
                assert not reply["result"].get("isError"), reply
                return json.loads(reply["result"]["content"][0]["text"])

            first = await call(arguments)
            if expected_error:
                assert first.get("error") == expected_error, first
                assert signatures == []
                assert encryptions == []
                assert env["service"]._preparations == {}
                for table in ("messages", "conversations", "chat_messages", "chat_sessions",
                              "human_channel_sends", "human_channel_ingress", "human_channel_mutations"):
                    assert (await env["db"].fetch_one(
                        "SELECT count(*) n FROM {{tables." + table + "}}"
                    ))["n"] == 0
                return
            assert "error" not in first, first
            again = await call(arguments)
            assert again == first
            assert len(signatures) == (1 if arguments["plaintext"] else 0)
            assert len(encryptions) == (0 if arguments["plaintext"] else 1)
            changed = await call(
                {
                    **arguments,
                    ("body" if kind == "mail" else "message"): "changed source",
                }
            )
            assert changed["error"] == "replay_conflict"
    finally:
        await mcp.shutdown()
    table = "messages" if kind == "mail" else "chat_messages"
    assert (
        await env["db"].fetch_one("SELECT count(*) n FROM {{tables." + table + "}}")
    )["n"] == 1
    assert (
        await env["db"].fetch_one(
            "SELECT count(*) n FROM {{tables.human_channel_ingress}}"
        )
    )["n"] == 1


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
