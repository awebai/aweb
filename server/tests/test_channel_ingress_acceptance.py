"""Server-owned ingress on real accepted rows; frozen receipts stay unchanged."""
from copy import deepcopy
import asyncio
from datetime import UTC, datetime
import json
from uuid import UUID, uuid4

import pytest

from aweb.human_channels.contract import ContractError, canonical_record
from aweb.human_channels.native import NativeMessagingService
from awid.signing import canonical_json_bytes, sign_message
from test_human_channels_native_send import complete, dto, native_send  # noqa: F401


CONTEXT = dict(platform="msteams", presence_kind="shared", input_origin="external_human",
               confidentiality="hosted_readable")


def _caller(auth):
    return canonical_json_bytes(dict(did_key=auth.did_key, did_aw=auth.did_aw,
        agent_id=auth.agent_id, team_id=auth.team_id, certificate_id=auth.certificate_id,
        grant_id=getattr(auth.grant, "grant_id", None))).decode()


class IngressAuthority:
    """Real host-owned verified-event records, scoped to each prepared plan."""

    async def context(self, auth, send, ingress_key, service, transaction):
        assert transaction.is_in_transaction()
        row = await transaction.fetchrow(
            """SELECT * FROM public.host_channel_input
               WHERE issuer=$1 AND namespace=$2 AND input_key=$3 FOR UPDATE""",
            auth.did_aw or auth.did_key, ingress_key.value["namespace"], ingress_key.value["key"],
        )
        if (not row or row["input_hash"] != ingress_key.value["input_hash"]
                or row["caller"] != _caller(auth)
                or row["service"] != canonical_record(service).decode()
                or row["message_id"] != UUID(send.value["message_id"])
                or row["envelope_hash"] != send.value["envelope_hash"]
                or (send.schema == "PreparedSend" and row["prepared_id"] != UUID(send.value["prepared_id"]))):
            raise ContractError("forbidden", "verified channel event binding")
        if not row["active"]:
            raise ContractError("stale", "verified channel event")
        return json.loads(row["context"])


async def _channel_service(env):
    await env["db"].execute("""CREATE TABLE public.host_channel_input (
        issuer text, namespace text, input_key text, input_hash text, service text,
        message_id uuid, envelope_hash text, prepared_id uuid, context jsonb, active bool, caller text,
        PRIMARY KEY (issuer,namespace,input_key))""")
    service = NativeMessagingService(env["service"].db, authority=env["provider"],
        service=env["provider"].service, ingress_authority=IngressAuthority())
    env["service"] = service
    return service


async def _prepare(env, kind="mail", via=None):
    mid, cid = str(uuid4()), str(uuid4())
    auth = env["auth"]
    payload = dict(type=kind, from_did=auth.did_key, to_did=env["recipient_did"],
        from_stable_id=auth.did_aw, to_stable_id="did:aw:human", subject="test", body="channel input",
        timestamp=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"), message_id=mid,
        conversation_id=cid, **{"from": "agent", "to": "human"})
    if via is not None:
        payload["via"] = via
    raw = canonical_json_bytes(payload).decode()
    target = await env["service"].resolve(auth, dto("ResolveRequest", dict(
        version="aweb-human-resolve-v1", team_id=auth.team_id, selector="human")))
    return await env["service"].prepare(auth, dto("PrepareRequest", dict(
        version="aweb-human-prepare-v1", kind=kind, message_id=mid,
        author=dict(kind="native", did=auth.did_aw), format="native_plaintext",
        envelope=canonical_json_bytes(dict(signed_payload=raw,
            signature=sign_message(env["signing_key"], raw.encode()))).decode(),
        target=target.value, conversation_id=cid)))


async def _bind(env, prepared, context=None, key=None):
    key = key or env["key"]
    context = CONTEXT if context is None else context
    await env["db"].execute("""INSERT INTO public.host_channel_input
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,true,$10)""",
        env["auth"].did_aw, key.value["namespace"], key.value["key"], key.value["input_hash"],
        canonical_record(env["provider"].service).decode(), UUID(prepared.value["message_id"]),
        prepared.value["envelope_hash"], UUID(prepared.value["prepared_id"]), json.dumps(context), _caller(env["auth"]))


async def _row(env, prepared):
    table = "messages" if prepared.value["kind"] == "mail" else "chat_messages"
    row = await env["db"].fetch_one("SELECT * FROM {{tables." + table + "}} WHERE message_id=$1",
                                  UUID(prepared.value["message_id"]))
    return row


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("via", [None, "telegram"])
async def test_channel_ingress_is_server_context_not_via(native_send, kind, via):
    env = native_send
    await _channel_service(env)
    prepared = await _prepare(env, kind, via)
    await _bind(env, prepared)
    result = await complete(env, prepared)
    row = await _row(env, prepared)
    assert json.loads(row["ingress"]) == CONTEXT
    assert "ingress" not in result.value["accepted"]
    assert "ingress" not in result.value
    assert canonical_record(result) == canonical_record(await env["service"].ingress_result(env["auth"], env["key"]))
    assert json.loads(row["signed_payload"]).get("via") == via
    mutation = await env["db"].fetch_one("SELECT context FROM {{tables.human_channel_mutations}}")
    assert json.loads(mutation["context"])["ingress"] == CONTEXT


@pytest.mark.asyncio
async def test_channel_ingress_ordinary_same_signer_is_absent(native_send):
    env = native_send
    ordinary = await env["prepared"](via="telegram")
    result = await complete(env, ordinary)
    assert (await _row(env, ordinary)).get("ingress") is None
    assert canonical_record(result) == canonical_record(await env["service"].ingress_result(env["auth"], env["key"]))


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["recovery", "new-key", "ordinary-facade"])
async def test_channel_ingress_changed_context_replay_refuses_at_row(native_send, mode):
    env = native_send
    await _channel_service(env)
    prepared = await _prepare(env)
    await _bind(env, prepared)
    original = await complete(env, prepared)
    if mode == "ordinary-facade":
        other = NativeMessagingService(env["service"].db, authority=env["provider"], service=env["provider"].service)
        with pytest.raises(ContractError, match="replay_conflict.*ingress"):
            await other.ingress_result(env["auth"], env["key"])
    elif mode == "recovery":
        await env["db"].execute("UPDATE public.host_channel_input SET context=$1::jsonb",
                                json.dumps(dict(CONTEXT, presence_kind="dedicated")))
        with pytest.raises(ContractError, match="replay_conflict.*ingress"):
            await env["service"].ingress_result(env["auth"], env["key"])
    else:
        key = dto("IngressKey", dict(env["key"].value, key="different-input"))
        await _bind(env, prepared, dict(CONTEXT, platform="telegram"), key)
        with pytest.raises(ContractError, match="replay_conflict.*ingress"):
            await complete(env, prepared, key=key)
    assert json.loads((await _row(env, prepared))["ingress"]) == CONTEXT
    receipt = await env["db"].fetch_one("SELECT result FROM {{tables.human_channel_ingress}}")
    assert json.loads(receipt["result"]) == original.value


@pytest.mark.asyncio
async def test_channel_ingress_provider_keeps_several_plans_bound(native_send):
    env = native_send
    await _channel_service(env)
    first, second = await _prepare(env), await _prepare(env)
    key = dto("IngressKey", dict(env["key"].value, key="second-input"))
    await _bind(env, first)
    other = dict(CONTEXT, platform="telegram", presence_kind="native", confidentiality="server_readable")
    await _bind(env, second, other, key)
    await complete(env, second, key=key)
    await complete(env, first)
    assert json.loads((await _row(env, first))["ingress"]) == CONTEXT
    assert json.loads((await _row(env, second))["ingress"]) == other


@pytest.mark.asyncio
async def test_channel_ingress_provider_rechecks_after_oss_actor_wait(native_send):
    env = native_send
    await _channel_service(env)
    prepared = await _prepare(env)
    await _bind(env, prepared)
    pending = None
    try:
        async with env["db"].transaction() as blocker:
            await blocker.fetch_one("SELECT agent_id FROM {{tables.agents}} WHERE agent_id=$1 FOR UPDATE", UUID(env["a"]))
            pid = await blocker.fetch_value("SELECT pg_backend_pid()")
            pending = asyncio.create_task(complete(env, prepared))
            async with asyncio.timeout(5):
                while not await env["db"].fetch_value(
                    "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1::int=ANY(pg_blocking_pids(pid)))", pid):
                    assert not pending.done()
                    await asyncio.sleep(0.01)
            # Real evidence changes while OSS acceptance waits. The provider
            # must inspect this committed revision after that wait, not before.
            await blocker.execute("UPDATE public.host_channel_input SET active=false")
        with pytest.raises(ContractError, match="stale.*channel event"):
            await asyncio.wait_for(pending, 5)
    finally:
        if pending is not None and not pending.done():
            pending.cancel()
            await asyncio.gather(pending, return_exceptions=True)
    assert await _row(env, prepared) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["wrong-plan", "wrong-caller", "wrong-service", "wrong-key",
                                    "inactive", "extra", "missing", "null", "bad-platform", "rollback"])
async def test_channel_ingress_provider_refuses_or_rolls_back_without_downgrade(native_send, failure):
    env = native_send
    await _channel_service(env)
    prepared = await _prepare(env)
    context = deepcopy(CONTEXT)
    if failure == "extra":
        context["private_binding_id"] = "must-not-escape"
    if failure == "missing":
        context.pop("input_origin")
    if failure == "bad-platform":
        context["platform"] = "telegram\n"
    await _bind(env, prepared, context)
    if failure == "inactive":
        await env["db"].execute("UPDATE public.host_channel_input SET active=false")
    if failure == "null":
        await env["db"].execute("UPDATE public.host_channel_input SET context='null'::jsonb")
    if failure in {"wrong-caller", "wrong-service"}:
        column = "caller" if failure == "wrong-caller" else "service"
        await env["db"].execute("UPDATE public.host_channel_input SET " + column + "='wrong'")
    if failure == "wrong-plan":
        # Same message ID, envelope and caller; only the preparation differs.
        target = await env["service"].resolve(env["auth"], dto("ResolveRequest", dict(
            version="aweb-human-resolve-v1", team_id=env["auth"].team_id, selector="human")))
        prepared = await env["service"].prepare(env["auth"], dto("PrepareRequest", dict(
            version="aweb-human-prepare-v1", kind=prepared.value["kind"],
            message_id=prepared.value["message_id"], envelope=prepared.value["envelope"],
            conversation_id=prepared.value["conversation_id"], format="native_plaintext",
            author=dict(kind="native", did=env["auth"].did_aw), target=target.value)))
    key = env["key"] if failure != "wrong-key" else dto("IngressKey", dict(env["key"].value, key="unbound"))
    expected = RuntimeError if failure == "rollback" else ContractError
    with pytest.raises(expected):
        await complete(env, prepared, key=key, fail="own_write" if failure == "rollback" else None)
    assert await _row(env, prepared) is None
    for table in ("human_channel_sends", "human_channel_ingress", "human_channel_mutations"):
        assert (await env["db"].fetch_one("SELECT count(*) n FROM {{tables." + table + "}}"))["n"] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail"])
async def test_ordinary_receipt_survives_normal_message_gc(native_send, kind):
    from datetime import timedelta
    from aweb.gc import gc_expired_messages
    env = native_send
    prepared = await env["prepared"](kind=kind)
    original = await complete(env, prepared)
    table = "messages" if kind == "mail" else "chat_messages"
    await env["db"].execute("UPDATE {{tables." + table + "}} SET created_at=$1 WHERE message_id=$2", datetime.now(UTC)-timedelta(days=31), UUID(prepared.value["message_id"]))
    deleted = await gc_expired_messages(env["service"].db)
    assert deleted["messages_deleted"] == 1
    assert await env["db"].fetch_value("SELECT count(*) FROM {{tables.human_channel_ingress}}") == 1
    recovered = await env["service"].ingress_result(env["auth"], env["key"])
    assert canonical_record(recovered) == canonical_record(original)


@pytest.mark.asyncio
@pytest.mark.parametrize("facade", ["channel", "ordinary"])
async def test_channel_receipt_missing_row_never_recovers_context(native_send, facade):
    from datetime import timedelta
    from aweb.gc import gc_expired_messages
    env = native_send
    await _channel_service(env)
    prepared = await _prepare(env)
    await _bind(env, prepared)
    original = await complete(env, prepared)
    await env["db"].execute(
        "UPDATE {{tables.messages}} SET created_at=$1 WHERE message_id=$2",
        datetime.now(UTC)-timedelta(days=31), UUID(prepared.value["message_id"]))
    assert (await gc_expired_messages(env["service"].db))["mail_deleted"] == 1
    service = env["service"] if facade == "channel" else NativeMessagingService(
        env["service"].db, authority=env["provider"], service=env["provider"].service)
    with pytest.raises(ContractError, match="replay_conflict.*channel ingress"):
        await service.ingress_result(env["auth"], env["key"])
    assert await _row(env, prepared) is None
    retained = await env["db"].fetch_one("SELECT result FROM {{tables.human_channel_ingress}}")
    assert canonical_record(dto("IngressResult", json.loads(retained["result"]))) == canonical_record(original)
