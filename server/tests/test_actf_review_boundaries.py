"""Real ingress regressions for actf runtime review boundaries."""
import asyncio
import json
import time
from contextlib import AsyncExitStack
from types import SimpleNamespace

import pytest

from test_actf_return_route import (  # noqa: F401
    route_pair, _effects, _expire_team_evidence, _federation_packet, _listener,
    _origin, _publish_server, _route_rows, _send, _socket, _stored,
)
from test_messages_http import _encode_certificate, _make_certificate
from awid.signing import canonical_json_bytes, sign_message


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("encrypted", [False, True], ids=["plaintext", "v2"])
@pytest.mark.parametrize("continuation", [False, True], ids=["first-contact", "continuation"])
async def test_signed_team_policy_ignores_other_enrollment(route_pair, kind, encrypted, continuation):
    source, target = route_pair.source, route_pair.target
    # A legitimate second enrollment does not change the team this send signs.
    cert = _make_certificate(target.team_sk, target.team_did, source.local.did,
        team_id=target.team_id, alias=target.local.alias, identity_scope="local")
    encoded = _encode_certificate(cert)
    await target.registry.revoke(target.local.certificate["certificate_id"])
    await target.registry_client.register_team_certificate(target.domain, "members",
        team_controller_signing_key=target.team_sk, certificate_id=cert["certificate_id"],
        member_did_key=source.local.did, member_did_aw=None, member_address=None,
        alias=target.local.alias, identity_scope="local", certificate=encoded)
    await target.db.execute("UPDATE {{tables.agents}} SET did_key=$2,certificate_id=$3 WHERE agent_id=$1",
        target.local.id, source.local.did, cert["certificate_id"])
    first = None
    if continuation:
        packet, first = _federation_packet(source.local, target.global_actor, kind, encrypted=encrypted)
        response = await target.client.post("/v1/federation/messages", json=packet)
        assert response.status_code == 200, response.text
    for mode in ("team_and_contacts", "contacts_only"):
        await target.db.execute("UPDATE {{tables.agents}} SET inbound_mode=$2 WHERE agent_id=$1",
            target.global_actor.id, mode)
        packet, _ = _federation_packet(source.local, target.global_actor, kind,
            encrypted=encrypted, continuation=str(first.cid) if continuation else None)
        before = await _effects(target)
        routes = await _route_rows(target, first.cid, source.local.did) if continuation else None
        response = await target.client.post("/v1/federation/messages", json=packet)
        assert response.status_code == 403, response.text
        assert response.json()["reason"] == "recipient_policy_rejected"
        assert await _effects(target) == before
        if continuation:
            assert await _route_rows(target, first.cid, source.local.did) == routes
    await target.db.execute("UPDATE {{tables.agents}} SET inbound_mode='open' WHERE agent_id=$1", target.global_actor.id)
    packet, accepted = _federation_packet(source.local, target.global_actor, kind,
        encrypted=encrypted, continuation=str(first.cid) if continuation else None)
    response = await target.client.post("/v1/federation/messages", json=packet)
    assert response.status_code == 200, response.text
    await _stored(target.global_actor, kind, accepted)
    first = accepted


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("encrypted", [False, True], ids=["plaintext", "v2"])
@pytest.mark.parametrize("poison_hint", [False, True], ids=["move", "poisoned-hint"])
async def test_sender_initiated_move_preserves_stored_hint_integrity(route_pair, kind, encrypted, poison_hint):
    source, target = route_pair.source, route_pair.target
    accepted, first = await _send(source.local, target.global_actor, kind, encrypted=encrypted)
    assert accepted.status_code == 200, accepted.text
    control, _ = _federation_packet(source.local, target.global_actor, kind, encrypted=encrypted, continuation=str(first.cid))
    unchanged = await target.client.post("/v1/federation/messages", json=control)
    assert unchanged.status_code == 200, unchanged.text
    sock = _socket()
    moved = _origin(sock)
    source.server.app.state.federation_public_origins = [moved]
    async with _listener(source.server.app, sock):
        await _publish_server(source, moved)
        await _expire_team_evidence(target)
        if poison_hint:
            await target.db.execute("UPDATE {{tables.conversation_participants}} SET transport_hint='local' WHERE conversation_id=$1 AND did=$2", first.cid, source.local.did)
        hint_before = await target.db.fetch_value("SELECT transport_hint FROM {{tables.conversation_participants}} WHERE conversation_id=$1 AND did=$2", first.cid, source.local.did)
        before, routes = await _effects(target), await _route_rows(target, first.cid, source.local.did)
        moved_node = SimpleNamespace(**dict(vars(source), origin=moved))
        moved_actor = SimpleNamespace(**dict(vars(source.local), node=moved_node))
        packet, sent = _federation_packet(moved_actor, target.global_actor, kind, encrypted=encrypted, continuation=str(first.cid))
        response = await target.client.post("/v1/federation/messages", json=packet)
        hint = await target.db.fetch_value("SELECT transport_hint FROM {{tables.conversation_participants}} WHERE conversation_id=$1 AND did=$2", first.cid, source.local.did)
        if poison_hint:
            assert response.status_code == 409, response.text
            assert response.json()["reason"] == "federation_conversation_invalid"
            assert await _effects(target) == before
            assert await _route_rows(target, first.cid, source.local.did) == routes
            assert hint == hint_before
        else:
            assert response.status_code == 200, response.text
            await _stored(target.global_actor, kind, sent)
            assert hint == "federation:" + moved
            for row in await _route_rows(target, first.cid, source.local.did):
                if row is not None:
                    assert row["delivery_origin"] == moved
                    assert row["route_certificate"] == source.local.encoded_certificate


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("encrypted", [False, True], ids=["plaintext", "v2"])
@pytest.mark.parametrize("optional_cert", ["absent", "unrelated", "forged", "malformed"])
async def test_legacy_route_optional_certificate_is_not_alias_authority(route_pair, kind, encrypted, optional_cert):
    source, target = route_pair.source, route_pair.target
    packet, first = _federation_packet(source.local, target.global_actor, kind, encrypted=encrypted)
    response = await target.client.post("/v1/federation/messages", json=packet)
    assert response.status_code == 200, response.text
    verified = await _stored(target.global_actor, kind, first)
    assert verified["from_alias"] == source.local.alias
    # Provision the historical route shape. No new legacy admission is created.
    for table, key in (("conversation_participants", "conversation_id"), ("chat_participants", "session_id")):
        await target.db.execute("UPDATE {{tables." + table + "}} SET route_team_id=NULL,route_certificate_id=NULL,route_certificate=NULL WHERE " + key + "=$1 AND did=$2", first.cid, source.local.did)
    def legacy_packet():
        packet, sent = _federation_packet(source.local, target.global_actor, kind, encrypted=encrypted, continuation=str(first.cid))
        packet["envelope"].pop("sender_certificate")
        if not encrypted:
            # A released local sender used an alias, not the new full-team label.
            sent.fields["from"] = source.local.alias
            raw = canonical_json_bytes(sent.fields)
            packet["envelope"]["signed_payload"] = raw.decode()
            packet["signature"] = sign_message(source.local.sk, raw)
        return packet, sent

    for proof in (None, optional_cert):
        packet, sent = legacy_packet()
        if proof == "unrelated":
            packet["envelope"]["sender_certificate"] = source.global_actor.encoded_certificate
        elif proof == "forged":
            forged = dict(source.local.certificate, alias="unverified-impostor")
            packet["envelope"]["sender_certificate"] = _encode_certificate(forged)
        elif proof == "malformed":
            packet["envelope"]["sender_certificate"] = "not-a-certificate"
        response = await target.client.post("/v1/federation/messages", json=packet)
        assert response.status_code == 200, response.text
        row = await _stored(target.global_actor, kind, sent)
        assert row["from_alias"] == source.local.did
        for table, key in (("conversation_participants", "conversation_id"), ("chat_participants", "session_id")):
            row = await target.db.fetch_one("SELECT alias,route_team_id FROM {{tables." + table + "}} WHERE " + key + "=$1 AND did=$2", first.cid, source.local.did)
            if row:
                assert row["alias"] == source.local.did and row["route_team_id"] is None
        event = await target.db.fetch_value("SELECT payload_json FROM {{tables.federation_mutation_outbox}} WHERE message_id=$1", sent.mid)
        assert (json.loads(event) if isinstance(event, str) else event)["from_alias"] == source.local.did
    # Optional proof must not upgrade the old route's origin authority either.
    bad, _ = legacy_packet()
    bad["envelope"]["sender_delivery_origin"] = target.origin
    before = await _effects(target)
    response = await target.client.post("/v1/federation/messages", json=bad)
    assert response.status_code == 422 and response.json()["reason"] == "local_sender_route_mismatch"
    assert await _effects(target) == before


@pytest.mark.asyncio
async def test_expired_phase_b_refresh_is_bounded_when_real_pool_is_exhausted(route_pair):
    source, target = route_pair.source, route_pair.target
    packet, first = _federation_packet(source.local, target.global_actor, "mail")
    assert (await target.client.post("/v1/federation/messages", json=packet)).status_code == 200
    before, routes = await _effects(target), await _route_rows(target, first.cid, source.local.did)
    packet, _ = _federation_packet(source.local, target.global_actor, "mail", continuation=str(first.cid))
    # Use actual evidence age, actual lock wait and actual shared pool pressure.
    await asyncio.sleep(58)
    pending = None
    async with AsyncExitStack() as held:
        async with target.db.acquire() as blocker:
            async with blocker.transaction():
                await blocker.fetchrow(target.db.prepare_query("SELECT conversation_id FROM {{tables.conversations}} WHERE conversation_id=$1 FOR UPDATE"), first.cid)
                pending = asyncio.create_task(target.client.post("/v1/federation/messages", json=packet, timeout=25))
                for _ in range(80):
                    await blocker.execute("SELECT pg_stat_clear_snapshot()")
                    waiting = await blocker.fetchval("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%conversations%' AND pid<>pg_backend_pid()")
                    if waiting or pending.done():
                        break
                    await asyncio.sleep(.05)
                assert waiting, pending.result().text if pending.done() else "Phase B did not reach the held row"
                # Phase B owns one connection; retain every other one. Releasing
                # the row lock below does NOT return blocker's connection.
                for _ in range(target.db._pool.get_max_size() - 2):
                    await asyncio.wait_for(held.enter_async_context(target.db.acquire()), 2)
                await asyncio.sleep(3)
            started = time.monotonic()
            done, _ = await asyncio.wait({pending}, timeout=12)
            # Recover old code safely after measuring its unbounded pool wait.
            if not done:
                await held.aclose()
                await pending
            assert done, "expired-proof refresh held the Phase-B connection/locks beyond the aggregate deadline"
            response = pending.result()
            assert time.monotonic() - started < 12
            assert response.status_code == 503, response.text
            assert response.json()["reason"] == "federation_authority_coordination_unavailable"
            assert response.json()["retryable"] is True
            # While pool pressure remains, an independent existing connection
            # must immediately obtain the rolled-back conversation lock.
            async with blocker.transaction():
                await blocker.fetchrow(target.db.prepare_query("SELECT conversation_id FROM {{tables.conversations}} WHERE conversation_id=$1 FOR UPDATE NOWAIT"), first.cid)
        await held.aclose()
    assert await _effects(target) == before
    assert await _route_rows(target, first.cid, source.local.did) == routes
    follow, sent = _federation_packet(source.local, target.global_actor, "mail", continuation=str(first.cid))
    response = await target.client.post("/v1/federation/messages", json=follow)
    assert response.status_code == 200, response.text
    await _stored(target.global_actor, "mail", sent)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("encrypted", [False, True], ids=["plaintext", "v2"])
async def test_signed_api_mount_uses_verified_origin_for_federation(route_pair, kind, encrypted):
    import httpx
    from starlette.applications import Starlette
    from starlette.routing import Mount
    source, target = route_pair.source, route_pair.target
    sock = _socket()
    origin = _origin(sock)
    paths = []
    app = Starlette(routes=[Mount("/api", app=source.server.app), Mount("/", app=source.server.app)])
    async def observe(scope, receive, send):
        if scope["type"] == "http":
            paths.append(scope["path"])
        await app(scope, receive, send)
    source.server.app.state.public_origin = origin
    async with _listener(observe, sock), httpx.AsyncClient(base_url=origin + "/api", timeout=10) as client:
        await _publish_server(source, origin + "/api")
        mounted = SimpleNamespace(**dict(vars(source), origin=origin, client=client))
        sender = SimpleNamespace(**dict(vars(source.local), node=mounted))
        response, first = await _send(sender, target.global_actor, kind, encrypted=encrypted)
        assert response.status_code == 200, response.text
        await _stored(target.global_actor, kind, first)
        reply, answer = await _send(target.global_actor, sender, kind, encrypted=encrypted, continuation=str(first.cid))
        assert reply.status_code == 200, reply.text
        await _stored(sender, kind, answer)
        again, final = await _send(sender, target.global_actor, kind, encrypted=encrypted, continuation=str(first.cid))
        assert again.status_code == 200, again.text
        await _stored(target.global_actor, kind, final)
        for row in await _route_rows(target, first.cid, source.local.did):
            if row:
                assert row["delivery_origin"] == origin
        assert any(path.startswith("/api/v1/") for path in paths)
        assert paths.count("/v1/federation/messages") == 1
        assert "/api/v1/federation/messages" not in paths
