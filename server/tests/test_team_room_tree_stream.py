"""ID-tree disposition on an already-admitted room stream, using real status caches."""

from datetime import datetime, timedelta, timezone
import json
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from nacl.signing import SigningKey
from awid.did import did_from_public_key
from awid.dns_verify import DomainAuthority
from awid.id_certificates import status_request
from awid_service.deps import get_domain_verifier
from aweb.api import _build_awid_registry_client
from test_team_room import privacy_app, TEAM, headers, metadata, post
from test_messages_http import _make_certificate, _encode_certificate
from test_identity_grants import _grant_headers
from test_cli_never_grants import registry_listener
from test_id_chain_request_auth import (
    ALICE,
    ROOT,
    _fixture_signer,
    _signed_fixture_certificate,
)


@pytest.mark.asyncio
@pytest.mark.parametrize("grant_actor", [False, True], ids=["certificate", "grant"])
@pytest.mark.parametrize("tree", ["valid", "revoked", "status_unavailable", "legacy"])
async def test_room_stream_rechecks_global_tree_after_opening(
    privacy_app,
    monkeypatch,
    grant_actor,
    tree,
):
    import aweb.routes.events as events_routes
    import aweb.identity_binding as identity_binding

    env = privacy_app
    room = await metadata(env)
    actor = env.actors["bob"]
    actor.sk, actor.did = bytes.fromhex(ALICE["seed_hex"]), ALICE["did_key"]
    domain = f"awtest-room-{uuid4().hex}.test"
    clock = SimpleNamespace(now=datetime.now(timezone.utc), evidence=100.0, polls=0)
    start = clock.now

    class StatusTransport(httpx.AsyncBaseTransport):
        def __init__(self):
            self.upstream = httpx.AsyncHTTPTransport()
            self.status_calls = 0
            self.status_down = False

        async def handle_async_request(self, request):
            if request.url.path == "/v1/id-certificates/status":
                self.status_calls += 1
                if self.status_down:
                    return httpx.Response(503, json={"detail": "status unavailable"})
            return await self.upstream.handle_async_request(request)

        async def aclose(self):
            await self.upstream.aclose()

    async with registry_listener(env) as (writer, origin):
        env.registry_app.state.awid_public_origins = (origin,)

        async def exact_dns(selected):
            assert selected == domain
            return DomainAuthority(ROOT["did_key"], origin, "_awid." + domain)

        env.registry_app.dependency_overrides[get_domain_verifier] = lambda: exact_dns
        stable = (await writer.register_did(actor.did, actor.sk)).did_aw
        receipt = None
        if tree != "legacy":
            await writer.register_namespace(
                domain, ROOT["did_key"], bytes.fromhex(ROOT["seed_hex"])
            )
            signed = _signed_fixture_certificate(
                "alice",
                domain=domain,
                identity=stable,
                parent={"kind": "namespace", "id": domain},
                issuer="root",
            )
            receipt = await writer.register_id_certificate(
                {"v": 1, "type": "aweb.id-chain", "certificates": [signed]},
                signer=_fixture_signer("alice"),
                expected_head=None,
                invitation_id=None,
            )
        await env.db.execute(
            """UPDATE {{tables.agents}} SET did_key=$1,did_aw=$2,address='',
            identity_scope='global' WHERE agent_id=$3""",
            actor.did,
            stable,
            actor.id,
        )
        actor.certificate = _encode_certificate(
            _make_certificate(
                env.team_sk,
                env.team_did,
                actor.did,
                team_id=TEAM,
                alias="bob",
                identity_scope="global",
                member_did_aw=stable,
                member_address="",
                certificate_id="privacy-bob",
            )
        )
        monkeypatch.setenv("AWID_REGISTRY_URL", origin)
        monkeypatch.setenv("AWEB_DATABASE_URL", "postgresql://unused/test")
        transport = StatusTransport()
        cached = _build_awid_registry_client(
            env.app, redis=env.redis, transport=transport
        )
        object.__setattr__(cached, "_domain_verifier", exact_dns)
        env.app.state.awid_registry_client = cached
        subject = {"id": stable, "did_key": actor.did}
        request = env.client.build_request(
            "GET",
            "/v1/events/stream",
            params={"deadline": (start + timedelta(seconds=120)).isoformat()},
        )
        if grant_actor:
            key, grant_id = SigningKey.generate(), uuid4()
            await env.db.execute(
                """INSERT INTO {{tables.identity_session_grants}}
                (grant_id,team_id,subject_agent_id,grant_did_key,scopes,issued_at,
                 expires_at,issued_by_certificate_id)
                VALUES ($1,$2,$3,$4,ARRAY['events.read','chat.read'],now(),
                        now()+interval '10 minutes','privacy-bob')""",
                grant_id,
                TEAM,
                actor.id,
                did_from_public_key(bytes(key.verify_key)),
            )
            auth = _grant_headers(
                signing_key=bytes(key),
                did_key=did_from_public_key(bytes(key.verify_key)),
                grant_id=str(grant_id),
                method="GET",
                path=request.url.raw_path.decode(),
                aud=env.app.state.public_origin,
            )
        else:
            auth = headers(actor)
        request.headers.update(auth)

        class StreamClock(datetime):
            @classmethod
            def now(cls, tz=None):
                return clock.now

        async def advance_poll(seconds):
            clock.polls += 1
            if clock.polls > 1:
                clock.now = start + timedelta(seconds=121)
                return
            clock.now = start + timedelta(seconds=62)
            clock.evidence += 62
            sent = await post(env, room)
            assert sent.status_code == 200, sent.text
            if tree == "revoked":
                await writer.revoke_id_certificate(
                    domain,
                    stable,
                    signer=_fixture_signer("root"),
                    expected_head=receipt["certificate_id"],
                )
            if tree != "legacy":
                assert transport.status_calls == 1  # opening admission warmed it
                transport.status_down = tree == "status_unavailable"
                # Wall-clock movement does not age Redis's clock. First prove
                # the still-fresh entry is used, then age that exact entry past
                # the production inclusive 60s bound without deleting it.
                evidence = await cached.id_chain_evidence(None, subject, domain=domain)
                assert evidence.age_seconds <= 60
                assert transport.status_calls == 1
                cache_key = cached._id_status_cache_key(
                    status_request(None, subject, domain=domain)
                )
                raw = await env.redis.get(cache_key)
                assert raw is not None
                entry = json.loads(raw)
                redis_seconds, _ = await env.redis.time()
                entry["fetched_at"] = int(redis_seconds) - 61
                await env.redis.set(cache_key, json.dumps(entry), ex=60)

        monkeypatch.setattr(events_routes, "datetime", StreamClock)
        monkeypatch.setattr(
            events_routes, "asyncio", SimpleNamespace(sleep=advance_poll)
        )
        monkeypatch.setattr(identity_binding, "monotonic", lambda: clock.evidence)
        try:
            response = await env.client.send(request)
            assert response.status_code == 200, response.text
            assert "event: connected" in response.text
            notices = [
                json.loads(line[6:])
                for line in response.text.splitlines()
                if line.startswith("data: ")
                and json.loads(line[6:]).get("type") == "actionable_room_post"
            ]
            assert len(notices) == (
                1 if tree in ("valid", "legacy") else 0
            ), response.text
            assert transport.status_calls == (0 if tree == "legacy" else 2)
            row = await env.db.fetch_one(
                "SELECT status,team_id,did_key,deleted_at FROM {{tables.agents}} WHERE agent_id=$1",
                actor.id,
            )
            assert row["status"] == "active" and row["deleted_at"] is None
            assert row["team_id"] == TEAM and row["did_key"] == actor.did
        finally:
            env.app.state.awid_registry_client = writer
            await cached.aclose()
