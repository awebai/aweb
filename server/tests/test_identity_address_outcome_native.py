"""Address-read failure is unknown, not proof that an identity has no address.

The real registry uses PostgreSQL. A held table lock makes its address read
time out through the real SDK; key binding is warmed from that same registry.
No registry, authentication, database or delivery behavior is substituted.
"""

import asyncio
from contextlib import asynccontextmanager, contextmanager
from dataclasses import replace
import json
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import httpx
import pytest
import pytest_asyncio
from starlette.requests import Request

from aweb.identity_auth_deps import get_messaging_auth, resolve_identity_auth
from aweb.identity_binding import verify_identity_binding
from aweb.mcp.auth import MCPAuthMiddleware
from aweb.mcp.tools.federation import mcp_messaging_auth
from awid.registry import RegistryClient, RegistryError
from messaging_actor_support import admit_messaging_actor, privacy_actor, register_messaging_team
from tests.test_dashboard_privacy import TEAM, privacy_stack
from tests.test_messages_http import _signed_identity_headers


@pytest_asyncio.fixture
async def address_world(shared_test_pool, monkeypatch):
    async with privacy_stack(shared_test_pool, monkeypatch, aliases=()) as env:
        yield env


def identity_request(env, actor):
    """A genuine signed identity request admitted by the production verifier."""
    origin = urlsplit(str(env.client.base_url))
    headers = _signed_identity_headers(actor.sk, actor.did, actor.stable_id)
    return Request(
        {
            "type": "http",
            "scheme": origin.scheme,
            "method": "GET",
            "server": (origin.hostname, origin.port),
            "path": "/v1/messages/inbox",
            "raw_path": b"/v1/messages/inbox",
            "query_string": b"",
            "app": env.app,
            "headers": [(key.lower().encode(), value.encode()) for key, value in headers.items()],
        }
    )


async def prepare_actor(env, name, *, address):
    member = await admit_messaging_actor(env, alias=name, team_id=TEAM, address=address)
    actor = privacy_actor(member)
    # These are actual observations, not seeded positive cache entries. Do not
    # warm reverse enumeration: the subsequent failure must reach the registry.
    request = identity_request(env, actor)
    await verify_identity_binding(request, did_key=actor.did, did_aw=actor.stable_id)
    if address:
        await verify_identity_binding(
            request,
            did_key=actor.did,
            did_aw=actor.stable_id,
            address=address,
        )
    await assert_registered_identity_membership(env, actor, team_id=TEAM)
    return actor


async def assert_registered_identity_membership(env, actor, *, team_id):
    name, domain = team_id.split(":", 1)
    registry = env.app.state.awid_registry_client
    certificates = await registry.list_team_certificates(domain, name, active_only=True)
    assert [
        (certificate.member_did_aw, certificate.member_address or "")
        for certificate in certificates
        if certificate.member_did_key == actor.did
    ] == [(actor.stable_id, actor.address)]


@asynccontextmanager
async def stalled_address_read(env):
    original = env.app.state.awid_registry_client
    reader = RegistryClient(
        registry_url=original.registry_url,
        timeout_seconds=1,
        transport=httpx.ASGITransport(app=env.registry_app),
        service_token=original.service_token,
    )
    try:
        # Hold the fault on a separate connection. The one-second client
        # bounds the locked address read while the real AWID routes still run.
        async with env.registry_db.transaction() as lock:
            await lock.execute("LOCK TABLE {{tables.public_addresses}} IN ACCESS EXCLUSIVE MODE")
            env.app.state.awid_registry_client = reader
            try:
                yield reader
            finally:
                env.app.state.awid_registry_client = original
    finally:
        await reader.aclose()


@contextmanager
def slow_setup_key_read(env):
    """Delay one real key read past the outage deadline during healthy setup."""
    app = env.registry_app
    registry_app = app.middleware_stack or app.build_middleware_stack()
    delayed = False

    async def delay(scope, receive, send):
        nonlocal delayed
        path = scope.get("path", "")
        if not delayed and scope.get("method") == "GET" and path.startswith("/v1/did/") and path.endswith("/key"):
            delayed = True
            await asyncio.sleep(1.1)
        await registry_app(scope, receive, send)

    app.middleware_stack = delay
    try:
        yield
    finally:
        app.middleware_stack = registry_app
    assert delayed


async def projection(env, actor):
    row = await env.db.fetch_one(
        "SELECT did_aw,address,did_aw_verified_key FROM {{tables.agents}} WHERE agent_id=$1",
        actor.id,
    )
    return dict(row)


async def send(env, actor, body):
    raw = json.dumps(body).encode()
    headers = _signed_identity_headers(actor.sk, actor.did, actor.stable_id, raw)
    headers["Content-Type"] = "application/json"
    return await env.client.post("/v1/messages", content=raw, headers=headers)


@pytest.mark.asyncio
async def test_failed_reverse_read_is_unknown_and_recovers_without_empty_evidence(
    address_world, caplog
):
    env = address_world
    actor = await prepare_actor(env, "alice", address="example.test/alice")
    before = await projection(env, actor)
    async with stalled_address_read(env) as reader:
        # Establish the actual dependency failure independently of auth's
        # current broad catch. This must not be an invented HTTP response.
        with pytest.raises(RegistryError) as failed:
            await reader.list_did_addresses(actor.stable_id)
        assert failed.value.status_code == 503
        assert isinstance(failed.value.__cause__, TimeoutError)

        request = identity_request(env, actor)
        signature = request.headers["Authorization"].split()[-1]
        identity = await resolve_identity_auth(request)
        assert identity.did_aw == actor.stable_id
        assert identity.did_key == actor.did
        outcome = getattr(identity, "address_resolution", None)
        assert outcome is not None, (
            "unavailable enumeration was discarded as an empty address list"
        )
        assert outcome.state == "unknown"
        assert isinstance(outcome.cause, RegistryError)
        assert outcome.cause.status_code == 503
        assert await projection(env, actor) == before

        # The second production auth adapter must carry the same UNKNOWN
        # outcome through its messaging conversion, not collapse to empty.
        context = await MCPAuthMiddleware(env.app, env.infra)._resolve_auth(
            identity_request(env, actor)
        )
        assert context.address_resolution.state == "unknown"
        assert isinstance(context.address_resolution.cause, RegistryError)
        assert context.address == actor.address
        assert mcp_messaging_auth(context).address_resolution is context.address_resolution
        assert await projection(env, actor) == before

    recovered = await resolve_identity_auth(identity_request(env, actor))
    assert recovered.address == actor.address
    assert recovered.address_resolution.state == "verified"
    assert recovered.address_resolution.cause is None
    diagnostics = [
        r.getMessage() for r in caplog.records if r.name == "aweb.identity_auth_deps"
    ]
    assert any("address" in line and "unavailable" in line for line in diagnostics)
    assert all(signature not in line and actor.address not in line for line in diagnostics)
    assert all(
        env.app.state.awid_registry_client.service_token not in line for line in diagnostics
    )


@pytest.mark.asyncio
async def test_successful_empty_reverse_read_is_distinct_from_unknown(address_world):
    env = address_world
    actor = await prepare_actor(env, "bob", address="")
    recipient = await admit_messaging_actor(env, alias="carol", team_id=TEAM, local=True)
    identity = await resolve_identity_auth(identity_request(env, actor))
    assert identity.address is None
    outcome = getattr(identity, "address_resolution", None)
    assert outcome is not None
    assert outcome.state == "empty"
    assert outcome.cause is None
    # An authoritative empty result is still a supported addressless send,
    # unlike unavailable required evidence. It must not acquire the new gate.
    message_id = uuid4()
    sent = await send(
        env,
        actor,
        {
            "to_did": recipient.did_key,
            "message_id": str(message_id),
            "subject": "known addressless",
            "body": "no invented From",
        },
    )
    assert sent.status_code == 200, sent.text
    stored = await env.db.fetch_one(
        "SELECT from_address FROM {{tables.messages}} WHERE message_id=$1",
        message_id,
    )
    assert stored["from_address"] is None


@pytest.mark.asyncio
async def test_address_outage_preserves_verified_sender_and_refuses_unknown_before_effect(
    address_world,
):
    env = address_world
    verified = await prepare_actor(env, "alice", address="example.test/alice")
    verified_empty = await prepare_actor(env, "bob", address="")
    unknown = await prepare_actor(env, "carol", address="")
    # Preserve the legacy projection case where a DID was stored before
    # verification evidence was retained.
    await env.db.execute(
        "UPDATE {{tables.agents}} SET did_aw_verified_key=NULL WHERE agent_id=$1",
        unknown.id,
    )
    before = {
        actor.id: await projection(env, actor) for actor in (verified, verified_empty, unknown)
    }
    async with stalled_address_read(env):
        kept_id, empty_id, refused_id = str(uuid4()), str(uuid4()), str(uuid4())
        kept = await send(
            env,
            verified,
            {
                "to_did": verified_empty.did,
                "message_id": kept_id,
                "subject": "existing sender",
                "body": "verified local address stays usable",
            },
        )
        assert kept.status_code == 200, kept.text
        stored = await env.db.fetch_one(
            "SELECT from_did,from_address FROM {{tables.messages}} WHERE message_id=$1",
            UUID(kept_id),
        )
        assert stored["from_did"] == verified.stable_id
        assert stored["from_address"] == verified.address

        empty = await send(
            env,
            verified_empty,
            {
                "to_did": verified.did,
                "message_id": empty_id,
                "subject": "verified empty",
                "body": "verified addressless sender stays usable",
            },
        )
        assert empty.status_code == 200, empty.text
        stored_empty = await env.db.fetch_one(
            "SELECT from_did,from_address FROM {{tables.messages}} WHERE message_id=$1",
            UUID(empty_id),
        )
        assert stored_empty["from_did"] == verified_empty.stable_id
        assert stored_empty["from_address"] is None

        dispatched = len(env.dispatched)
        refused = await send(
            env,
            unknown,
            {
                "to_did": verified.did,
                "message_id": refused_id,
                "subject": "unknown address",
                "body": "must not choose another From",
            },
        )
        assert refused.status_code == 503, refused.text
        assert refused.json()["detail"]["code"] == "address_evidence_unavailable"
        assert (
            await env.db.fetch_value(
                "SELECT COUNT(*) FROM {{tables.messages}} WHERE message_id=$1",
                UUID(refused_id),
            )
            == 0
        )
        assert len(env.dispatched) == dispatched
        for actor in (verified, verified_empty, unknown):
            assert await projection(env, actor) == before[actor.id]


@pytest.mark.asyncio
async def test_conflicting_verified_stored_addresses_refuse_during_outage_before_effect(
    address_world,
):
    env = address_world
    with slow_setup_key_read(env):
        actor = await prepare_actor(env, "alice", address="example.test/alice")
    recipient = await admit_messaging_actor(env, alias="bob", team_id=TEAM, local=True)
    other_domain = "second-member.test"
    other_address = f"{other_domain}/alice"
    other_team_id = f"second:{other_domain}"
    controller = await env.registry.ensure_namespace(domain=other_domain)
    registry = env.app.state.awid_registry_client
    await registry.register_address(
        other_domain, "alice", actor.stable_id, controller, current_did_key=actor.did,
    )
    await register_messaging_team(env, team_id=other_team_id)
    second = await admit_messaging_actor(
        env,
        alias="alice",
        team_id=other_team_id,
        existing_identity=replace(actor.registered, address=other_address),
    )
    await assert_registered_identity_membership(env, privacy_actor(second), team_id=other_team_id)
    before = [
        dict(row)
        for row in await env.db.fetch_all(
            "SELECT agent_id,did_aw,address,did_aw_verified_key FROM {{tables.agents}} "
            "WHERE did_key=$1 ORDER BY agent_id",
            actor.did,
        )
    ]
    assert len(before) == 2
    assert {row["agent_id"] for row in before} == {actor.id, UUID(second.agent_id)}
    assert {row["address"] for row in before} == {actor.address, other_address}
    assert all(row["did_aw_verified_key"] == actor.did for row in before)
    dispatched = len(env.dispatched)
    message_id = uuid4()
    async with stalled_address_read(env):
        auth = await get_messaging_auth(identity_request(env, actor), db=env.db)
        assert auth.address is None
        assert auth.address_resolution.state == "context_required"
        assert not auth.address_resolution.stored_binding_verified
        assert isinstance(auth.address_resolution.cause, RegistryError)
        response = await send(
            env,
            actor,
            {
                "to_did": recipient.did_key,
                "message_id": str(message_id),
                "subject": "ambiguous stored From",
                "body": "must not choose either address",
            },
        )
        assert response.status_code == 409, response.text
        assert response.json()["detail"]["code"] == "sender_context_required"
        assert "X-AWID-Team-Certificate" in response.json()["detail"]["message"]
        assert await env.db.fetch_value("SELECT COUNT(*) FROM {{tables.messages}}") == 0
        assert await env.db.fetch_value("SELECT COUNT(*) FROM {{tables.conversations}}") == 0
        assert len(env.dispatched) == dispatched
        after = [
            dict(row)
            for row in await env.db.fetch_all(
                "SELECT agent_id,did_aw,address,did_aw_verified_key FROM {{tables.agents}} "
                "WHERE did_key=$1 ORDER BY agent_id",
                actor.did,
            )
        ]
        assert after == before
