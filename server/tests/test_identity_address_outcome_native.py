"""Address-read failure is unknown, not proof that an identity has no address.

The real registry uses PostgreSQL. A held table lock makes its address read
time out through the real SDK; key binding is warmed from that same registry.
No registry, authentication, database or delivery behavior is substituted.
"""

from contextlib import asynccontextmanager
import json
from types import SimpleNamespace
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import httpx
import pytest
from starlette.requests import Request

from aweb.identity_auth_deps import resolve_identity_auth
from aweb.identity_binding import verify_identity_binding
from aweb.mcp.auth import MCPAuthMiddleware
from aweb.mcp.tools.federation import mcp_messaging_auth
from awid.registry import RegistryClient, RegistryError
from identity_binding_support import register_global_identity
from tests.test_dashboard_privacy import privacy_app as privacy_app  # noqa: PLC0414
from tests.test_messages_http import _signed_identity_headers


def identity_request(env, actor):
    """A genuine signed identity request admitted by the production verifier."""
    origin = urlsplit(str(env.client.base_url))
    headers = _signed_identity_headers(actor.sk, actor.did, actor.stable_id)
    return Request({
        "type": "http", "scheme": origin.scheme, "method": "GET",
        "server": (origin.hostname, origin.port),
        "path": "/v1/messages/inbox", "raw_path": b"/v1/messages/inbox",
        "query_string": b"", "app": env.app,
        "headers": [(key.lower().encode(), value.encode()) for key, value in headers.items()],
    })


async def prepare_actor(env, name, *, address):
    original = env.actors[name]
    stable_id = await register_global_identity(env, original, address)
    await env.db.execute(
        "UPDATE {{tables.agents}} SET identity_scope='global', did_aw=$1, "
        "address=$2, did_aw_verified_key=did_key WHERE agent_id=$3",
        stable_id, address or None, original.id,
    )
    actor = SimpleNamespace(**vars(original), stable_id=stable_id, address=address)
    # These are actual observations, not seeded positive cache entries. Do not
    # warm reverse enumeration: the subsequent failure must reach the registry.
    request = identity_request(env, actor)
    await verify_identity_binding(request, did_key=actor.did, did_aw=stable_id)
    if address:
        await verify_identity_binding(
            request, did_key=actor.did, did_aw=stable_id, address=address,
        )
    return actor


@asynccontextmanager
async def address_reader(env):
    original = env.app.state.awid_registry_client
    # ASGI is only the transport: this is the production AWID application and
    # its real SQL route, with a bounded production SDK timeout.
    reader = RegistryClient(
        registry_url=original.registry_url, timeout_seconds=1,
        transport=httpx.ASGITransport(app=env.registry_app),
        service_token=original.service_token,
    )
    env.app.state.awid_registry_client = reader
    try:
        yield reader
    finally:
        env.app.state.awid_registry_client = original
        await reader.aclose()


@asynccontextmanager
async def stalled_address_read(env):
    # Separate real PG connection; only registry address queries are blocked.
    # DID/key and independent team/revocation evidence stay available. Leaving
    # the transaction releases the fault and exercises recovery on the same SDK.
    async with env.registry_db.transaction() as lock:
        await lock.execute("LOCK TABLE {{tables.public_addresses}} IN ACCESS EXCLUSIVE MODE")
        yield


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
async def test_failed_reverse_read_is_unknown_and_recovers_without_empty_evidence(privacy_app, caplog):
    env = privacy_app
    async with address_reader(env):
        actor = await prepare_actor(env, "alice", address=f"example.test/adbv-{uuid4().hex}")
        before = await projection(env, actor)
        async with stalled_address_read(env):
            # Establish the actual dependency failure independently of auth's
            # current broad catch. This must not be an invented HTTP response.
            with pytest.raises(RegistryError) as failed:
                await env.app.state.awid_registry_client.list_did_addresses(actor.stable_id)
            assert failed.value.status_code == 503
            assert isinstance(failed.value.__cause__, TimeoutError)

            request = identity_request(env, actor)
            signature = request.headers["Authorization"].split()[-1]
            identity = await resolve_identity_auth(request)
            assert identity.did_aw == actor.stable_id
            assert identity.did_key == actor.did
            outcome = getattr(identity, "address_resolution", None)
            assert outcome is not None, "unavailable enumeration was discarded as an empty address list"
            assert outcome.state == "unknown"
            assert isinstance(outcome.cause, RegistryError)
            assert outcome.cause.status_code == 503
            assert await projection(env, actor) == before

            # The second production auth adapter must carry the same UNKNOWN
            # outcome through its messaging conversion, not collapse to empty.
            context = await MCPAuthMiddleware(env.app, env.infra)._resolve_auth(identity_request(env, actor))
            assert context.address_resolution.state == "unknown"
            assert isinstance(context.address_resolution.cause, RegistryError)
            assert context.address == actor.address
            assert mcp_messaging_auth(context).address_resolution is context.address_resolution
            assert await projection(env, actor) == before

        recovered = await resolve_identity_auth(identity_request(env, actor))
        assert recovered.address == actor.address
        assert recovered.address_resolution.state == "verified"
        assert recovered.address_resolution.cause is None
        diagnostics = [r.getMessage() for r in caplog.records if r.name == "aweb.identity_auth_deps"]
        assert any("address" in line and "unavailable" in line for line in diagnostics)
        assert all(signature not in line and actor.address not in line for line in diagnostics)
        assert all(env.app.state.awid_registry_client.service_token not in line for line in diagnostics)


@pytest.mark.asyncio
async def test_successful_empty_reverse_read_is_distinct_from_unknown(privacy_app):
    env = privacy_app
    async with address_reader(env):
        actor = await prepare_actor(env, "bob", address="")
        identity = await resolve_identity_auth(identity_request(env, actor))
        assert identity.address is None
        outcome = getattr(identity, "address_resolution", None)
        assert outcome is not None
        assert outcome.state == "empty"
        assert outcome.cause is None
        # An authoritative empty result is still a supported addressless send,
        # unlike unavailable required evidence. It must not acquire the new gate.
        message_id = uuid4()
        sent = await send(env, actor, {
            "to_did": env.actors["carol"].did, "message_id": str(message_id),
            "subject": "known addressless", "body": "no invented From",
        })
        assert sent.status_code == 200, sent.text
        stored = await env.db.fetch_one(
            "SELECT from_address FROM {{tables.messages}} WHERE message_id=$1", message_id,
        )
        assert stored["from_address"] is None


@pytest.mark.asyncio
async def test_address_outage_preserves_verified_sender_and_refuses_unknown_before_effect(privacy_app):
    env = privacy_app
    async with address_reader(env):
        verified = await prepare_actor(env, "alice", address=f"example.test/adbv-{uuid4().hex}")
        verified_empty = await prepare_actor(env, "bob", address="")
        unknown = await prepare_actor(env, "carol", address="")
        await env.db.execute(
            "UPDATE {{tables.agents}} SET did_aw_verified_key=NULL WHERE agent_id=$1", unknown.id,
        )
        before = {actor.id: await projection(env, actor) for actor in (verified, verified_empty, unknown)}
        async with stalled_address_read(env):
            kept_id, empty_id, refused_id = str(uuid4()), str(uuid4()), str(uuid4())
            kept = await send(env, verified, {
                "to_did": verified_empty.did, "message_id": kept_id,
                "subject": "existing sender", "body": "verified local address stays usable",
            })
            assert kept.status_code == 200, kept.text
            stored = await env.db.fetch_one(
                "SELECT from_did,from_address FROM {{tables.messages}} WHERE message_id=$1",
                UUID(kept_id),
            )
            assert stored["from_did"] == verified.stable_id
            assert stored["from_address"] == verified.address

            empty = await send(env, verified_empty, {
                "to_did": verified.did, "message_id": empty_id,
                "subject": "verified empty", "body": "verified addressless sender stays usable",
            })
            assert empty.status_code == 200, empty.text
            stored_empty = await env.db.fetch_one(
                "SELECT from_did,from_address FROM {{tables.messages}} WHERE message_id=$1", UUID(empty_id),
            )
            assert stored_empty["from_did"] == verified_empty.stable_id
            assert stored_empty["from_address"] is None

            dispatched = len(env.dispatched)
            refused = await send(env, unknown, {
                "to_did": verified.did, "message_id": refused_id,
                "subject": "unknown address", "body": "must not choose another From",
            })
            assert refused.status_code == 503, refused.text
            assert refused.json()["detail"]["code"] == "address_evidence_unavailable"
            assert await env.db.fetch_value(
                "SELECT COUNT(*) FROM {{tables.messages}} WHERE message_id=$1",
                UUID(refused_id),
            ) == 0
            assert len(env.dispatched) == dispatched
            for actor in (verified, verified_empty, unknown):
                assert await projection(env, actor) == before[actor.id]
