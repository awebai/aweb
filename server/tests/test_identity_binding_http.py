"""Identity attribution through real AWID, HTTP, PostgreSQL and Redis."""

from __future__ import annotations

import json
import base64
import hashlib
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from awid.did import stable_id_from_did_key
from awid.registry import CachedRegistryClient
from awid.signing import canonical_json_bytes, sign_message
from test_cli_never_grants import registry_listener
from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401
from test_messages_http import (
    _encode_certificate,
    _make_certificate,
    _make_keypair,
    _signed_identity_headers,
    _signed_team_headers,
)


async def request(
    env, actor, method, path, payload=None, *, certificate=None, did_aw=None
):
    body = json.dumps(payload).encode() if payload is not None else b""
    if did_aw is not None:
        headers = _signed_identity_headers(actor.sk, actor.did, did_aw, body)
    else:
        headers = _signed_team_headers(
            actor.sk, actor.did, TEAM, certificate or actor.certificate, body
        )
    return await env.client.request(
        method,
        path,
        content=body,
        headers={**headers, "Content-Type": "application/json"},
    )


def certificate(env, actor, did_aw="", address=""):
    return _encode_certificate(
        _make_certificate(
            env.team_sk,
            env.team_did,
            actor.did,
            team_id=TEAM,
            alias="bob",
            identity_scope="global",
            member_did_aw=did_aw,
            member_address=address,
            certificate_id="identity-binding-bob",
        )
    )


async def register(env, registry, actor, name="bob"):
    identity = await registry.register_did(actor.did, actor.sk)
    # Namespace/address provisioning is fixture data; all resolution and DID
    # registration/rotation run through the actual AWID HTTP service.
    namespace = await env.registry_db.fetch_one(
        "INSERT INTO {{tables.dns_namespaces}} (domain, controller_did, verification_status) "
        "VALUES ('identity.test', $1, 'verified') RETURNING namespace_id",
        env.team_did,
    )
    await env.registry_db.execute(
        "INSERT INTO {{tables.public_addresses}} (namespace_id, name, did_aw) VALUES ($1, $2, $3)",
        namespace["namespace_id"],
        name,
        identity.did_aw,
    )
    return identity.did_aw, f"identity.test/{name}"


@pytest.mark.asyncio
@pytest.mark.parametrize("claim", ["other_identity", "other_address"])
async def test_connect_refuses_inconsistent_identity_claims_without_writes(
    privacy_app, claim
):
    env = privacy_app
    bob, alice = env.actors["bob"], env.actors["alice"]
    async with registry_listener(env) as (registry, _):
        stable, address = await register(env, registry, alice)
        if claim == "other_address":
            stable = (await registry.register_did(bob.did, bob.sk)).did_aw
        before = await env.db.fetch_all(
            "SELECT * FROM {{tables.agents}} ORDER BY agent_id"
        )
        result = await request(
            env,
            bob,
            "POST",
            "/v1/connect",
            {},
            certificate=certificate(env, bob, stable, address),
        )
        assert result.status_code == 403, result.text
        assert result.json()["detail"] == "identity_binding_mismatch"
        assert before == await env.db.fetch_all(
            "SELECT * FROM {{tables.agents}} ORDER BY agent_id"
        )


@pytest.mark.asyncio
async def test_verified_identity_connects_and_receives_mail(privacy_app):
    env = privacy_app
    bob, alice = env.actors["bob"], env.actors["alice"]
    async with registry_listener(env) as (registry, _):
        stable, address = await register(env, registry, bob)
        bob.certificate = certificate(env, bob, stable, address)
        connected = await request(env, bob, "POST", "/v1/connect", {})
        assert connected.status_code == 200, connected.text
        row = await env.db.fetch_one(
            "SELECT * FROM {{tables.agents}} WHERE agent_id=$1", bob.id
        )
        assert (row["did_aw"], row["address"], row["did_aw_verified_key"]) == (
            stable,
            address,
            bob.did,
        )
        sent = await request(
            env,
            alice,
            "POST",
            "/v1/messages",
            {"to_did": stable, "subject": "hello", "body": "hello"},
        )
        assert sent.status_code == 200, sent.text
        received = await request(
            env, bob, "GET", f"/v1/messages/{sent.json()['message_id']}"
        )
        assert received.status_code == 200, received.text


@pytest.mark.asyncio
async def test_self_derived_identity_requires_definitive_registry_absence(privacy_app):
    env = privacy_app
    bob = env.actors["bob"]
    stable = stable_id_from_did_key(bob.did)
    async with registry_listener(env):
        bob.certificate = certificate(env, bob, stable)
        connected = await request(env, bob, "POST", "/v1/connect", {})
        assert connected.status_code == 200, connected.text
        authenticated = await request(env, bob, "GET", "/v1/team")
        assert authenticated.status_code == 200, authenticated.text
        other = env.actors["alice"]
        forged = _encode_certificate(
            _make_certificate(
                env.team_sk,
                env.team_did,
                other.did,
                team_id=TEAM,
                alias="alice",
                member_did_aw=stable,
                identity_scope="global",
            )
        )
        refused = await request(
            env, other, "POST", "/v1/connect", {}, certificate=forged
        )
        assert refused.status_code == 403, refused.text


@pytest.mark.asyncio
@pytest.mark.parametrize("projection_transition", ["new", "migrated"])
async def test_rotation_requires_current_key_and_preserves_multi_team_identity(
    privacy_app, projection_transition
):
    env = privacy_app
    bob = env.actors["bob"]
    async with registry_listener(env) as (registry, _):
        stable = (await registry.register_did(bob.did, bob.sk)).did_aw
        new_sk, _, new_did = _make_keypair()
        await registry.rotate_key(stable, new_did, bob.sk, new_sk)
        # Self-derivation is not a fallback for a registered, rotated identity.
        refused = await request(
            env,
            bob,
            "POST",
            "/v1/connect",
            {},
            certificate=certificate(env, bob, stable),
        )
        assert refused.status_code == 403, refused.text
        bob.sk, bob.did = new_sk, new_did
        bob.certificate = certificate(env, bob, stable)
        # A fresh current-key projection may join the same identity in each
        # team, while the old key projection cannot acquire current authority.
        if projection_transition == "new":
            await env.db.execute(
                "UPDATE {{tables.workspaces}} SET deleted_at=NOW() WHERE agent_id=$1",
                bob.id,
            )
            await env.db.execute(
                "UPDATE {{tables.agents}} SET deleted_at=NOW() WHERE agent_id=$1",
                bob.id,
            )
        else:
            await env.db.execute(
                "UPDATE {{tables.agents}} SET did_key=$1 WHERE agent_id=$2",
                bob.did,
                bob.id,
            )
        first = await request(env, bob, "POST", "/v1/connect", {})
        assert first.status_code == 200, first.text
        second_team = f"second-{uuid4().hex[:8]}:example.test"
        await env.registry_db.execute(
            "INSERT INTO {{tables.teams}} (domain,name,team_did_key,visibility) VALUES ('example.test',$1,$2,'public')",
            second_team.split(":")[0],
            env.team_did,
        )
        cert = _encode_certificate(
            _make_certificate(
                env.team_sk,
                env.team_did,
                bob.did,
                team_id=second_team,
                alias="bob",
                member_did_aw=stable,
                identity_scope="global",
            )
        )
        body = b"{}"
        headers = _signed_team_headers(bob.sk, bob.did, second_team, cert, body)
        second = await env.client.post(
            "/v1/connect",
            content=body,
            headers={**headers, "Content-Type": "application/json"},
        )
        assert second.status_code == 200, second.text
        rows = await env.db.fetch_all(
            "SELECT did_aw_verified_key FROM {{tables.agents}} WHERE did_aw=$1 AND deleted_at IS NULL",
            stable,
        )
        assert len(rows) == 2 and all(
            row["did_aw_verified_key"] == bob.did for row in rows
        )
        identity_inbox = await request(env, bob, "GET", "/v1/messages/inbox", did_aw=stable)
        assert identity_inbox.status_code == 200, identity_inbox.text


@pytest.mark.asyncio
async def test_old_projections_require_verification_before_stable_resolution(
    privacy_app,
):
    from aweb.messaging.messages import resolve_agent_by_did
    from aweb.federation.delivery import _lock_current_recipient
    from aweb.federation.envelope import FederationEnvelope
    from awid.federation_errors import FederationAuthorityError
    from aweb.messaging.chat import resolve_agent_by_did as resolve_chat

    env = privacy_app
    bob = env.actors["bob"]
    async with registry_listener(env) as (registry, _):
        stable, address = await register(env, registry, bob)
        await env.db.execute(
            "UPDATE {{tables.agents}} SET did_aw=$1,address=$2 WHERE agent_id=$3",
            stable,
            address,
            bob.id,
        )
        envelope = FederationEnvelope(
            type="mail",
            sender_did_aw=stable_id_from_did_key(env.actors["alice"].did),
            sender_current_did_key=env.actors["alice"].did,
            target_did_aw=stable,
            target_current_did_key=bob.did,
            target_address=address,
            target_delivery_origin=str(env.client.base_url).rstrip("/"),
            message_id=str(uuid4()),
            timestamp=datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            signed_payload="{}",
            body="hello",
        )
        async with env.db.transaction() as tx:
            with pytest.raises(FederationAuthorityError):
                await _lock_current_recipient(
                    tx, envelope=envelope, recipient={"agent_id": bob.id}
                )
        other_team = f"other-{uuid4().hex[:8]}:identity.test"
        _, _, other_key = _make_keypair()
        await env.db.execute(
            "INSERT INTO {{tables.teams}} (team_id,namespace,team_name,team_did_key) VALUES ($1,'identity.test','other',$2)",
            other_team, env.team_did,
        )
        await env.db.execute(
            "INSERT INTO {{tables.agents}} (team_id,did_key,did_aw,address,alias,identity_scope,inbound_mode) "
            "VALUES ($1,$2,$3,$4,'other','global','open')",
            other_team,other_key,stable,address,
        )
        assert await resolve_agent_by_did(env.infra, stable) is None
        assert await resolve_chat(env.infra, stable) is None
        assert await resolve_agent_by_did(env.infra, bob.did) is not None
        bob.certificate = certificate(env, bob, stable, address)
        authenticated = await request(env, bob, "GET", "/v1/team")
        assert authenticated.status_code == 200, authenticated.text
        assert (await resolve_agent_by_did(env.infra, stable))["agent_id"] == bob.id
        from aweb.messaging.messages import _active_team_ids_for_identity
        from aweb.identity_metadata import lookup_identity_metadata_by_did
        assert other_team not in await _active_team_ids_for_identity(env.infra,[stable,bob.did])
        metadata=await lookup_identity_metadata_by_did(env.infra,[other_key])
        assert not metadata[other_key].get("stable_id")
        assert not metadata[other_key].get("address")

        async with env.db.transaction() as tx:
            current = await _lock_current_recipient(
                tx, envelope=envelope, recipient={"agent_id": bob.id}
            )
            assert current["did_aw"] == stable


@pytest.mark.asyncio
async def test_registry_outage_does_not_provision_or_use_self_derivation(privacy_app):
    env = privacy_app
    bob = env.actors["bob"]
    async with registry_listener(env) as (_, origin):
        cached = CachedRegistryClient(origin, env.redis)
        await cached.get_team_public_key("example.test", TEAM.split(":")[0])
        await cached.get_team_revocations("example.test", TEAM.split(":")[0])
    # Stop the actual listener after warming only team facts. Identity reads
    # must fail closed rather than infer registry absence from a connection error.
    existing = env.app.state.awid_registry_client
    env.app.state.awid_registry_client = cached
    try:
        stable = stable_id_from_did_key(bob.did)
        before = await env.db.fetch_all(
            "SELECT * FROM {{tables.agents}} ORDER BY agent_id"
        )
        result = await request(
            env,
            bob,
            "POST",
            "/v1/connect",
            {},
            certificate=certificate(env, bob, stable),
        )
        assert result.status_code == 503, result.text
        assert before == await env.db.fetch_all(
            "SELECT * FROM {{tables.agents}} ORDER BY agent_id"
        )
    finally:
        env.app.state.awid_registry_client = existing
        await cached.aclose()


@pytest.mark.asyncio
async def test_identity_and_grant_auth_recheck_the_subject_binding(privacy_app):
    env = privacy_app
    bob = env.actors["bob"]
    async with registry_listener(env) as (registry, _):
        stable, address = await register(env, registry, bob)
        bob.certificate = certificate(env, bob, stable, address)
        connected = await request(env, bob, "POST", "/v1/connect", {})
        assert connected.status_code == 200, connected.text
        grant_sk, _, grant_did = _make_keypair()
        minted = await request(
            env,
            bob,
            "POST",
            "/v1/identity-grants",
            {
                "grant_did_key": grant_did,
                "scopes": ["mail.read"],
                "ttl_seconds": 3600,
            },
        )
        assert minted.status_code == 200, minted.text
        grant_id = minted.json()["grant_id"]
        sent = await request(
            env,
            env.actors["alice"],
            "POST",
            "/v1/messages",
            {
                "to_did": stable,
                "subject": "hello",
                "body": "hello",
            },
        )
        assert sent.status_code == 200, sent.text
        path = f"/v1/messages/{sent.json()['message_id']}"

        async def grant_read():
            timestamp = datetime.now(timezone.utc).isoformat()
            payload = canonical_json_bytes(
                dict(
                    v=1,
                    auth="identity-grant",
                    method="GET",
                    path=path,
                    grant_id=grant_id,
                    body_sha256=hashlib.sha256(b"").hexdigest(),
                    timestamp=timestamp,
                    aud=str(env.client.base_url).rstrip("/"),
                )
            )
            return await env.client.get(
                path,
                headers={
                    "Authorization": f"AWEB-Grant DIDKey {grant_did} {sign_message(grant_sk, payload)}",
                    "X-AWEB-Grant-ID": grant_id,
                    "X-AWEB-Timestamp": timestamp,
                    "X-AWEB-Signed-Payload": base64.urlsafe_b64encode(payload)
                    .decode()
                    .rstrip("="),
                },
            )

        allowed = await grant_read()
        assert allowed.status_code == 200, allowed.text
        identity_read = await request(env, bob, "GET", path, did_aw=stable)
        assert identity_read.status_code == 200, identity_read.text
        other = (
            await registry.register_did(env.actors["carol"].did, env.actors["carol"].sk)
        ).did_aw
        await env.db.execute(
            "UPDATE {{tables.agents}} SET did_aw=$1,address=NULL,did_aw_verified_key=NULL WHERE agent_id=$2",
            other,
            bob.id,
        )
        refused = await grant_read()
        assert refused.status_code == 403, refused.text
        identity_refused = await request(env, bob, "GET", path, did_aw="")
        assert identity_refused.status_code == 403, identity_refused.text


@pytest.mark.asyncio
async def test_observing_rotated_identity_excludes_prior_key_projections(privacy_app):
    from aweb.messaging.messages import resolve_agent_by_did

    env = privacy_app
    bob = env.actors["bob"]
    async with registry_listener(env) as (registry, _):
        stable = (await registry.register_did(bob.did, bob.sk)).did_aw
        bob.certificate = certificate(env, bob, stable)
        admitted = await request(env, bob, "POST", "/v1/connect", {})
        assert admitted.status_code == 200, admitted.text
        old_key, old_certificate = bob.did, bob.certificate
        new_sk, _, new_key = _make_keypair()
        await registry.rotate_key(stable, new_key, bob.sk, new_sk)
        old_sk = bob.sk
        bob.did, bob.sk = new_key, new_sk
        authenticated = await request(
            env, bob, "GET", "/v1/messages/inbox", did_aw=stable
        )
        assert authenticated.status_code == 200, authenticated.text
        old_row = await env.db.fetch_one(
            "SELECT did_key,did_aw_verified_key FROM {{tables.agents}} WHERE agent_id=$1",
            bob.id,
        )
        assert old_row["did_key"] == old_key
        assert old_row["did_aw_verified_key"] is None
        assert await resolve_agent_by_did(env.infra, stable) is None
        # A superseded positive cache entry must not restore the old marker.
        bob.did, bob.sk = old_key, old_sk
        denied = await request(env, bob, "GET", "/v1/team", certificate=old_certificate)
        assert denied.status_code == 403, denied.text


@pytest.mark.asyncio
async def test_cached_prior_key_cannot_change_routing_markers(privacy_app):
    from collections import OrderedDict
    from types import SimpleNamespace
    from starlette.requests import Request
    from aweb.identity_binding import refresh_projection_binding, verify_identity_binding
    from aweb.messaging.messages import resolve_agent_by_did

    env = privacy_app
    bob = env.actors["bob"]
    async with registry_listener(env) as (registry, _):
        stable = (await registry.register_did(bob.did, bob.sk)).did_aw
        bob.certificate = certificate(env, bob, stable)
        assert (await request(env, bob, "POST", "/v1/connect", {})).status_code == 200
        old_cache = OrderedDict(env.app.state.identity_binding_cache)
        new_sk, _, new_key = _make_keypair()
        await registry.rotate_key(stable, new_key, bob.sk, new_sk)
        new_row = await env.db.fetch_one(
            "INSERT INTO {{tables.agents}} (team_id,did_key,did_aw,alias,identity_scope) "
            "VALUES ($1,$2,$3,'new-bob','global') RETURNING agent_id", TEAM,new_key,stable,
        )
        other_worker = Request({"type":"http", "app":SimpleNamespace(state=SimpleNamespace(awid_registry_client=registry))})
        current = await verify_identity_binding(other_worker, did_key=new_key, did_aw=stable)
        await refresh_projection_binding(env.db, agent_id=new_row["agent_id"], did_key=new_key, binding=current)
        before = await env.db.fetch_all("SELECT * FROM {{tables.agents}} ORDER BY agent_id")
        # Model the allowed 60-second authentication cache of a different worker.
        env.app.state.identity_binding_cache = old_cache
        cached_auth = await request(env, bob, "GET", "/v1/team")
        assert cached_auth.status_code == 200, cached_auth.text
        assert before == await env.db.fetch_all("SELECT * FROM {{tables.agents}} ORDER BY agent_id")
        assert (await resolve_agent_by_did(env.infra,stable))["agent_id"] == new_row["agent_id"]


@pytest.mark.asyncio
async def test_operator_verification_restores_only_bound_projections(privacy_app):
    import asyncio
    import os
    import sys
    from urllib.parse import quote
    from aweb.messaging.messages import resolve_agent_by_did

    env = privacy_app
    bob, alice, carol = (env.actors[name] for name in ("bob","alice","carol"))
    async with registry_listener(env) as (registry, origin):
        stable,address = await register(env,registry,bob)
        self_derived = stable_id_from_did_key(carol.did)
        for actor,claim,claimed_address in ((bob,stable,address),(alice,stable,None),(carol,self_derived,None)):
            await env.db.execute(
                "UPDATE {{tables.agents}} SET identity_scope='global',did_aw=$2,address=$3,did_aw_verified_key=NULL WHERE agent_id=$1",
                actor.id,claim,claimed_address,
            )
        db_name = await env.db.fetch_value("SELECT current_database()")
        child_env = dict(os.environ)
        user = quote(os.environ.get("TEST_DB_USER", "postgres"), safe="")
        password = quote(os.environ.get("TEST_DB_PASSWORD", "postgres"), safe="")
        host = os.environ.get("TEST_DB_HOST", "localhost")
        port = os.environ.get("TEST_DB_PORT", "5432")
        child_env.update(AWEB_DATABASE_URL=f"postgresql://{user}:{password}@{host}:{port}/{db_name}", AWID_REGISTRY_URL=origin)

        async def operator(*options):
            command = await asyncio.create_subprocess_exec(
                sys.executable, "-c", "from aweb.cli import app; app()",
                "verify-identity-bindings", *options, env=child_env,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            output,error = await asyncio.wait_for(command.communicate(), 30)
            assert command.returncode == 1, error.decode()
            return json.loads(output)

        before = await env.db.fetch_all("SELECT * FROM {{tables.agents}} ORDER BY agent_id")
        assert await resolve_agent_by_did(env.infra,stable) is None
        expected = dict(verified=1,self_derived=1,unbound=1,awid_error=0)
        assert await operator("--dry-run") == expected
        assert before == await env.db.fetch_all("SELECT * FROM {{tables.agents}} ORDER BY agent_id")
        assert await operator() == expected
        after = await env.db.fetch_all("SELECT * FROM {{tables.agents}} ORDER BY agent_id")
        assert [{**dict(row),"did_aw_verified_key":None} for row in after] == [dict(row) for row in before]
        assert (await resolve_agent_by_did(env.infra,stable))["agent_id"] == bob.id
        assert (await resolve_agent_by_did(env.infra,self_derived))["agent_id"] == carol.id
        assert next(row for row in after if row["agent_id"]==alice.id)["did_aw_verified_key"] is None
        assert await operator() == dict(verified=0,self_derived=0,unbound=1,awid_error=0)
        assert after == await env.db.fetch_all("SELECT * FROM {{tables.agents}} ORDER BY agent_id")


@pytest.mark.asyncio
async def test_operator_verification_preserves_rows_on_registry_error(privacy_app):
    from aweb.identity_binding import verify_pending_identity_bindings

    env = privacy_app
    bob = env.actors["bob"]
    await env.db.execute("UPDATE {{tables.agents}} SET identity_scope='local',did_aw=NULL,address=NULL,did_aw_verified_key=NULL")
    async with registry_listener(env) as (registry, origin):
        stable = (await registry.register_did(bob.did,bob.sk)).did_aw
        await env.db.execute("UPDATE {{tables.agents}} SET identity_scope='global',did_aw=$2 WHERE agent_id=$1",bob.id,stable)
    client = CachedRegistryClient(origin,env.redis)
    try:
        before = await env.db.fetch_all("SELECT * FROM {{tables.agents}} ORDER BY agent_id")
        assert await verify_pending_identity_bindings(env.db,client) == dict(verified=0,self_derived=0,unbound=0,awid_error=1)
        assert before == await env.db.fetch_all("SELECT * FROM {{tables.agents}} ORDER BY agent_id")
    finally:
        await client.aclose()
