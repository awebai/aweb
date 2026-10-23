"""F1 reproductions on the unshipped S2 candidate, with real HTTP/auth/PG.

Expected behavior follows secrets' 6b5bee7f ruling. Missing-event diagnostics
are deliberately not specified here pending the design owner's amendment.
"""

import asyncio
import base64
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest
from awid.did import did_from_public_key
from nacl.signing import SigningKey

from aweb.hook_bindings import activate_binding, write_pending_bindings
from aweb.hook_producer import load_core_hooks
from aweb.routes.hook_bindings import router
from tests.test_app_events_http import _build_events_app
from tests.test_core_hook_bindings_http import headers
from tests.test_core_hook_key_config import configured
from tests.test_core_hook_producer import registration
from tests.test_hook_binding_activation import (
    AUDIENCE, DIGEST, INSTALLATION, ORIGIN, RECORD, TEAM, _install, env,
)
from tests.test_installation_http import (
    admin, client as installation_client, confirmation, db, origin, post,
)
from tests.test_messages_http import _encode_certificate, _make_certificate

pytestmark = pytest.mark.asyncio


async def signing_authority(mode, configured, monkeypatch):
    if mode == "absent":
        return None
    if mode == "valid":
        return load_core_hooks("https://core.example")
    # Load a genuinely valid configured key, then let wall time cross its
    # advertised boundary. No clock or product function is replaced.
    _, _, entry = configured
    cutoff = datetime.now(UTC).replace(microsecond=0) + timedelta(seconds=2)
    entry = dict(entry, valid_until=cutoff.strftime("%Y-%m-%dT%H:%M:%SZ"))
    monkeypatch.setenv("AWEB_HOOK_PRODUCER_KEYS", json.dumps([entry]))
    hooks = load_core_hooks("https://core.example")
    await asyncio.sleep(max(0, (cutoff - datetime.now(UTC)).total_seconds()) + 0.02)
    assert datetime.now(UTC) >= cutoff
    return hooks


async def mutation_registration(env):
    await _install(env.db)
    async with env.db.transaction() as tx:
        target, = await write_pending_bindings(
            tx, team_id=TEAM, app_id="logs", origin=ORIGIN, digest=DIGEST,
            installation_id=INSTALLATION, generation=1,
            declarations=[replace(RECORD, hook="post-mutation-hook")],
        )
    return target


async def owner_request(env, target, operation, hooks):
    member = SigningKey.generate()
    did = did_from_public_key(bytes(member.verify_key))
    await env.db.execute(
        "UPDATE {{tables.agents}} SET did_key=$1,did_aw=NULL,address=NULL,identity_scope='local' WHERE team_id=$2",
        did, TEAM,
    )
    cert = _encode_certificate(_make_certificate(
        bytes(env.owner.key), did_from_public_key(bytes(env.owner.key.verify_key)),
        did, team_id=TEAM, identity_scope="local",
    ))
    app = _build_events_app(env.db, public_origin=AUDIENCE)
    app.include_router(router)
    app.state.awid_registry_client = env.registry
    app.state.core_hooks = hooks
    signing, signature = env.owner.sign("hook-binding." + operation, target)
    body = json.dumps({"act": base64.b64encode(signing).decode(), "signature": signature}).encode()
    path = f"/v1/apps/hook-bindings/{target.binding_id}/{operation}"
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=False), base_url=AUDIENCE,
    ) as client:
        return await client.post(path, content=body, headers=headers(member, cert, body, path, uuid4().hex))


@pytest.mark.parametrize("mode", ["absent", "expired", "valid"])
async def test_activation_requires_current_core_key(env, configured, monkeypatch, mode):
    target = await mutation_registration(env)
    hooks = await signing_authority(mode, configured, monkeypatch)
    response = await owner_request(env, target, "activate", hooks)
    state = await env.db.fetch_value(
        "SELECT state FROM {{tables.app_hook_bindings}} WHERE binding_id=$1", target.binding_id,
    )
    nonces = await env.db.fetch_value("SELECT COUNT(*) FROM {{tables.owner_act_nonces}}")
    assert (response.status_code, state, nonces) == (
        (200, "active", 1) if mode == "valid" else (409, "pending", 0)
    ), response.text
    if mode != "valid":
        assert response.json()["detail"] == "core_hook_producer_unconfigured"


@pytest.mark.parametrize("mode", ["absent", "expired", "valid"])
async def test_owner_revocation_commits_with_an_owed_observer(env, configured, monkeypatch, mode):
    target = await mutation_registration(env)
    signing, signature = env.owner.sign("hook-binding.activate", target)
    await activate_binding(
        env.db, env.verifier, team_id=TEAM, binding_id=target.binding_id,
        signing=signing, signature=signature,
    )
    # The revoked target alone would disappear from active resolution. This
    # second eligible registration makes the revocation event genuinely owed.
    await registration(env.db, team=TEAM, app="observer")
    hooks = await signing_authority(mode, configured, monkeypatch)
    response = await owner_request(env, target, "revoke", hooks)
    state = await env.db.fetch_value(
        "SELECT state FROM {{tables.app_hook_bindings}} WHERE binding_id=$1", target.binding_id,
    )
    nonces = await env.db.fetch_value("SELECT COUNT(*) FROM {{tables.owner_act_nonces}}")
    assert (response.status_code, state, nonces) == (200, "revoked", 2), response.text
    if mode == "valid":
        assert await env.db.fetch_value("SELECT COUNT(*) FROM {{tables.outbox_events}}") == 1


@pytest.mark.parametrize("mode", ["absent", "expired", "valid"])
async def test_http_install_commits_when_core_key_unavailable(
    db, origin, configured, installation_client, monkeypatch, mode,
):
    await admin(db)
    await registration(db)
    outer = installation_client._transport.app
    inner = next(route.app for route in outer.routes if route.path == "/api")
    inner.state.core_hooks = await signing_authority(mode, configured, monkeypatch)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=outer, raise_app_exceptions=False), base_url="http://test",
    ) as client:
        response = await post(client, confirmation(origin))
    installed = await db.fetch_value("SELECT COUNT(*) FROM {{tables.team_app_installs}} WHERE app_id='fixture'")
    assert (response.status_code, installed) == (200, 1), response.text
    if mode == "valid":
        assert await db.fetch_value("SELECT COUNT(*) FROM {{tables.outbox_events}}") == 1
