"""Real certificate and owner-act auth, PostgreSQL effects and hook enqueue."""

import base64
import hashlib
import json
from datetime import UTC, datetime

import httpx
import pytest
from awid.did import did_from_public_key
from awid.signing import canonical_json_bytes, sign_message
from nacl.signing import SigningKey

from aweb.hook_bindings import activate_binding
from aweb.routes.hook_bindings import router
from aweb_naapp.hooks.envelope import verify
from tests.test_core_hook_producer import context, registration
from tests.test_hook_binding_activation import env, TEAM, AUDIENCE, _install, _bindings
from tests.test_messages_http import _make_certificate, _encode_certificate
from tests.test_app_events_http import _build_events_app

pytestmark = pytest.mark.asyncio


def headers(key, cert, body, path, trace, signed_trace=True):
    timestamp = datetime.now(UTC).isoformat()
    fields = {
        "v": 2, "aud": AUDIENCE, "method": "POST", "path": path, "team_id": TEAM,
        "body_sha256": hashlib.sha256(body).hexdigest(), "timestamp": timestamp,
    }
    if signed_trace:
        fields["trace_id"] = trace
    signed = canonical_json_bytes(fields)
    return {
        "Authorization": f"DIDKey {did_from_public_key(bytes(key.verify_key))} {sign_message(bytes(key), signed)}",
        "X-AWEB-Signed-Payload": base64.urlsafe_b64encode(signed).decode().rstrip("="),
        "X-AWEB-Timestamp": timestamp, "X-AWID-Team-Certificate": cert, "Content-Type": "application/json",
        "X-Request-ID": trace,
    }


@pytest.mark.parametrize("operation,signed_trace", [("activate", True), ("revoke", True), ("activate", False)])
async def test_binding_and_event_commit_together_and_retry_after_recording_failure(env, operation, signed_trace):
    await _install(env.db)
    target, _ = await _bindings(env)
    if operation == "revoke":
        signing, signature = env.owner.sign("hook-binding.activate", target)
        await activate_binding(env.db, env.verifier, team_id=TEAM, binding_id=target.binding_id, signing=signing, signature=signature)
    await registration(env.db, team=TEAM, app="observer")
    member = SigningKey.generate()
    did = did_from_public_key(bytes(member.verify_key))
    await env.db.execute("UPDATE {{tables.agents}} SET did_key=$1,did_aw=NULL,address=NULL,identity_scope='local' WHERE team_id=$2", did, TEAM)
    cert = _encode_certificate(_make_certificate(
        bytes(env.owner.key), did_from_public_key(bytes(env.owner.key.verify_key)), did,
        team_id=TEAM, identity_scope="local",
    ))
    app = _build_events_app(env.db, public_origin=AUDIENCE)
    app.include_router(router)
    app.state.awid_registry_client = env.registry
    app.state.core_hooks = context().hooks
    signing, signature = env.owner.sign("hook-binding." + operation, target)
    body = json.dumps({"act": base64.b64encode(signing).decode(), "signature": signature}).encode()
    path = f"/v1/apps/hook-bindings/{target.binding_id}/{operation}"
    trace = SigningKey.generate().verify_key.encode().hex()[:32]
    # A real DB failure after the state write. No internal code is replaced.
    await env.db.execute("CREATE FUNCTION aweb.reject_hook_insert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'recording unavailable'; END $$")
    await env.db.execute("CREATE TRIGGER reject_hook_insert BEFORE INSERT ON {{tables.outbox_events}} FOR EACH ROW EXECUTE FUNCTION aweb.reject_hook_insert()")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False), base_url=AUDIENCE) as client:
        refused = await client.post(path, content=body, headers=headers(member, cert, body, path, trace, signed_trace))
        assert refused.status_code == 500
        assert await env.db.fetch_value("SELECT state FROM {{tables.app_hook_bindings}} WHERE binding_id=$1", target.binding_id) == ("pending" if operation == "activate" else "active")
        assert await env.db.fetch_value("SELECT COUNT(*) FROM {{tables.outbox_events}}") == 0
        await env.db.execute("DROP TRIGGER reject_hook_insert ON {{tables.outbox_events}}")
        committed = await client.post(path, content=body, headers=headers(member, cert, body, path, trace, signed_trace))
    assert committed.status_code == 200, committed.text
    row = await env.db.fetch_one("SELECT payload,signature FROM {{tables.outbox_events}}")
    event = verify(bytes(row["payload"]), row["signature"], team_id=TEAM).fields
    assert event["payload"]["mutation_type"] == "hook_binding." + ("activated" if operation == "activate" else "revoked")
    assert event["payload"]["owner_act_sha256"] == hashlib.sha256(signing).hexdigest()
    assert event["actor"] == {"authority_mode": "owner_act", "did_key": did_from_public_key(bytes(env.owner.key.verify_key)), "attestations": []}
    if signed_trace:
        assert event["trace"] == {"id": trace, "origin": "signed_request"}
    else:
        assert event["trace"]["origin"] == "producer" and event["trace"]["id"] != trace
    assert event["producer"]["seq"] == 1
