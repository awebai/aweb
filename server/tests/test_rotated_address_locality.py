"""Fresh address sends remain local after real AWID/CLI key rotation.

The old membership projection deliberately retains its old key. All address,
rotation, authentication, signature and delivery decisions use real services.
"""
import json
import os
from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest

from awid.signing import canonical_json_bytes, sign_message
from test_cli_human_reply import _cli, _pem
from test_cli_never_grants import registry_listener
from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401
from identity_binding_support import register_global_identity
from test_identity_binding_http import certificate, request
from test_messages_http import _signed_identity_headers


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
async def test_fresh_address_delivery_after_cli_rotation_is_local(
    privacy_app, source_cli_binary, tmp_path, kind,
):
    env = privacy_app
    alice, bob = env.actors["alice"], env.actors["bob"]
    address = "example.test/bob"
    async with registry_listener(env) as (registry, origin):
        stable = await register_global_identity(env, bob, address)
        # A published namespace route must not turn this resident into a
        # federated recipient when its old key projection is invalidated.
        await env.registry_db.execute(
            "UPDATE {{tables.dns_namespaces}} SET default_delivery_origin='http://127.0.0.1:1' WHERE domain='example.test'",
        )
        bob.certificate = certificate(env, bob, stable, address)
        admitted = await request(env, bob, "POST", "/v1/connect", {})
        assert admitted.status_code == 200, admitted.text
        home = tmp_path / ".aw"
        home.mkdir(mode=0o700)
        _pem(home / "signing.key", "ED25519 PRIVATE KEY", bob.sk)
        (home / "identity.yaml").write_text(json.dumps({
            "did": bob.did, "stable_id": stable, "address": address,
            "registry_url": origin, "custody": "self", "identity_scope": "global",
        }))
        child = {key: value for key, value in os.environ.items() if not key.startswith(("AW", "XDG_"))}
        child.update(HOME=str(tmp_path), PWD=str(tmp_path), XDG_CONFIG_HOME=str(tmp_path / ".config"),
                     AW_NO_UPDATE_CHECK="1", AWID_REGISTRY_URL=origin)

        async def fresh_send(label):
            resolved = await registry.resolve_address_fresh("example.test", "bob")
            assert resolved.did_aw == stable
            mid, cid = str(uuid4()), str(uuid4())
            timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
            signed = {"type": kind, "from_did": alice.did, "from": "example.test/alice", "to": address,
                      "to_did": resolved.current_did_key, "to_stable_id": stable,
                      "message_id": mid, "conversation_id": cid, "timestamp": timestamp,
                      "body": label}
            if kind == "mail":
                signed.update(subject=label, priority="normal")
                payload = {"to_address": address, "new_conversation": True,
                           "subject": label, "body": label, "conversation_id": cid}
                path = "/v1/messages"
            else:
                payload = {"to_addresses": [address], "message": label, "leaving": True, "session_id": cid}
                signed.update(session_id=cid, sender_leaving=True)
                path = "/v1/chat/sessions"
            encoded = canonical_json_bytes(signed).decode()
            payload.update(message_id=mid, timestamp=timestamp, from_did=alice.did,
                           signed_payload=encoded, signature=sign_message(alice.sk, encoded.encode()))
            raw = json.dumps(payload).encode()
            response = await env.client.post(path, content=raw, headers={
                "Content-Type": "application/json", **_signed_identity_headers(alice.sk, alice.did, "", raw),
            })
            assert response.status_code == 200, response.text
            table, column = ("messages", "conversation_id") if kind == "mail" else ("chat_messages", "session_id")
            stored = await env.db.fetch_one(
                "SELECT * FROM {{tables." + table + "}} WHERE message_id=$1", UUID(mid),
            )
            assert stored is not None
            assert str(stored[column]) == cid
            return cid

        first = await fresh_send("Before rotation")
        old_key = bob.did
        rotated = await _cli(source_cli_binary, tmp_path, child, "id", "rotate-key", "--json")
        new_key = rotated["new_did"]
        assert new_key != old_key
        assert (await registry.resolve_key_fresh(stable)).current_did_key == new_key
        # Mirror the real walk: the new key authenticates before the later
        # delegate sends. This invalidates superseded projection evidence.
        import base64
        bob.sk = base64.b64decode("".join((home / "signing.key").read_text().splitlines()[1:-1]))
        bob.did = new_key
        refreshed = await request(env, bob, "GET", "/v1/messages/inbox", did_aw=stable)
        assert refreshed.status_code == 200, refreshed.text
        before = await env.db.fetch_one("SELECT * FROM {{tables.agents}} WHERE agent_id=$1", bob.id)
        assert before["did_key"] == old_key
        assert before["did_aw_verified_key"] is None
        second = await fresh_send("After rotation")
        assert first != second
        assert before == await env.db.fetch_one("SELECT * FROM {{tables.agents}} WHERE agent_id=$1", bob.id)
