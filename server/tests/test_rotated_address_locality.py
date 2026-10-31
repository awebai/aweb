"""Fresh address sends remain local after real AWID/CLI key rotation.

The old membership projection deliberately retains its old key. All address,
rotation, authentication, signature and delivery decisions use real services.
"""
import base64
import json
import os
from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest

from awid.signing import canonical_json_bytes, sign_message
from aweb.internal_auth import build_internal_auth_header_value
from aweb.mcp.server import create_mcp_app
from aweb.mcp.signing import HostedMessageSigningResult, canonical_signed_payload
from test_cli_human_reply import _cli, _pem
from test_cli_never_grants import registry_listener
from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401
from identity_binding_support import register_global_identity
from test_identity_binding_http import certificate, request
from test_messages_http import _signed_identity_headers


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("adapter", ["http", "mcp"])
async def test_fresh_address_delivery_after_cli_rotation_is_local(
    privacy_app, source_cli_binary, tmp_path, monkeypatch, kind, adapter,
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

        mcp = None
        if adapter == "mcp":
            monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "1")
            monkeypatch.setenv("AWEB_INTERNAL_AUTH_SECRET", "rotation-locality-test-secret")

            async def signer(**kwargs):
                encoded = canonical_signed_payload(kwargs["payload"])
                return HostedMessageSigningResult(
                    from_did=alice.did, signing_key_id=alice.did, signed_payload=encoded,
                    signature=sign_message(alice.sk, encoded.encode()),
                )

            mcp = create_mcp_app(db_infra=env.infra, redis=env.redis, registry_client=registry,
                                 hosted_signer=signer, public_origin=env.app.state.public_origin)
            env.app.mount("/mcp", mcp)
            await mcp.startup()

        async def fresh_send(label, *, claims=None, expected_status=200):
            resolved = await registry.resolve_address_fresh("example.test", "bob")
            assert resolved.did_aw == stable
            if adapter == "mcp":
                principal = str(uuid4())
                from test_dashboard_privacy import TEAM
                headers = {
                    "Accept": "application/json, text/event-stream", "X-Team-ID": TEAM,
                    "X-User-ID": principal, "X-AWEB-Actor-ID": str(alice.id),
                    "X-AWEB-Auth": build_internal_auth_header_value(
                        secret="rotation-locality-test-secret", team_id=TEAM,
                        principal_type="u", principal_id=principal, actor_id=str(alice.id),
                    ),
                }
                arguments = {"to": address, "plaintext": True}
                arguments.update({"body": label, "subject": label} if kind == "mail" else {"message": label, "leaving": True})
                response = await env.client.post("/mcp/", headers=headers, json={
                    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": "send_mail" if kind == "mail" else "send_chat", "arguments": arguments},
                })
                assert response.status_code == 200, response.text
                result = response.json()
                assert "error" not in result, result
                result = json.loads(result["result"]["content"][0]["text"])
                assert "error" not in result, result
                mid = result["message_id"]
                cid = result["conversation_id"] if kind == "mail" else result["session_id"]
                table = "messages" if kind == "mail" else "chat_messages"
                assert await env.db.fetch_val("SELECT count(*) FROM {{tables." + table + "}} WHERE message_id=$1", UUID(mid)) == 1
                return cid
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
                signed["sender_leaving"] = True
                path = "/v1/chat/sessions"
            signed.update(claims or {})
            encoded = canonical_json_bytes(signed).decode()
            payload.update(message_id=mid, timestamp=timestamp, from_did=alice.did,
                           signed_payload=encoded, signature=sign_message(alice.sk, encoded.encode()))
            raw = json.dumps(payload).encode()
            tables = ("messages", "chat_messages", "conversations", "chat_sessions")
            before_counts = {name: await env.db.fetch_val("SELECT count(*) FROM {{tables." + name + "}}") for name in tables}
            response = await env.client.post(path, content=raw, headers={
                "Content-Type": "application/json", **_signed_identity_headers(alice.sk, alice.did, "", raw),
            })
            assert response.status_code == expected_status, response.text
            if expected_status != 200:
                after_counts = {name: await env.db.fetch_val("SELECT count(*) FROM {{tables." + name + "}}") for name in tables}
                if expected_status == 422:
                    assert after_counts == before_counts
                else:
                    # Remote chat may retain its outgoing session projection;
                    # it must not store a locally delivered message.
                    assert after_counts["messages"] == before_counts["messages"]
                    assert after_counts["chat_messages"] == before_counts["chat_messages"]
                return None
            table, column = ("messages", "conversation_id") if kind == "mail" else ("chat_messages", "session_id")
            stored = await env.db.fetch_one(
                "SELECT * FROM {{tables." + table + "}} WHERE message_id=$1", UUID(mid),
            )
            assert stored is not None
            assert str(stored[column]) == cid
            return cid

        try:
            first = await fresh_send("Before rotation")
            old_key = bob.did
            rotated = await _cli(source_cli_binary, tmp_path, child, "id", "rotate-key", "--json")
            new_key = rotated["new_did"]
            assert new_key != old_key
            assert (await registry.resolve_key_fresh(stable)).current_did_key == new_key
            interim = await fresh_send("After rotation before new-key auth")
            if adapter == "mcp" and kind == "chat":
                assert interim == first  # Agent chat keeps its existing session reuse.
            else:
                assert interim != first
            # Mirror the real walk: the new key authenticates before the later
            # delegate sends. This invalidates superseded projection evidence.
            bob.sk = base64.b64decode("".join((home / "signing.key").read_text().splitlines()[1:-1]))
            bob.did = new_key
            refreshed = await request(env, bob, "GET", "/v1/messages/inbox", did_aw=stable)
            assert refreshed.status_code == 200, refreshed.text
            before = await env.db.fetch_one("SELECT * FROM {{tables.agents}} WHERE agent_id=$1", bob.id)
            assert before["did_key"] == old_key
            assert before["did_aw_verified_key"] is None
            second = await fresh_send("After rotation")
            if adapter == "mcp" and kind == "chat":
                assert second == first
            else:
                assert second != first
            assert before == await env.db.fetch_one("SELECT * FROM {{tables.agents}} WHERE agent_id=$1", bob.id)
            if adapter == "http":
                # Residence never substitutes for current key/address binding.
                for claims in ({"to_did": old_key}, {"to_stable_id": "did:aw:other"}, {"to": "example.test/other"}):
                    await fresh_send("Invalid binding", claims=claims, expected_status=422)
                assert before == await env.db.fetch_one("SELECT * FROM {{tables.agents}} WHERE agent_id=$1", bob.id)
                # A deleted row no longer establishes residence. The valid
                # address route must then take federation, with no local message.
                await env.db.execute("UPDATE {{tables.agents}} SET deleted_at=clock_timestamp() WHERE agent_id=$1", bob.id)
                await fresh_send("No local residence", expected_status=502)
        finally:
            if mcp is not None:
                await mcp.shutdown()
