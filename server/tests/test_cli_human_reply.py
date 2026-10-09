"""Real HTTP/DB delivery from a synthetic custodial human through the aw CLI.

Keys represent a disposable host custodian, not a Cloud authentication fixture.
No routing, identity discovery, delivery, or cryptography is mocked.
"""
from __future__ import annotations

import asyncio
import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from uuid import uuid4

import pytest

from awid.e2ee_keys import build_encryption_key_assertion
from aweb.e2ee_messages import decrypt_e2ee_message, encrypt_e2ee_mail, generate_x25519_keypair
from test_dashboard_privacy import TEAM, _request, privacy_app  # noqa: F401


def _pem(path, kind, raw):
    path.write_text(f"-----BEGIN {kind}-----\n{base64.b64encode(raw).decode()}\n-----END {kind}-----\n")
    path.chmod(0o600)


@pytest.mark.asyncio
async def test_custodial_human_receives_encrypted_cli_reply(privacy_app, tmp_path):
    env = privacy_app
    now = datetime.now(timezone.utc)
    identities = {}
    for name, custody in (("alice", "hosted_custodial"), ("bob", "self")):
        actor = env.actors[name]
        private, public = generate_x25519_keypair()
        assertion = build_encryption_key_assertion(
            signing_key=actor.sk, identity_did=actor.did, identity_stable_id="",
            encryption_public_key=public, custody=custody, now=now,
        )
        identities[name] = dict(address="", did=actor.did, stable_id="", team_id=TEAM,
                                signing_key=actor.sk, private_key=private, encryption_key=assertion)
    await env.db.execute("UPDATE {{tables.agents}} SET agent_type = 'human' WHERE agent_id = $1", env.actors["alice"].id)
    human, agent = identities["alice"], identities["bob"]
    message_id, conversation_id = str(uuid4()), str(uuid4())
    source = encrypt_e2ee_mail(sender=human, recipients=[agent], subject="Human question",
                              body="Human private text", message_id=message_id,
                              conversation_id=conversation_id, created_at=now)
    sent = await _request(env, "alice", "POST", "/v1/messages", {
        "to_did": agent["did"], "conversation_id": conversation_id,
        "content_mode": "encrypted_v2", "message_version": 2, "encrypted_envelope": source,
    })
    assert sent.status_code == 200, sent.text
    assert source["sender_encryption_key"]["custody"] == "hosted_custodial"

    identity_home = tmp_path / ".aw"
    identity_home.mkdir(mode=0o700)
    (identity_home / "identity.yaml").write_text(json.dumps({
        "did": agent["did"], "custody": "self", "identity_scope": "local",
        "created_at": now.isoformat(),
    }))
    _pem(identity_home / "signing.key", "ED25519 PRIVATE KEY", agent["signing_key"])
    _pem(identity_home / "encryption.key", "X25519 PRIVATE KEY", agent["private_key"])
    assertion = agent["encryption_key"]
    (identity_home / "assertion.json").write_text(json.dumps(assertion))
    (identity_home / "encryption.yaml").write_text(json.dumps({
        "active_key_id": assertion["encryption_key_id"], "keys": [{
            "key_id": assertion["encryption_key_id"], "public_key": assertion["public_key"],
            "private_key_path": str(identity_home / "encryption.key"),
            "assertion_path": str(identity_home / "assertion.json"),
            **{key: assertion[key] for key in ("created_at", "not_before", "expires_at")},
            "published_at": now.isoformat(),
        }],
    }))
    root = Path(__file__).resolve().parents[2]
    binary = tmp_path / "aw"
    build = await asyncio.create_subprocess_exec("go", "build", "-o", str(binary), "./cmd/aw",
                                                cwd=root / "cli/go", stdout=asyncio.subprocess.PIPE,
                                                stderr=asyncio.subprocess.STDOUT)
    output, _ = await build.communicate()
    assert build.returncode == 0, output.decode()
    child_env = {k: v for k, v in os.environ.items() if not k.startswith(("AWEB_", "AWID_"))}
    child_env.update(AWEB_IDENTITY_HOME=str(identity_home), AWEB_URL=str(env.client.base_url),
                     HOME=str(tmp_path), AWID_REGISTRY_URL=str(env.client.base_url))
    body_file = tmp_path / "reply.txt"
    body_file.write_text("Agent private reply")
    reply = await asyncio.create_subprocess_exec(str(binary), "mail", "reply", message_id,
                                                "--body-file", str(body_file), "--json", cwd=tmp_path,
                                                env=child_env, stdout=asyncio.subprocess.PIPE,
                                                stderr=asyncio.subprocess.STDOUT)
    output, _ = await asyncio.wait_for(reply.communicate(), 30)
    assert reply.returncode == 0, output.decode()
    response = await _request(env, "alice", "GET", f"/v1/messages/conversations/{conversation_id}")
    assert response.status_code == 200, response.text
    messages = response.json()["messages"]
    assert len(messages) == 2
    delivered = next(m for m in messages if m["message_id"] != message_id)
    assert delivered["content_mode"] == "encrypted_v2"
    assert delivered["conversation_id"] == conversation_id
    assert "Agent private reply" not in json.dumps(delivered)
    plain = decrypt_e2ee_message(delivered["encrypted_envelope"], {
        **human, "encryption_key_id": human["encryption_key"]["encryption_key_id"],
    })
    assert plain["body"] == "Agent private reply"
