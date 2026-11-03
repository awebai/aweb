"""Opt-in disposable live fixture for an independently operated real wake reader.

AW_TEST_WAKE_HANDOFF names a private directory outside the repository. Nothing
is sent until its owner presents the manifest's capability to the control port.
The fixture proves delivery only; the wake owner retains actual session proof.
"""
import asyncio
import json
import os
from pathlib import Path
import secrets

import pytest

from test_actf_return_route import route_pair, _reader_home, _send  # noqa: F401


@pytest.mark.asyncio
async def test_live_wake_reader_handoff(route_pair):
    configured = os.environ.get("AW_TEST_WAKE_HANDOFF")
    if not configured:
        pytest.skip("opt-in real OATS receiver handoff")
    root = Path(configured)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    home, env = _reader_home(route_pair.target.global_actor, root / "receiver")
    capability = secrets.token_urlsafe(32)
    stopped = asyncio.Event()
    sent = {}
    async def control(reader, writer):
        try:
            command = json.loads(await asyncio.wait_for(reader.readline(), 10))
            if not secrets.compare_digest(str(command.get("capability", "")), capability):
                raise ValueError("invalid fixture capability")
            if command.get("action") == "send":
                kind, encrypted = command["kind"], command["encrypted"]
                if kind not in {"mail", "chat"} or type(encrypted) is not bool:
                    raise ValueError("unknown fixture case")
                case = f"{kind}-{'v2' if encrypted else 'plaintext'}"
                if case not in sent:
                    response, submitted = await _send(route_pair.source.local, route_pair.target.global_actor,
                                                      kind, encrypted=encrypted)
                    assert response.status_code == 200, response.text
                    sent[case] = dict(case=case, message_id=str(submitted.mid),
                                     conversation_id=str(submitted.cid), body=submitted.fields["body"])
                    (root / "sent.json").write_text(json.dumps(sent, indent=2))
                result = sent[case]
            elif command.get("action") == "stop":
                result = {"stopped": True, "sent": len(sent)}
                stopped.set()
            else:
                raise ValueError("unknown fixture action")
            writer.write((json.dumps(result)+"\n").encode())
        except Exception as exc:
            writer.write((json.dumps({"error": str(exc)})+"\n").encode())
        finally:
            await writer.drain()
            writer.close()
            await writer.wait_closed()
    async with await asyncio.start_server(control, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]
        manifest = dict(identity_home=str(home), team_id=route_pair.target.team_id,
            service_url=route_pair.target.origin, registry_url=route_pair.target.registry_client.registry_url,
            environment={key: env[key] for key in ("HOME", "XDG_CONFIG_HOME", "AW_NO_UPDATE_CHECK",
                         "AWEB_IDENTITY_HOME", "AWID_REGISTRY_URL")},
            control_host="127.0.0.1", control_port=port, capability=capability,
            lifetime_seconds=1800, cases=[f"{k}-{f}" for k in ("mail", "chat") for f in ("plaintext", "v2")])
        path = root / "manifest.json"
        path.write_text(json.dumps(manifest, indent=2))
        path.chmod(0o600)
        try:
            await asyncio.wait_for(stopped.wait(), 1800)
            assert len(sent) == 4, "wake owner did not request all four real deliveries"
        finally:
            path.unlink(missing_ok=True)
