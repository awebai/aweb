"""Current Go SDK through real OSS HTTP/AWID/PostgreSQL/Redis; no auth mocks.

Run from server with PYTHONPATH=tests and its locked environment.
"""
import asyncio
import base64
import json
import os
from pathlib import Path
import subprocess

import pytest

from conftest import shared_test_pool  # noqa: F401
from awid.did import stable_id_from_did_key
from awid.signing import canonical_json_bytes, sign_message
from test_dashboard_privacy import TEAM, _request, privacy_app  # noqa: F401

pytest_plugins = ("pgdbm.fixtures.conftest",)
ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session")
def request_auth_driver(tmp_path_factory):
    binary = tmp_path_factory.mktemp("v2-driver") / ("driver.exe" if os.name == "nt" else "driver")
    build = subprocess.run(
        ["go", "build", "-o", str(binary), str(Path(__file__).with_name("request_auth_v2_driver.go"))],
        cwd=ROOT / "cli/go", text=True, capture_output=True, timeout=120,
    )
    assert build.returncode == 0, build.stdout + build.stderr
    return binary


@pytest.mark.asyncio
@pytest.mark.parametrize("family", ["certificate", "identity-local", "identity-global"])
async def test_sdk_json_and_streaming_v2_against_real_stack(privacy_app, request_auth_driver, tmp_path, family):
    env = privacy_app
    env.app.state.public_origin = str(env.client.base_url).rstrip("/")
    actor = env.actors["alice"]
    stable_id = ""
    if family == "identity-global":
        await env.app.state.awid_registry_client.register_did(actor.did, actor.sk)
        stable_id = stable_id_from_did_key(actor.did)
    session = await _request(env, "alice", "POST", "/v1/chat/sessions", {"to_aliases": ["bob"], "message": "real session"})
    assert session.status_code == 200, session.text
    certificate = ""
    if family == "certificate":
        cert = json.loads(base64.b64decode(actor.certificate))
        for field in ("member_did_aw", "member_address", "signature"):
            cert.pop(field, None)
        cert["signature"] = sign_message(env.team_sk, canonical_json_bytes(cert))
        certificate = base64.b64encode(json.dumps(cert).encode()).decode()
    authority = tmp_path / "authority.json"
    authority.write_text(json.dumps(dict(
        URL=str(env.client.base_url).rstrip("/"), DID=actor.did, StableID=stable_id,
        Key=base64.b64encode(actor.sk).decode(), Certificate=certificate,
        SessionID=session.json()["session_id"], Recipient=env.actors["bob"].did,
    )))
    authority.chmod(0o600)
    try:
        process = await asyncio.create_subprocess_exec(
            str(request_auth_driver), str(authority), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), 30)
        assert process.returncode == 0, stderr.decode()
        assert json.loads(stdout) == {"v2_requests": 5, "retargeted_status": 401}
    finally:
        authority.unlink(missing_ok=True)
