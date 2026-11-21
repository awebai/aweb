"""Released Go fetch verifies the real registry's current team authority."""

from __future__ import annotations

import asyncio
import base64
import json
from pathlib import Path
import subprocess
from uuid import uuid4

import pytest
from awid.team_certificate import issue_team_certificate
from test_cli_never_grants import registry_listener
from test_dashboard_privacy import TEAM, TEAM_NAME
from test_dashboard_privacy import privacy_app as privacy_app
from test_messages_http import _make_keypair

__all__ = ["privacy_app"]


@pytest.fixture(scope="session")
def current_certificate_fetch_probe(tmp_path_factory):
    root = Path(__file__).resolve().parents[2]
    source = Path(__file__).with_name("fixtures") / "current_certificate_fetch.go"
    binary = tmp_path_factory.mktemp("certificate-fetch-probe") / "fetch-certificate"
    subprocess.run(
        ["go", "build", "-o", str(binary), str(source)],
        cwd=root / "cli" / "go",
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    return binary


async def _fetch(binary, *, registry_origin, member_seed, certificate_id):
    process = await asyncio.create_subprocess_exec(
        str(binary),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    output, errors = await asyncio.wait_for(
        process.communicate(
            json.dumps(
                {
                    "registry_url": registry_origin,
                    "domain": "example.test",
                    "team": TEAM_NAME,
                    "certificate_id": certificate_id,
                    "member_seed": base64.b64encode(member_seed).decode(),
                }
            ).encode()
        ),
        15,
    )
    assert process.returncode == 0, errors.decode()
    return json.loads(output)


@pytest.mark.asyncio
async def test_go_fetch_refuses_unrevoked_certificate_after_controller_rotation(
    privacy_app,
    current_certificate_fetch_probe,
):
    # team-auth-envelope-v2.md:64-69: active status never replaces signature
    # verification under the current team key. A namespace controller can
    # change that key without revoking the previously registered certificate.
    env = privacy_app
    member_sk, _, member_did = _make_keypair()
    certificate_id = "fetch-" + uuid4().hex
    alias = "fetch-" + uuid4().hex[:12]
    _, certificate = issue_team_certificate(
        team_id=TEAM,
        team_signing_key=env.team_sk,
        member_did_key=member_did,
        alias=alias,
        identity_scope="local",
        certificate_id=certificate_id,
    )
    async with registry_listener(env) as (registry, origin):
        await registry.register_team_certificate(
            "example.test",
            TEAM_NAME,
            team_controller_signing_key=env.team_sk,
            certificate_id=certificate_id,
            member_did_key=member_did,
            member_did_aw=None,
            member_address=None,
            alias=alias,
            identity_scope="local",
            certificate=certificate,
        )
        valid = await _fetch(
            current_certificate_fetch_probe,
            registry_origin=origin,
            member_seed=member_sk,
            certificate_id=certificate_id,
        )
        assert valid == {"certificate_id": certificate_id}, valid
        _, _, replacement_did = _make_keypair()
        await registry.rotate_team_key(
            "example.test",
            TEAM_NAME,
            new_team_did_key=replacement_did,
            namespace_controller_signing_key=env.namespace_sk,
        )
        status = await registry.get_team_certificate_status_fresh(
            "example.test",
            TEAM_NAME,
            certificate_id,
        )
        assert status is not None
        assert status["team_did_key"] == replacement_did
        assert status["status"] == "active"
        refused = await _fetch(
            current_certificate_fetch_probe,
            registry_origin=origin,
            member_seed=member_sk,
            certificate_id=certificate_id,
        )
        assert refused.get("code") == "team_key_not_current", refused
        assert refused.get("error"), refused
