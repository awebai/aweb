"""Pending private certificates keep a key claim distinct from registry evidence."""

import asyncio
import json
import subprocess
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from awid.dns_verify import DomainAuthority
from awid_service.deps import get_domain_verifier
from test_cli_never_grants import registry_listener
from test_dashboard_privacy import privacy_app as privacy_app
from test_messages_http import _encode_certificate, _make_certificate, _make_keypair

__all__ = ["privacy_app"]


@pytest.fixture(scope="session")
def team_key_observation_probe(tmp_path_factory):
    root = Path(__file__).resolve().parents[2]
    source = Path(__file__).with_name("fixtures") / "team_key_observation.go"
    binary = tmp_path_factory.mktemp("team-key-observation") / "observe-team-key"
    subprocess.run(
        ["go", "build", "-o", str(binary), str(source)],
        cwd=root / "cli" / "go",
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    return binary


async def observe_team_key(binary, *, origin, certificate):
    process = await asyncio.create_subprocess_exec(
        str(binary),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    output, errors = await asyncio.wait_for(
        process.communicate(
            json.dumps({"registry_url": origin, "certificate": certificate}).encode()
        ),
        15,
    )
    assert process.returncode == 0, errors.decode()
    return json.loads(output)


@pytest.mark.asyncio
async def test_private_pending_key_confirms_only_when_the_existing_registry_read_answers(
    privacy_app,
    team_key_observation_probe,
):
    # identity.md, Pending private-team key confirmation (Antares245fb075):
    # neither private403 nor unregistered404 is agreement with a supplied key.
    env = privacy_app
    namespace_key, namespace_did = env.namespace_sk, env.namespace_did
    _, _, member_did = _make_keypair()
    name = "pending-" + uuid4().hex[:12]
    team_id = name + ":example.test"
    async with registry_listener(env) as (writer, origin):

        async def authority(domain):
            assert domain == "example.test"
            return DomainAuthority(namespace_did, origin, "_awid.example.test")

        env.registry_app.dependency_overrides[get_domain_verifier] = lambda: authority
        await writer.register_team(
            domain="example.test",
            name=name,
            display_name="Pending private member",
            team_did_key=env.team_did,
            visibility="private",
            namespace_controller_signing_key=namespace_key,
        )
        certificate = _make_certificate(
            env.team_sk,
            env.team_did,
            member_did,
            team_id=team_id,
            alias="worker",
            identity_scope="local",
            certificate_id="pending-" + uuid4().hex,
        )
        header = _encode_certificate(certificate)
        async with httpx.AsyncClient(base_url=origin) as anonymous:
            metadata = await anonymous.get(f"/v1/namespaces/example.test/teams/{name}")
            status = await anonymous.get(
                f"/v1/namespaces/example.test/teams/{name}/certificates/{certificate['certificate_id']}/status"
            )
        assert metadata.status_code == 403, metadata.text
        assert status.status_code == 404, status.text
        pending = await observe_team_key(
            team_key_observation_probe, origin=origin, certificate=header
        )
        assert pending == {
            "evidence": {"did_key": env.team_did, "state": "unconfirmed"}
        }, pending

        await writer.register_team_certificate(
            "example.test",
            name,
            team_controller_signing_key=env.team_sk,
            certificate_id=certificate["certificate_id"],
            member_did_key=member_did,
            member_did_aw=None,
            member_address=None,
            alias="worker",
            identity_scope="local",
            certificate=header,
        )
        confirmed = await observe_team_key(
            team_key_observation_probe, origin=origin, certificate=header
        )
        assert confirmed == {
            "evidence": {"did_key": env.team_did, "state": "confirmed"}
        }, confirmed

        # Deliberate response/artifact substitution: a valid self-signed blob
        # reuses the registered ID. The independent registry key must win.
        substituted_key, _, substituted_did = _make_keypair()
        substituted = _make_certificate(
            substituted_key,
            substituted_did,
            member_did,
            team_id=team_id,
            alias="worker",
            identity_scope="local",
            certificate_id=certificate["certificate_id"],
        )
        substituted = _encode_certificate(substituted)
        refused = await observe_team_key(
            team_key_observation_probe, origin=origin, certificate=substituted
        )
        assert refused.get("code") == "team_key_not_current", refused
        assert "does not match the registry's" in refused["error"]
        assert "ask the team's owner" in refused["error"]

    unknown = await observe_team_key(
        team_key_observation_probe, origin=origin, certificate=header
    )
    assert unknown == {"evidence": {"did_key": env.team_did, "state": "unconfirmed"}}, (
        unknown
    )
