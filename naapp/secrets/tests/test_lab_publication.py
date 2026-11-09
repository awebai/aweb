"""Real CLI certificate/key checks and real AWID routes, not mocked authority."""

import base64
import json
import os
import socket
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from aweb_naapp_testing import Member
from awid.signing import canonical_json_bytes, sign_message
from lab_environment import LabConfigurationError
from lab_publication import publish_lab_runtime

from tests.test_aw_surface import aw_binary as aw_binary
from tests.test_lab_environment import PREFIX, configured


def write_home(home, member, registry, server):
    """Throwaway generated key material stays in files, never a test literal."""
    __tracebackhide__ = True
    team, alias = member.team_id, member.alias
    cert = member.certificate()
    cert.pop("signature")
    cert.pop("lifetime")
    cert["identity_scope"] = "global" if cert.get("member_did_aw") else "local"
    cert["signature"] = sign_message(bytes(member.team_key), canonical_json_bytes(cert))
    cert_path = "team-certs/" + team.replace(":", "__") + ".pem"
    (home / "team-certs").mkdir(exist_ok=True, mode=0o700)
    files = {
        cert_path: json.dumps(cert),
        "teams.yaml": json.dumps(
            {
                "active_team": team,
                "memberships": [
                    {
                        "team_id": team,
                        "alias": alias,
                        "cert_path": cert_path,
                        "registry_url": registry,
                        "aweb_url": server,
                    }
                ],
            }
        ),
        "workspace.yaml": json.dumps(
            {
                "aweb_url": server,
                "memberships": [
                    {
                        "team_id": team,
                        "alias": alias,
                        "cert_path": cert_path,
                        "workspace_id": "00000000-0000-4000-8000-000000000001",
                    }
                ],
            }
        ),
    }
    if cert.get("member_did_aw"):
        files["identity.yaml"] = json.dumps(
            {
                "schema_version": 2,
                "identity_scope": "global",
                "custody": "self",
                "did": member.did_key,
                "stable_id": cert["member_did_aw"],
                "registry_url": registry,
                "created_at": cert["issued_at"],
            }
        )
    for name, content in files.items():
        path = home / name
        path.write_text(content)
        path.chmod(0o600)
    key = home / "signing.key"
    key.write_text(
        "-----BEGIN ED25519 PRIVATE KEY-----\n"
        + base64.b64encode(bytes(member.member_key)).decode()
        + "\n-----END ED25519 PRIVATE KEY-----\n"
    )
    key.chmod(0o600)
    return cert


@pytest.fixture
async def lab(tmp_path, registry, aw_binary):
    inputs = configured(tmp_path)
    inputs[PREFIX + "AW_BINARY"] = str(aw_binary)
    inputs[PREFIX + "AWID_REGISTRY_URL"] = "https://registry.example"
    team = inputs[PREFIX + "TEAM_ID"]
    first = Member(team, alias="human", certificate_id="lab-human")
    await registry.add_team(team, first.team_did_key)
    await registry.publish_team_server(
        team, first.team_key, server_url=inputs[PREFIX + "COORDINATION_ORIGIN"]
    )
    members = {}
    for actor in ("HUMAN", "AGENT_A", "AGENT_B"):
        member = Member(
            team,
            team_key=first.team_key,
            alias=actor.lower(),
            certificate_id="lab-" + actor.lower(),
        )
        home = Path(inputs[PREFIX + actor + "_IDENTITY_HOME"])
        cert = write_home(
            home,
            member,
            inputs[PREFIX + "AWID_REGISTRY_URL"],
            inputs[PREFIX + "COORDINATION_ORIGIN"],
        )
        await registry.add_certificate(cert)
        members[actor] = member
    return inputs, members, registry


async def test_private_publication_records_actual_certified_principals_and_coverage(lab, tmp_path):
    inputs, members, registry = lab
    directory = tmp_path / "published"
    async with publish_lab_runtime(
        inputs,
        private_dns="excluded",
        directory=directory,
        registry_transport=registry.transport,
    ) as path:
        body = json.loads(path.read_text())
        assert body["profile"] == "byot-native-kms-lab/1"
        assert body["inputs"] == inputs
        assert body["coverage"] == {
            "private_address_refusal": "excluded",
            "full_release_gate": False,
        }
        assert {key: value["principal_did"] for key, value in body["actors"].items()} == {
            actor: member.did_key for actor, member in members.items()
        }
        assert body["runner_uid"] != os.geteuid()
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
        assert body["actors"]["AGENT_A"] != body["actors"]["AGENT_B"]
        assert not any("MCP" in key or "ONEPASSWORD" in key for key in body["inputs"])
    assert not directory.exists()
    assert await registry.db.fetch_value("SELECT count(*) FROM {{tables.team_certificates}}") == 3


@pytest.mark.parametrize(
    "problem",
    [
        "revoked",
        "team-key",
        "wrong-server",
        "wrong-registry",
        "same-principal",
        "signing-key",
        "missing-home",
    ],
)
async def test_mismatched_or_unavailable_authority_never_publishes(lab, tmp_path, problem):
    inputs, members, registry = lab
    member = members["AGENT_B"]
    home = Path(inputs[PREFIX + "AGENT_B_IDENTITY_HOME"])
    if problem == "revoked":
        await registry.revoke(member.certificate_id)
    elif problem == "team-key":
        await registry.rotate_team_key(member.team_id, Member(member.team_id).team_did_key)
    elif problem == "wrong-server":
        await registry.publish_team_server(
            member.team_id,
            member.team_key,
            server_url="https://other.example.test",
            issued_at=datetime.now(UTC) + timedelta(seconds=1),
        )
    elif problem == "wrong-registry":
        state = json.loads((home / "teams.yaml").read_text())
        state["memberships"][0]["registry_url"] = "https://other.example.test"
        (home / "teams.yaml").write_text(json.dumps(state))
    elif problem == "same-principal":
        write_home(
            home,
            members["AGENT_A"],
            inputs[PREFIX + "AWID_REGISTRY_URL"],
            inputs[PREFIX + "COORDINATION_ORIGIN"],
        )
    elif problem == "signing-key":
        (home / "signing.key").write_bytes(b"not a signing key")
    else:
        inputs[PREFIX + "AGENT_B_IDENTITY_HOME"] = str(tmp_path / "missing")
    directory = tmp_path / "published"
    with pytest.raises(LabConfigurationError) as caught:
        async with publish_lab_runtime(
            inputs,
            private_dns="excluded",
            directory=directory,
            registry_transport=registry.transport,
        ):
            pytest.fail("unverified actors must not be published")
    assert str(tmp_path) not in str(caught.value)
    assert not directory.exists()


async def test_runtime_is_removed_on_caller_failure_and_cannot_be_adopted(lab, tmp_path):
    inputs, _, registry = lab
    directory = tmp_path / "published"
    with pytest.raises(LookupError):
        async with publish_lab_runtime(
            inputs,
            private_dns="excluded",
            directory=directory,
            registry_transport=registry.transport,
        ):
            raise LookupError("caller_failed")
    assert not directory.exists()
    directory.mkdir()
    prior = directory / "runtime.json"
    prior.write_text("owned elsewhere")
    with pytest.raises(LabConfigurationError):
        async with publish_lab_runtime(
            inputs,
            private_dns="excluded",
            directory=directory,
            registry_transport=registry.transport,
        ):
            pytest.fail("must not adopt an existing publication")
    assert prior.read_text() == "owned elsewhere"


@pytest.mark.parametrize("problem", [None, "rotated-key", "metadata-registry"])
async def test_global_principals_use_the_registry_current_key_and_explicit_authority(
    lab, tmp_path, problem
):
    inputs, members, registry = lab
    member = members["AGENT_A"]
    stable = await registry.register_did(member.member_key)
    member.extra_cert_fields["member_did_aw"] = stable
    home = Path(inputs[PREFIX + "AGENT_A_IDENTITY_HOME"])
    write_home(
        home, member, inputs[PREFIX + "AWID_REGISTRY_URL"], inputs[PREFIX + "COORDINATION_ORIGIN"]
    )
    if problem == "rotated-key":
        await registry.rotate_did(stable, member.member_key, Member(member.team_id).member_key)
    elif problem == "metadata-registry":
        identity = json.loads((home / "identity.yaml").read_text())
        identity["registry_url"] = "https://other.example.test"
        (home / "identity.yaml").write_text(json.dumps(identity))
    directory = tmp_path / "global-runtime"
    if problem:
        with pytest.raises(LabConfigurationError):
            async with publish_lab_runtime(
                inputs,
                private_dns="excluded",
                directory=directory,
                registry_transport=registry.transport,
            ):
                pytest.fail("uncurrent global principal must not be published")
        assert not directory.exists()
    else:
        async with publish_lab_runtime(
            inputs,
            private_dns="excluded",
            directory=directory,
            registry_transport=registry.transport,
        ) as path:
            assert json.loads(path.read_text())["actors"]["AGENT_A"]["principal_did"] == stable


async def test_included_dns_scenario_is_recorded_as_selected_not_as_passed(lab, tmp_path):
    inputs, _, registry = lab
    inputs[PREFIX + "PRIVATE_DNS_NAME"] = "private.lab.example.test"
    async with publish_lab_runtime(
        inputs,
        private_dns="included",
        directory=tmp_path / "dns-runtime",
        registry_transport=registry.transport,
    ) as path:
        body = json.loads(path.read_text())
        assert body["coverage"]["private_address_refusal"] == "included"
        assert len(body["inputs"]) == 19
        assert body["coverage"]["full_release_gate"] is False


async def test_unreachable_selected_registry_refuses_without_public_fallback(lab, tmp_path):
    inputs, members, _ = lab
    # A kernel-bound socket with no listener gives a real connection refusal.
    # No mock responder or fabricated registry status is involved.
    with socket.socket() as unavailable:
        unavailable.bind(("127.0.0.1", 0))
        origin = f"https://127.0.0.1:{unavailable.getsockname()[1]}"
        inputs[PREFIX + "AWID_REGISTRY_URL"] = origin
        for actor, member in members.items():
            write_home(
                Path(inputs[PREFIX + actor + "_IDENTITY_HOME"]),
                member,
                origin,
                inputs[PREFIX + "COORDINATION_ORIGIN"],
            )
        directory = tmp_path / "unavailable-runtime"
        with pytest.raises(LabConfigurationError):
            async with publish_lab_runtime(inputs, private_dns="excluded", directory=directory):
                pytest.fail("unavailable authority must not produce a publication")
        assert not directory.exists()
