"""Real CLI certificate/key checks and real AWID routes, not mocked authority."""

import base64
import json
import os
import shutil
import socket
import stat
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import dns.asyncresolver
import pytest
import yaml
from aweb_naapp_testing import Member
from aweb_naapp_testing.network import DnsServer
from awid.dns_verify import awid_txt_value
from awid.id_certificates import id_certificate_id, sign_id_certificate
from awid.registry import RegistryClient
from awid.signing import canonical_json_bytes, sign_message
from lab_environment import LabConfigurationError
from lab_publication import publish_lab_runtime

from tests.test_aw_surface import aw_binary as aw_binary
from tests.test_lab_environment import PREFIX, configured, local_custody


def write_home(home, member, registry, server, *, file_key=True):
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
    if not file_key:
        files.pop("workspace.yaml")
    if cert.get("member_did_aw") and file_key:
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
    if file_key:
        key = home / "signing.key"
        key.write_text(
            "-----BEGIN ED25519 PRIVATE KEY-----\n"
            + base64.b64encode(bytes(member.member_key)).decode()
            + "\n-----END ED25519 PRIVATE KEY-----\n"
        )
        key.chmod(0o600)
    return cert


@pytest.fixture(scope="module")
def human_fixture_binary(tmp_path_factory):
    root = Path(__file__).resolve().parents[3]
    binary = tmp_path_factory.mktemp("lab-human-fixture") / "human-fixture"
    subprocess.run(
        [
            "go",
            "build",
            "-o",
            str(binary),
            str(Path(__file__).parent / "testdata/lab_human_fixture.go"),
        ],
        cwd=root / "cli/go",
        env={**os.environ, "GOMAXPROCS": "2"},
        check=True,
        capture_output=True,
        timeout=120,
    )
    return binary


@pytest.fixture
async def lab_dns():
    server = DnsServer({})
    await server.start()
    try:
        yield server
    finally:
        server.close()


@pytest.fixture
async def lab(tmp_path, registry, aw_binary, human_fixture_binary, monkeypatch, request, lab_dns):
    inputs = configured(tmp_path)
    inputs[PREFIX + "AW_BINARY"] = str(aw_binary)
    inputs[PREFIX + "AWID_REGISTRY_URL"] = "https://registry.example"
    registry.app.state.awid_public_origins = (inputs[PREFIX + "AWID_REGISTRY_URL"],)
    team = inputs[PREFIX + "TEAM_ID"]
    first = Member(team, alias="team-controller", certificate_id="lab-controller")
    await registry.add_team(team, first.team_did_key)
    await registry.publish_team_server(
        team, first.team_key, server_url=inputs[PREFIX + "COORDINATION_ORIGIN"]
    )
    controller = Member(team)
    domain = "example.test"
    lab_dns.records[("_awid." + domain, "TXT")] = [
        '"' + awid_txt_value(controller.did_key, inputs[PREFIX + "AWID_REGISTRY_URL"]) + '"'
    ]
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = ["127.0.0.1"]
    resolver.port = lab_dns.port
    previous = dns.asyncresolver.default_resolver
    dns.asyncresolver.default_resolver = resolver
    monkeypatch.setenv("HOME", str(tmp_path))
    client = RegistryClient(
        registry_url=inputs[PREFIX + "AWID_REGISTRY_URL"], transport=registry.transport
    )
    try:
        await client.register_namespace(domain, controller.did_key, bytes(controller.member_key))
        members = {}
        for actor in ("HUMAN", "AGENT_A", "AGENT_B"):
            member = Member(
                team,
                team_key=first.team_key,
                alias=actor.lower(),
                certificate_id="lab-" + actor.lower(),
            )
            if actor == "HUMAN":
                stable = await registry.register_did(member.member_key)
                member.extra_cert_fields["member_did_aw"] = stable
                signed = await sign_id_certificate(
                    {
                        "v": 1,
                        "type": "aweb.id-certificate",
                        "id": stable,
                        "domain": domain,
                        "parent": {"kind": "namespace", "id": domain},
                        "kind": getattr(request, "param", "human"),
                        "issuer_key": controller.did_key,
                        "issued_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    },
                    signer=lambda body: (
                        controller.did_key,
                        controller.member_key.sign(body).signature,
                    ),
                )
                bundle = {"v": 1, "type": "aweb.id-chain", "certificates": [signed]}
                await client.register_id_certificate(
                    bundle,
                    signer=lambda body, selected=member: (
                        selected.did_key,
                        selected.member_key.sign(body).signature,
                    ),
                    expected_head=None,
                    invitation_id=None,
                )
                encrypted_store = tmp_path / "human-keychain.encrypted"
                subprocess.run(
                    [
                        str(human_fixture_binary),
                        "--domain",
                        domain,
                        "--registry",
                        inputs[PREFIX + "AWID_REGISTRY_URL"],
                        "--certificate",
                        id_certificate_id(signed["certificate"]),
                        "--keychain-file",
                        str(encrypted_store),
                    ],
                    input=bytes(member.member_key),
                    capture_output=True,
                    check=True,
                    timeout=10,
                )
                home = tmp_path / ".awid" / "humans" / domain / stable[7:]
                inputs[PREFIX + actor + "_IDENTITY_HOME"] = str(home)
                (home / "id-chain.json").write_text(json.dumps(bundle))
                (home / "id-chain.json").chmod(0o600)
                assert not (home / "signing.key").exists()
                assert encrypted_store.read_bytes().startswith(
                    b"-----BEGIN ENCRYPTED PRIVATE KEY-----"
                )
            else:
                home = Path(inputs[PREFIX + actor + "_IDENTITY_HOME"])
            cert = write_home(
                home,
                member,
                inputs[PREFIX + "AWID_REGISTRY_URL"],
                inputs[PREFIX + "COORDINATION_ORIGIN"],
                file_key=actor != "HUMAN",
            )
            await registry.add_certificate(cert)
            members[actor] = member
        yield inputs, members, registry
    finally:
        await client.aclose()
        dns.asyncresolver.default_resolver = previous


@pytest.mark.parametrize("custody_mode", ["kms", "local_key_file"])
async def test_private_publication_records_actual_certified_principals_and_coverage(
    lab, tmp_path, custody_mode
):
    inputs, members, registry = lab
    if custody_mode == "local_key_file":
        inputs = local_custody(inputs, tmp_path)
    directory = tmp_path / "published"
    async with publish_lab_runtime(
        inputs,
        private_dns="excluded",
        directory=directory,
        registry_transport=registry.transport,
    ) as path:
        body = json.loads(path.read_text())
        assert body["profile"] == "byot-native-lab/1"
        assert body["custody_mode"] == custody_mode
        assert body["inputs"] == inputs
        assert body["coverage"] == {
            "private_address_refusal": "excluded",
            "full_release_gate": False,
            "custody": {
                mode: "not_tested" if mode == custody_mode else "excluded"
                for mode in ("kms", "local_key_file")
            },
        }
        assert {key: value["principal_did"] for key, value in body["actors"].items()} == {
            actor: member.extra_cert_fields.get("member_did_aw", member.did_key)
            for actor, member in members.items()
        }
        assert body["actors"]["HUMAN"]["custody"] == "not_tested"
        assert body["actors"]["HUMAN"]["signing_readiness"] == "not_tested"
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
        assert len(body["inputs"]) == 20
        assert body["coverage"]["full_release_gate"] is False


@pytest.mark.parametrize(
    "problem", ["copied-record", "missing-chain", "prepared", "agent-home", "revoked"]
)
async def test_protected_human_public_prerequisites_refuse_invalid_records(lab, tmp_path, problem):
    inputs, members, registry = lab
    home = Path(inputs[PREFIX + "HUMAN_IDENTITY_HOME"])
    if problem == "copied-record":
        copied = tmp_path / "copied-human"
        shutil.copytree(home, copied)
        inputs[PREFIX + "HUMAN_IDENTITY_HOME"] = str(copied)
    elif problem == "missing-chain":
        (home / "id-chain.json").unlink()
    elif problem == "prepared":
        record = yaml.safe_load((home / "identity.yaml").read_text())
        record["state"] = "prepared"
        (home / "identity.yaml").write_text(json.dumps(record))
    elif problem == "agent-home":
        inputs[PREFIX + "HUMAN_IDENTITY_HOME"] = inputs[PREFIX + "AGENT_A_IDENTITY_HOME"]
    else:
        await registry.revoke(members["HUMAN"].certificate_id)
    assert not (home / "signing.key").exists()
    directory = tmp_path / "invalid-human-runtime"
    with pytest.raises(LabConfigurationError):
        async with publish_lab_runtime(
            inputs,
            private_dns="excluded",
            directory=directory,
            registry_transport=registry.transport,
        ):
            pytest.fail("invalid public human facts must refuse publication")
    assert not directory.exists()


@pytest.mark.parametrize("lab", ["agent"], indirect=True)
async def test_registered_agent_kind_cannot_substitute_for_protected_human(lab, tmp_path):
    inputs, _, registry = lab
    with pytest.raises(LabConfigurationError) as caught:
        async with publish_lab_runtime(
            inputs,
            private_dns="excluded",
            directory=tmp_path / "agent-kind",
            registry_transport=registry.transport,
        ):
            pytest.fail("a valid agent chain is not a human chain")
    assert caught.value.code == "lab_human_identity_invalid"


async def test_human_dns_authority_unavailable_is_explicit(lab, tmp_path, lab_dns):
    inputs, _, registry = lab
    lab_dns.records.clear()
    with pytest.raises(LabConfigurationError) as caught:
        async with publish_lab_runtime(
            inputs,
            private_dns="excluded",
            directory=tmp_path / "no-authority",
            registry_transport=registry.transport,
        ):
            pytest.fail("missing namespace authority must refuse publication")
    assert caught.value.code == "lab_human_identity_unavailable"


async def test_unreachable_selected_registry_refuses_without_public_fallback(
    lab, tmp_path, lab_dns
):
    inputs, members, _ = lab
    # A kernel-bound socket with no listener gives a real connection refusal.
    # No mock responder or fabricated registry status is involved.
    with socket.socket() as unavailable:
        unavailable.bind(("127.0.0.1", 0))
        origin = f"https://127.0.0.1:{unavailable.getsockname()[1]}"
        txt_key = ("_awid.example.test", "TXT")
        lab_dns.records[txt_key] = [
            lab_dns.records[txt_key][0].replace(inputs[PREFIX + "AWID_REGISTRY_URL"], origin)
        ]
        inputs[PREFIX + "AWID_REGISTRY_URL"] = origin
        for actor in members:
            home = Path(inputs[PREFIX + actor + "_IDENTITY_HOME"])
            for filename in ("identity.yaml", "teams.yaml"):
                state = (
                    yaml.safe_load((home / filename).read_text())
                    if (home / filename).exists()
                    else None
                )
                if state is None:
                    continue
                if filename == "identity.yaml":
                    state["registry_url"] = origin
                else:
                    state["memberships"][0]["registry_url"] = origin
                (home / filename).write_text(json.dumps(state))
        directory = tmp_path / "unavailable-runtime"
        with pytest.raises(LabConfigurationError) as caught:
            async with publish_lab_runtime(inputs, private_dns="excluded", directory=directory):
                pytest.fail("unavailable authority must not produce a publication")
        assert caught.value.code == "lab_human_identity_unavailable"
        assert not directory.exists()
