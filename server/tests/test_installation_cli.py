"""A real CLI and TLS app origin against aweb, AWID, PostgreSQL and Redis."""

import asyncio
import base64
import json
import os
from pathlib import Path

import pytest
import test_app_manifest_fetch as manifest_fixture
import test_dashboard_privacy as services
from aweb.app_manifests import ManifestFetcher
from aweb_naapp.egress import InternalDestinations, parse_destination
from aweb_naapp_testing.network import local_address
from awid.signing import canonical_json_bytes, sign_message
from test_agent_activity_emitter_e2e import _team_home

origin = manifest_fixture.origin
privacy_app = services.privacy_app
pytestmark = pytest.mark.asyncio


async def test_cli_member_request_admin_install_update_and_refused_update_preserve_local_tools(
    privacy_app, origin, source_cli_binary, tmp_path,
):
    env = privacy_app
    # The CLI uses the literal IP and the fixture CA. The server uses the real
    # egress guard with only this fixture's exact address allowed internally.
    address = local_address()
    origin.url = f"https://{address}:{origin.tls.port}"
    destination = parse_destination({
        "host": address, "port": origin.tls.port, "path": "/**", "methods": ["GET"],
        "network": "internal", "cidr": f"{address}/32",
    }, internal_destinations=InternalDestinations.ALLOWED)
    env.app.state.manifest_fetcher = ManifestFetcher(egress=origin.fetcher.egress, destination=destination)
    await env.db.execute("CREATE TABLE aweb.test_install_admins (team_id TEXT, did_key TEXT)")

    async def policy(tx, subject, *, action, app_id, verified_origin=None):
        return subject.kind == "certificate" and bool(await tx.fetch_value(
            "SELECT EXISTS(SELECT 1 FROM aweb.test_install_admins WHERE team_id=$1 AND did_key=$2)",
            subject.team_id, subject.did_key,
        ))

    env.app.state.install_admin_policy = policy
    def member_home(name, location):
        member = env.actors[name]
        home = _team_home(env, location, name)
        # Go omits these empty optional fields when it encodes a certificate.
        certificate = json.loads(base64.b64decode(member.certificate))
        for field in ("member_did_aw", "member_address", "signature"):
            certificate.pop(field)
        certificate["signature"] = sign_message(env.team_sk, canonical_json_bytes(certificate))
        next((home / "team-certs").glob("*.pem")).write_text(json.dumps(certificate))
        (home / "identity.yaml").write_text(json.dumps({
            "schema_version": 2, "did": member.did, "custody": "self", "identity_scope": "local",
        }))
        (home / "identity.yaml").chmod(0o600)
        return home

    home = member_home("alice", tmp_path)
    process_env = {**os.environ, "AW_HOME": str(tmp_path / "plugin-store"), "AW_NO_UPDATE_CHECK": "1",
                   "SSL_CERT_FILE": str(origin.tls.certificates.ca_file),
                   # On macOS, opt into the Go 1.27 SSL_CERT_FILE behavior even
                   # when the module retains its earlier Go compatibility defaults.
                   "GODEBUG": ",".join(filter(None, [os.environ.get("GODEBUG"), "x509sslcertoverrideplatform=1"]))}
    for name in ("AW_IDENTITY_HOME", "AW_TEAM", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        process_env.pop(name, None)
    # The native guard's lowercase proxy remains in force for other hosts.
    # Only this real TLS fixture's exact address bypasses it in the CLI child.
    fixture_no_proxy = ",".join(filter(None, [process_env.get("NO_PROXY") or process_env.get("no_proxy"), address]))
    process_env["NO_PROXY"] = process_env["no_proxy"] = fixture_no_proxy

    async def cli(*args, identity_home=home):
        process = await asyncio.create_subprocess_exec(
            str(source_cli_binary), "--identity-home", str(identity_home), "--json", "plugin", *args,
            cwd=tmp_path, env=process_env, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), 45)
        return process.returncode, stdout.decode(), stderr.decode()

    origin.publish(origin.manifest())
    code, out, error = await cli("install", origin.url)
    assert code != 0 and "admin_required" in error, out + error
    assert await env.db.fetch_value("SELECT COUNT(*) FROM {{tables.team_app_installs}}") == 0
    code, out, error = await cli("request", origin.url)
    assert code == 0, out + error
    assert json.loads(out)["state"] == "pending"
    assert await env.db.fetch_value("SELECT COUNT(*) FROM {{tables.team_app_installs}}") == 0

    await env.db.execute("INSERT INTO aweb.test_install_admins VALUES ($1,$2)", services.TEAM, env.actors["alice"].did)
    code, out, error = await cli("install", origin.url, "--grant-scope", "fixture:read")
    assert code == 0, out + error
    installed = json.loads(out)
    assert installed["provenance"]["registered_generation"] == 1
    installation_id = installed["provenance"]["registered_installation_id"]
    assert await env.db.fetch_value("SELECT granted_scopes FROM {{tables.team_app_installs}}") == ["fixture:read"]
    path = Path(installed["path"]) / "manifest.json"
    assert path.read_bytes() == origin.routes[manifest_fixture.VARIANT][1]

    # A second resident/member can join the same active team installation.
    # It must not need install-admin or mutate the team's narrowed grants.
    bob_home = member_home("bob", tmp_path / "bob")
    code, out, error = await cli("install", origin.url, identity_home=bob_home)
    assert code == 0, out + error
    assert json.loads(out)["provenance"]["registered_generation"] == 1
    assert await env.db.fetch_value("SELECT granted_scopes FROM {{tables.team_app_installs}}") == ["fixture:read"]
    code, out, error = await cli("install", origin.url)
    assert code == 0, out + error
    assert json.loads(out)["provenance"]["registered_generation"] == 1
    assert await env.db.fetch_value("SELECT granted_scopes FROM {{tables.team_app_installs}}") == ["fixture:read"]

    origin.publish(origin.manifest(version="2.0.0"))
    code, out, error = await cli("update", "fixture")
    assert code == 0, out + error
    updated = json.loads(out)
    assert updated["provenance"]["registered_generation"] == 2
    assert updated["provenance"]["registered_installation_id"] == installation_id
    saved = path.read_bytes()
    assert await env.db.fetch_value("SELECT granted_scopes FROM {{tables.team_app_installs}}") == ["fixture:read"]

    await env.db.execute("DELETE FROM aweb.test_install_admins")
    origin.publish(origin.manifest(version="3.0.0"))
    code, out, error = await cli("update", "fixture")
    assert code != 0 and "admin_required" in error, out + error
    assert path.read_bytes() == saved
    assert await env.db.fetch_value("SELECT generation FROM {{tables.team_app_installs}}") == 2

    # Team uninstall uses the selected resident authority and retains the
    # local bytes/approval, which may also serve another team.
    code, out, error = await cli("uninstall", "fixture")
    assert code != 0 and "admin_required" in error, out + error
    assert path.read_bytes() == saved
    assert await env.db.fetch_value("SELECT state FROM {{tables.team_app_installs}}") == "active"
    await env.db.execute("INSERT INTO aweb.test_install_admins VALUES ($1,$2)", services.TEAM, env.actors["alice"].did)
    code, out, error = await cli("uninstall", "fixture", "--expected-generation", "1")
    assert code != 0 and "generation_conflict" in error, out + error
    code, out, error = await cli("uninstall", "fixture")
    assert code == 0, out + error
    retired = json.loads(out)
    assert retired["state"] == "uninstalled" and retired["generation"] == 3
    assert retired["installation_id"] == installation_id
    assert path.read_bytes() == saved
    code, out, error = await cli("uninstall", "fixture")
    assert code == 0 and json.loads(out)["generation"] == retired["generation"], out + error
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.app_hook_bindings}} WHERE state IN ('active','pending')") == 0
    code, out, error = await cli("install", origin.url)
    assert code == 0, out + error
    replacement = json.loads(out)["provenance"]
    assert replacement["registered_installation_id"] != installation_id
    assert replacement["registered_generation"] > retired["generation"]
