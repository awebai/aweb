"""The team owner activates and revokes hook bindings with the real aw CLI.

The CLI, the TLS app origin, aweb served over TLS with an https public origin,
the AWID registry holding the team's controller key, PostgreSQL and Redis are
all real. The owner's key is the team key in the CLI's own AWID state; a
member without it is refused before anything is signed.
"""

import asyncio
import base64
import json
import os

import pytest
import pytest_asyncio
import test_app_manifest_fetch as manifest_fixture
import test_dashboard_privacy as services
from aweb.app_manifests import ManifestFetcher
from aweb_naapp.egress import InternalDestinations, parse_destination
from aweb_naapp_testing.network import local_address
from awid.signing import canonical_json_bytes, sign_message
from test_agent_activity_emitter_e2e import _pem, _team_home

origin_fixture = manifest_fixture.origin
privacy_app = services.privacy_app
pytestmark = pytest.mark.asyncio

CATALOG = {"id": "aweb.hooks", "version": 1}


@pytest_asyncio.fixture
async def origin(origin_fixture):
    origin_fixture.url = f"https://{local_address()}:{origin_fixture.tls.port}"
    return origin_fixture


@pytest.fixture
def privacy_server_tls(origin):
    # aweb listens on the origin's address with its certificate, so one CA
    # file lets the CLI trust both, and the server's public origin is https.
    return local_address(), origin.tls.certificates


def hooked_manifest(origin, **app_changes):
    """The fixture manifest with real-catalog hooks, scopes and reads listed
    out of code-point order, and a key that may sign hook events."""
    doc = json.loads(origin.manifest(**app_changes))
    doc["app_keys"][0]["purposes"].append("hook-event")
    doc["hooks"] = {
        "registration_version": 1,
        "registrations": [{
            "catalog": CATALOG, "hook": "post-command-hook", "tool": "audit-ingest",
            "scopes": ["fixture:write", "fixture:append"],
        }],
        "productions": [{
            "catalog": CATALOG, "hook": "post-manifest-command-hook",
            "reads": ["workspace-read", "workspace-list"],
        }],
    }
    return (json.dumps(doc, indent=2) + "\n").encode()


async def test_owner_activates_and_revokes_bindings_with_the_team_key(
    privacy_app, origin, source_cli_binary, tmp_path,
):
    env = privacy_app
    address = local_address()
    destination = parse_destination({
        "host": address, "port": origin.tls.port, "path": "/**", "methods": ["GET"],
        "network": "internal", "cidr": f"{address}/32",
    }, internal_destinations=InternalDestinations.ALLOWED)
    env.app.state.manifest_fetcher = ManifestFetcher(egress=origin.fetcher.egress, destination=destination)
    assert str(env.client.base_url).startswith("https://")

    async def admit_everyone(tx, subject, *, action, app_id, verified_origin=None):
        return subject.kind == "certificate"

    env.app.state.install_admin_policy = admit_everyone

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

    alice_home = member_home("alice", tmp_path / "alice")
    bob_home = member_home("bob", tmp_path / "bob")
    # Only the owner's machine holds the team (controller) key, in AWID state.
    owner_user_home = tmp_path / "owner-user"
    member_user_home = tmp_path / "member-user"
    team_name, domain = services.TEAM.split(":", 1)
    key_dir = owner_user_home / ".awid" / "team-keys" / domain
    key_dir.mkdir(parents=True, mode=0o700)
    _pem(key_dir / f"{team_name}.key", "ED25519 PRIVATE KEY", env.team_sk)
    member_user_home.mkdir()

    process_env = {**os.environ, "AW_HOME": str(tmp_path / "plugin-store"), "AW_NO_UPDATE_CHECK": "1",
                   "SSL_CERT_FILE": str(origin.tls.certificates.ca_file),
                   "GODEBUG": ",".join(filter(None, [os.environ.get("GODEBUG"), "x509sslcertoverrideplatform=1"]))}
    for name in ("AW_IDENTITY_HOME", "AW_TEAM", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        process_env.pop(name, None)
    fixture_no_proxy = ",".join(filter(None, [process_env.get("NO_PROXY") or process_env.get("no_proxy"), address]))
    process_env["NO_PROXY"] = process_env["no_proxy"] = fixture_no_proxy

    async def cli(*args, identity_home, user_home):
        process = await asyncio.create_subprocess_exec(
            str(source_cli_binary), "--identity-home", str(identity_home), "--json", *args,
            cwd=tmp_path, env={**process_env, "HOME": str(user_home)},
            stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), 45)
        return process.returncode, stdout.decode(), stderr.decode()

    async def owner(*args):
        return await cli(*args, identity_home=alice_home, user_home=owner_user_home)

    async def member(*args):
        return await cli(*args, identity_home=bob_home, user_home=member_user_home)

    manifest = hooked_manifest(origin)
    origin.publish(manifest)
    code, out, error = await owner("plugin", "install", origin.url)
    assert code == 0, out + error

    code, out, error = await member("hooks", "bindings", "fixture")
    assert code == 0, out + error
    listed = json.loads(out)
    assert listed["team_id"] == services.TEAM
    rows = {row["kind"]: row for row in listed["bindings"]}
    assert {row["state"] for row in rows.values()} == {"pending"}
    registration, production = rows["registration"], rows["production"]
    assert registration["scopes"] == ["fixture:append", "fixture:write"]
    assert production["reads"] == ["workspace-list", "workspace-read"]

    async def state(binding_id):
        return await env.db.fetch_value(
            "SELECT state FROM {{tables.app_hook_bindings}} WHERE binding_id = $1::uuid", binding_id,
        )

    # A member without the team key is refused before anything is fetched or signed.
    seen = len(origin.tls.seen)
    code, out, error = await member("hooks", "activate", "fixture", registration["binding_id"], "--yes")
    assert code != 0 and json.loads(out)["error"]["code"] == "owner_key_required", out + error
    assert len(origin.tls.seen) == seen
    assert await state(registration["binding_id"]) == "pending"

    # Without a terminal the owner must confirm explicitly; nothing is sent.
    code, out, error = await owner("hooks", "activate", "fixture", registration["binding_id"])
    assert code != 0 and json.loads(out)["error"]["code"] == "confirmation_required", out + error
    assert await state(registration["binding_id"]) == "pending"

    # The owner sees the fetched, digest-checked manifest's facts, then signs.
    seen = len(origin.tls.seen)
    code, out, error = await owner("hooks", "activate", "fixture", registration["binding_id"], "--yes")
    assert code == 0, out + error
    assert manifest_fixture.VARIANT in [s.request_line.split(" ")[1] for s in origin.tls.seen[seen:]]
    for shown in (str(env.client.base_url).rstrip("/"), registration["digest"], "post-command-hook", "audit-ingest",
                  "POST", "/v1/audit-ingest", "fixture:append", "fixture:write", registration["binding_id"]):
        assert shown in error, (shown, error)
    activated = json.loads(out)
    assert (activated["binding_id"], activated["state"]) == (registration["binding_id"], "active")
    assert await env.db.fetch_value(
        "SELECT activation_act_sha256 IS NOT NULL FROM {{tables.app_hook_bindings}} WHERE binding_id = $1::uuid",
        registration["binding_id"],
    )

    code, out, error = await owner("hooks", "activate", "fixture", production["binding_id"], "--yes")
    assert code == 0, out + error
    for shown in ("post-manifest-command-hook", "workspace-list", "workspace-read"):
        assert shown in error, (shown, error)
    assert json.loads(out)["state"] == "active"

    code, out, error = await owner("hooks", "revoke", "fixture", registration["binding_id"], "--yes")
    assert code == 0, out + error
    revoked = json.loads(out)
    assert (revoked["state"], revoked["ended_by"]) == ("revoked", "owner_act")
    assert await state(production["binding_id"]) == "active"

    # When the origin no longer serves the pinned bytes, the owner signs nothing.
    origin.publish(hooked_manifest(origin, version="9.9.9"))
    code, out, error = await owner("hooks", "revoke", "fixture", production["binding_id"], "--yes")
    assert code != 0 and json.loads(out)["error"]["code"] == "binding_manifest_mismatch", out + error
    assert await state(production["binding_id"]) == "active"
