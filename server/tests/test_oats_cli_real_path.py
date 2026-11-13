"""aw's three OATS commands against the real protected service and AWID.

The built aw binary runs as the deployment's root against the native signer
world (tests.test_independent_protected_signer.signer_world and
tests.test_protected_admission_native.admission_world), both served on
loopback sockets whose origins the world is built with. Nothing is mocked:
aw's proofs, the signer's checks and effects, and AWID's registration and
status are the production code. The human's approval is driven through the
signer's own approval options and execute with the enrolled authenticator;
the browser page is separately attributed.

Native bodies require the coordinator's VM placement. No local DB fallback.
"""

import asyncio
import json
import os
import re
import socket
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
import uvicorn
from awid.did import did_from_public_key, generate_keypair

from tests.test_cli_human_reply import _pem
from tests.test_independent_protected_signer import DOMAIN, TEAM, did, signer_world
from tests.test_protected_admission_native import admission_world

pytest_plugins = ("tests.test_independent_protected_signer",)

PROFILE_VECTOR = Path(__file__).resolve().parents[2] / "docs/vectors/protected-service-profile-v1.json"


def _listener():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    return sock, f"http://127.0.0.1:{sock.getsockname()[1]}"


@asynccontextmanager
async def _serving(app, sock):
    server = uvicorn.Server(uvicorn.Config(app, lifespan="off", log_level="error", ws="none"))
    serving = asyncio.create_task(server.serve(sockets=[sock]))
    try:
        for _ in range(250):
            if server.started:
                break
            await asyncio.sleep(.02)
        assert server.started
        yield
    finally:
        server.should_exit = True
        await asyncio.wait_for(serving, 5)
        sock.close()


@asynccontextmanager
async def oats_world(test_db_factory, tmp_path):
    """The native world on real sockets, with the root's aw home and profile."""
    registry_sock, registry_origin = _listener()
    request_sock, request_origin = _listener()
    async with signer_world(test_db_factory, tmp_path, registry_origin=registry_origin, request_origin=request_origin) as w:
        async with admission_world(w, tmp_path) as a:
            async with _serving(w.host.app, registry_sock), _serving(a.api, request_sock):
                yield a, _profile(tmp_path, a), _root_home(tmp_path, w)


def _profile(tmp_path, a):
    w = a.w
    fields = json.loads(PROFILE_VECTOR.read_bytes())
    policy = fields["bindings"][0]["policy"]
    fields.update(request_origin=w.request_origin, registry_origin=w.registry_origin)
    fields["namespace_authorities"] = [{"domain": d, "controller_did": k} for d, k in w.registry.namespace_keys.items()]
    fields["bindings"] = [
        {"scope": w.context.fields(), "authority_key_did": did(w.controller), "policy": policy},
        {"scope": a.human.context.fields(), "authority_key_did": did(w.human_key), "policy": policy},
    ]
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(fields))
    return path


def _root_home(tmp_path, w):
    """The root's own identity home: its key and stable ID, nothing else."""
    root = (tmp_path / "root").resolve()
    home = root / ".aw"
    home.mkdir(parents=True, mode=0o700)
    _pem(home / "signing.key", "ED25519 PRIVATE KEY", bytes(w.root))
    (home / "identity.yaml").write_text(json.dumps({"did": did(w.root), "stable_id": w.root_id, "custody": "self",
        "identity_scope": "global"}))
    no_opener = tmp_path / "no-browser-opener"
    no_opener.mkdir()
    env = {k: v for k, v in os.environ.items() if not k.startswith(("AW", "XDG_"))}
    env.update(HOME=str(root), PWD=str(root), XDG_CONFIG_HOME=str(root / ".config"), XDG_STATE_HOME=str(root / ".state"),
        AW_NO_UPDATE_CHECK="1", PATH=str(no_opener), AWID_REGISTRY_URL=w.registry_origin)
    return root, env


@asynccontextmanager
async def _running(home, *args, grace=5.0):
    """The aw process for args, which never outlives its caller: on every
    exit, a timeout, cancellation or failed assertion included, it is asked to
    terminate, killed if it has not after grace seconds, and waited for."""
    root, env = home
    proc = await asyncio.create_subprocess_exec(os.environ["AW_TEST_CLI_BINARY"], "--json", *args, cwd=root, env=env,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        yield proc
    finally:
        if proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), grace)
            except TimeoutError:
                proc.kill()
                await proc.wait()


async def _aw(home, *args, timeout=120, grace=5.0):
    """aw's exit status, its --json answer and its progress lines."""
    async with _running(home, *args, grace=grace) as proc:
        out, err = await asyncio.wait_for(proc.communicate(), timeout)
    return proc.returncode, json.loads(out or b"{}"), err.decode()


async def _endorse(a, profile, home, operation_id, *, page_timeout=60, timeout=120):
    """Run aw id endorse, approving its exact operation once aw shows its page."""
    args = ("id", "endorse", "--protected-profile", str(profile), "--human", a.human.context.authority_id if a else "",
        "--team", TEAM, "--deployment-label", "oats-root", "--operation-id", operation_id)
    async with _running(home, *args) as proc:
        progress = []
        while True:
            line = (await asyncio.wait_for(proc.stderr.readline(), page_timeout)).decode()
            assert line, "".join(progress)
            progress.append(line)
            if re.search(r"Approve it on this page: \S+/handoff/\S+", line):
                break
        options = await a.human.signer.approval_options(operation_id, human=a.actor)
        approved = await a.human.signer.execute(operation_id, a.device.get(dict(options)), human=a.actor)
        assert approved.state == "committed"
        out, err = await asyncio.wait_for(proc.communicate(), timeout)
    return proc.returncode, json.loads(out or b"{}"), "".join(progress) + err.decode()


async def _current_head(w, identity):
    async with httpx.AsyncClient(base_url=w.registry_origin) as client:
        status = (await client.post("/v1/id-certificates/status", json={"v": 1, "domain": DOMAIN, "ids": [identity]})).json()
    return next(row["current_certificate_id"] for row in status["identities"] if row["id"] == identity)


@pytest.mark.usefixtures("source_cli_binary")
@pytest.mark.asyncio
async def test_the_policy_read_answers_the_provisioned_policy_with_its_version_and_digest(test_db_factory, tmp_path):
    async with oats_world(test_db_factory, tmp_path) as (a, profile, home):
        status, answer, progress = await _aw(home, "id", "team", "admission-policy", "--team", TEAM, "--protected-profile", str(profile))
        assert status == 0, progress
        assert answer == {"service_id": a.w.context.service_id, "team_id": TEAM, "mode": "protected", "policy": a.policy}


@pytest.mark.usefixtures("source_cli_binary")
@pytest.mark.asyncio
async def test_an_endorsed_root_admits_an_agent_once_under_its_own_operation_id(test_db_factory, tmp_path):
    async with oats_world(test_db_factory, tmp_path) as (a, profile, home):
        w = a.w
        endorsement = str(uuid4())
        status, endorsed, progress = await _endorse(a, profile, home, endorsement)
        assert status == 0, progress
        assert endorsed["operation_id"] == endorsement and endorsed["state"] == "committed" and endorsed["registered"] is True
        # aw registered the root's certificate with its own proof; the
        # registry's current head is exactly that certificate.
        assert await _current_head(w, w.root_id) == endorsed["certificate_id"]

        _, child_public = generate_keypair()
        child_key = did_from_public_key(child_public)
        admission = str(uuid4())
        certificate_out = home[0] / "worker-team-certificate.json"
        admit = ("id", "team", "admit", "--protected-profile", str(profile), "--team", TEAM, "--member-key", child_key,
            "--alias", "worker", "--policy-version", str(a.policy["version"]), "--policy-digest", a.policy["digest"],
            "--operation-id", admission, "--certificate-out", str(certificate_out))
        status, admitted, progress = await _aw(home, *admit)
        assert status == 0, progress
        assert admitted == {"operation_id": admission, "state": "committed", "certificate_out": str(certificate_out)}
        certificate = json.loads(certificate_out.read_text())
        assert certificate["member_did_key"] == child_key and certificate["alias"] == "worker"
        assert certificate["identity_scope"] == "local" and "member_did_aw" not in certificate
        records = await w.registry.list_team_certificates_fresh(DOMAIN, "engineering", active_only=True)
        assert [r.certificate_id for r in records].count(certificate["certificate_id"]) == 1

        # The same id and inputs return the original certificate: no second
        # signature, admission or quota.
        first = certificate_out.read_bytes()
        status, again, progress = await _aw(home, *admit)
        assert status == 0, progress
        assert again == admitted and certificate_out.read_bytes() == first
        records = await w.registry.list_team_certificates_fresh(DOMAIN, "engineering", active_only=True)
        assert [r.certificate_id for r in records].count(certificate["certificate_id"]) == 1
        assert await w.db.fetch_value("SELECT count(*) FROM {{tables.protected_root_admissions}} WHERE root_id=$1", w.root_id) == 1
        assert await w.db.fetch_value(
            "SELECT count(*) FROM {{tables.protected_local_audit}} WHERE kind='protected_operation_signed' AND subject=$1",
            admission) == 1

        # Changed inputs under that id are a conflict, and nothing is sent
        # for them.
        changed = tuple("other" if arg == "worker" else arg for arg in admit)
        status, refused, progress = await _aw(home, *changed)
        assert status != 0 and refused["error"]["code"] == "operation_conflict", progress


def _fake_aw(tmp_path, monkeypatch, body):
    """An aw stand-in that records its pid, then runs body."""
    pid_file = tmp_path / "fake-aw.pid"
    fake = tmp_path / "fake-aw"
    fake.write_text(f"#!{sys.executable}\nimport os, signal, time\nopen({str(pid_file)!r}, 'w').write(str(os.getpid()))\n{body}\n")
    fake.chmod(0o755)
    monkeypatch.setenv("AW_TEST_CLI_BINARY", str(fake))
    return pid_file


def _gone(pid_file):
    try:
        os.kill(int(pid_file.read_text()), 0)
    except ProcessLookupError:
        return True
    return False


@pytest.mark.asyncio
async def test_an_aw_that_never_answers_is_stopped_when_its_wait_ends(tmp_path, monkeypatch):
    pid_file = _fake_aw(tmp_path, monkeypatch, "time.sleep(60)")
    with pytest.raises(TimeoutError):
        await _aw((tmp_path, dict(os.environ)), "id", "team", "admission-policy", timeout=2)
    assert _gone(pid_file)


@pytest.mark.asyncio
async def test_an_aw_that_ignores_termination_is_killed(tmp_path, monkeypatch):
    pid_file = _fake_aw(tmp_path, monkeypatch, "signal.signal(signal.SIGTERM, signal.SIG_IGN)\ntime.sleep(60)")
    started = asyncio.get_running_loop().time()
    with pytest.raises(TimeoutError):
        await _aw((tmp_path, dict(os.environ)), "id", "team", "admission-policy", timeout=2, grace=0.5)
    # Stopped by the kill after the grace, not by waiting out its sleep.
    assert asyncio.get_running_loop().time() - started < 10
    assert _gone(pid_file)


@pytest.mark.asyncio
async def test_an_endorse_that_never_shows_its_page_is_stopped(tmp_path, monkeypatch):
    pid_file = _fake_aw(tmp_path, monkeypatch, "time.sleep(60)")
    with pytest.raises(TimeoutError):
        await _endorse(None, tmp_path / "profile.json", (tmp_path, dict(os.environ)), str(uuid4()), page_timeout=2)
    assert _gone(pid_file)


@pytest.mark.asyncio
async def test_an_endorse_whose_aw_ends_before_its_page_is_reported_and_stopped(tmp_path, monkeypatch):
    pid_file = _fake_aw(tmp_path, monkeypatch, "import sys\nsys.stderr.write('Preparing operation x\\n')")
    with pytest.raises(AssertionError, match="Preparing operation x"):
        await _endorse(None, tmp_path / "profile.json", (tmp_path, dict(os.environ)), str(uuid4()), page_timeout=5)
    assert _gone(pid_file)


@pytest.mark.usefixtures("source_cli_binary")
@pytest.mark.asyncio
async def test_a_root_is_created_with_no_address_at_the_real_registry_and_only_once(test_db_factory, tmp_path):
    registry_sock, registry_origin = _listener()
    request_sock, request_origin = _listener()
    async with signer_world(test_db_factory, tmp_path, registry_origin=registry_origin, request_origin=request_origin) as w:
        async with _serving(w.host.app, registry_sock):
            request_sock.close()
            root = (tmp_path / "new-root").resolve()
            no_opener = tmp_path / "no-browser-opener"
            no_opener.mkdir()
            env = {k: v for k, v in os.environ.items() if not k.startswith(("AW", "XDG_"))}
            env.update(HOME=str(tmp_path), XDG_CONFIG_HOME=str(tmp_path / ".config"), XDG_STATE_HOME=str(tmp_path / ".state"),
                AW_NO_UPDATE_CHECK="1", PATH=str(no_opener))
            create = ("--identity-home", str(root), "id", "create", "--no-address", "--registry", registry_origin)
            status, created, progress = await _aw((tmp_path, env), *create)
            assert status == 0, progress
            assert created["status"] == "created" and created["registry_url"] == registry_origin
            # The registry itself maps the new did:aw to the key aw holds.
            async with httpx.AsyncClient(base_url=registry_origin) as client:
                key = (await client.get(f"/v1/did/{created['did_aw']}/key")).json()
            assert key["current_did_key"] == created["did_key"]
            assert (root / "signing.key").stat().st_mode & 0o777 == 0o600
            assert "address" not in (root / "identity.yaml").read_text()
            # A rerun on the complete identity creates nothing.
            status, refused, progress = await _aw((tmp_path, env), *create)
            assert status != 0 and refused["error"]["code"] == "identity_exists", progress


@pytest.mark.usefixtures("source_cli_binary")
@pytest.mark.asyncio
async def test_an_endorsement_that_is_not_waited_for_is_finished_by_a_rerun(test_db_factory, tmp_path):
    async with oats_world(test_db_factory, tmp_path) as (a, profile, home):
        w = a.w
        operation = str(uuid4())
        endorse = ("id", "endorse", "--protected-profile", str(profile), "--human", a.human.context.authority_id, "--team", TEAM,
            "--deployment-label", "oats-root", "--operation-id", operation, "--no-wait", "--no-browser")
        # Not waited for: aw reports the pending operation and its page, and exits.
        status, pending, progress = await _aw(home, *endorse)
        assert status == 0, progress
        assert pending["operation_id"] == operation and pending["state"] == "pending"
        assert pending["page"].startswith(a.w.human_origin + "/handoff/") and pending["reason"] == "awaiting_human"
        assert len(pending["digest"]) == 64 and pending["fingerprint"] == " ".join(
            pending["digest"][i:i + 4] for i in range(0, 16, 4))
        # The human approves on the service.
        options = await a.human.signer.approval_options(operation, human=a.actor)
        approved = await a.human.signer.execute(operation, a.device.get(dict(options)), human=a.actor)
        assert approved.state == "committed"
        # The same command again finishes: no wait, registration and read-back.
        status, endorsed, progress = await _aw(home, *endorse)
        assert status == 0, progress
        assert endorsed["operation_id"] == operation and endorsed["state"] == "committed" and endorsed["registered"] is True
        assert await _current_head(w, w.root_id) == endorsed["certificate_id"]


@pytest.mark.usefixtures("source_cli_binary")
@pytest.mark.asyncio
async def test_a_spawned_key_only_agent_is_admitted_and_its_certificate_installed_in_its_home(test_db_factory, tmp_path):
    async with oats_world(test_db_factory, tmp_path) as (a, profile, home):
        w = a.w
        status, endorsed, progress = await _endorse(a, profile, home, str(uuid4()))
        assert status == 0 and endorsed["state"] == "committed", progress

        # OATS's spawn: a key-only home for the agent, registered nowhere.
        child = home[0] / "worker-home"
        create = ("--identity-home", str(child), "id", "create", "--local")
        status, created, progress = await _aw(home, *create)
        assert status == 0 and created["status"] == "created", progress
        assert "did_aw" not in created
        status, again, progress = await _aw(home, *create)
        assert status == 0 and again == {**created, "status": "already_exists"}, progress

        # The root admits that key; the certificate file is installed into the
        # agent's home after aw checks it at the real registry.
        certificate_out = home[0] / "worker-team-certificate.json"
        status, admitted, progress = await _aw(home, "id", "team", "admit", "--protected-profile", str(profile), "--team", TEAM,
            "--member-key", created["did_key"], "--alias", "worker", "--policy-version", str(a.policy["version"]),
            "--policy-digest", a.policy["digest"], "--operation-id", str(uuid4()), "--certificate-out", str(certificate_out))
        assert status == 0 and admitted["state"] == "committed", progress
        certificate = json.loads(certificate_out.read_text())
        install = ("--identity-home", str(child), "id", "team", "install-cert", "--certificate", str(certificate_out),
            "--registry", w.registry_origin)
        status, installed, progress = await _aw(home, *install)
        assert status == 0, progress
        assert installed["status"] == "installed" and installed["team_id"] == TEAM and installed["alias"] == "worker"
        assert installed["certificate_id"] == certificate["certificate_id"] and installed["did_key"] == created["did_key"]
        status, again, progress = await _aw(home, *install)
        assert status == 0 and again["status"] == "already_installed", progress

        # Once the registry revokes it, the same file is refused.
        await w.registry.revoke_team_certificate(DOMAIN, "engineering", team_controller_signing_key=bytes(w.controller),
            certificate_id=certificate["certificate_id"])
        status, refused, progress = await _aw(home, *install)
        assert status != 0 and refused["error"]["code"] == "certificate_revoked", progress
