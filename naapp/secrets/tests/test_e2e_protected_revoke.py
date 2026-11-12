"""The protected round trip: aw prepares, the human approves in a real browser.

One human-role.revoke goes through the independent protected server
(aweb.protected_signing.host, HOST.md): the requester's aw prepares it with
its covering-v2 proof, the approving human logs in on the console page in a
fresh Chromium tab with a passkey and approves the exact act with a separate
user verification, the server signs with the team controller key only it
holds, and aw reports the exact committed receipt. The signed act is retained
in the receipt and local audit; it is NOT applied to the app (acxy.9).

Real: AWID with DNS verification, aweb, the secrets app installed as a
disposable fixture app, the protected server image with ProtectedControllerCustody,
the aw binary, Chromium running the console page's own script. Substituted:
the outbound notification transport (a TLS mailpit read by this test), and the
person (a CDP virtual authenticator). Provisioning follows HOST.md through
B3's own enrolment APIs; nothing inserts a credential, session or success row.

make e2e only, in an aweb-placed exclusive window.
"""

from __future__ import annotations

import base64
import json
import os
import re
import secrets
import shutil
import subprocess
from collections.abc import Iterator
from urllib.parse import unquote

import pexpect
import pytest
from aweb_naapp_testing.network import make_certificates

from tests.test_e2e_owner_acts import (
    API,
    AWEB,
    DOMAIN,
    REGISTRY,
    REPO,
    ROLE,
    TEAM,
    TEAM_ID,
    Holder,
    Lane,
    _docker,
    aw,
    await_awid_txt,
    first_json,
    publish_awid_txt,
    write_service_member,
)

pytestmark = pytest.mark.e2e

SIGNER = "https://signer.svc.test"
HUMAN = "https://human.svc.test"
SERVICE_ID = "e2e-protected"
PROFILE = "/runtime/protected/config/profile.json"
CONTACT = "approver@h.test"


class ProtectedLane(Lane):
    def protected(self, *args: str, timeout: int = 900) -> subprocess.CompletedProcess[str]:
        return self.compose("--profile", "protected", *args, timeout=timeout)

    def provision(self, *args: str, stdin: str | None = None) -> dict:
        """The trusted provisioner, inside the protected container as its uid."""
        result = subprocess.run(
            ["docker", "compose", "-p", self.project, "-f", str(REPO / "naapp/secrets/docker-compose.e2e.yml"),
             "--profile", "protected", "run", "--rm", "-T", "--no-deps", "--entrypoint", "python",
             "protected", "/provision.py", *args],
            env=self.env, text=True, capture_output=True, input=stdin, timeout=300, check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        return first_json(result.stdout)

    def chromium(self, machine: str, *args: str) -> dict:
        """The approving human's Chromium, in the requester's network namespace."""
        result = _docker("run", "--rm", f"--network=container:{machine}", f"--volume={self.runtime}:/runtime",
                         f"{self.project}-chromium", *args, "--ca", "/runtime/tls/ca.pem", timeout=300)
        assert result.returncode == 0, result.stdout + result.stderr
        out = result.stdout.strip()
        return first_json(out) if "{" in out else {}


@pytest.fixture(scope="module")
def lane(tmp_path_factory: pytest.TempPathFactory) -> Iterator[ProtectedLane]:
    if os.environ.get("SECRETS_E2E") != "1":
        pytest.skip("make e2e only")
    project = os.environ.get("NAAPP_E2E_PROJECT", "secrets-protected-e2e")
    runtime = tmp_path_factory.mktemp("protected")
    runtime.chmod(0o755)
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, text=True, capture_output=True, check=True).stdout.strip()
    lane = ProtectedLane(project, runtime, {**os.environ, "SECRETS_E2E_RUNTIME": str(runtime), "SECRETS_E2E_SOURCE_COMMIT": commit,
                                       "SECRETS_E2E_AWID_SERVICE_TOKEN": secrets.token_hex(32)})

    (runtime / "dns").mkdir()
    (runtime / "dns" / "Corefile").write_text(
        f"{DOMAIN}:53 {{\n  errors\n  file /zones/{DOMAIN}.zone {DOMAIN} {{ reload 1s }}\n}}\n"
        ".:53 {\n  errors\n  forward . 127.0.0.11\n}\n"
    )
    publish_awid_txt(lane, "did:key:z6MkpendingpendingpendingpendingpendingpendingpendingP")
    hosts = ["api.secrets.svc.test", "console.secrets.svc.test", "signer.svc.test", "human.svc.test", "mail.svc.test"]
    (runtime / "tls").mkdir()
    tls = make_certificates(runtime / "tls", hosts, [])
    shutil.copyfile(tls.cert_file, runtime / "tls" / "smtp.pem")
    shutil.copyfile(tls.key_file, runtime / "tls" / "smtp-key.pem")
    for path in (runtime / "tls").iterdir():
        path.chmod(0o644)
    (runtime / "front").mkdir()
    upstream = {"api.secrets.svc.test": "secrets:8770", "console.secrets.svc.test": "secrets:8770",
                "signer.svc.test": "protected:8080", "human.svc.test": "protected:8080"}
    (runtime / "front" / "Caddyfile").write_text(
        "{\n  auto_https off\n}\n"
        + "".join(
            f"{host}:443 {{\n  tls /tls/{tls.cert_file.name} /tls/{tls.key_file.name}\n  reverse_proxy {target}\n}}\n"
            for host, target in upstream.items()
        )
    )
    try:
        lane.up("dns")
        dns = lane.compose("ps", "-q", "dns").stdout.strip()
        ip = _docker("inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", dns).stdout.strip()
        assert ip, "no DNS address"
        lane.env["SECRETS_E2E_DNS_IP"] = ip
        lane.up("postgres", "redis", "awid", "aweb", "smtp")
        result = lane.protected("up", "-d", "--wait", "smtp-tls")
        assert result.returncode == 0, result.stdout + result.stderr
        result = lane.compose("--profile", "protected", "--profile", "chromium", "build", "cli", "protected", "chromium")
        assert result.returncode == 0, result.stdout + result.stderr
        yield lane
    finally:
        lane.compose("--profile", "protected", "--profile", "chromium", "--profile", "browser",
                     "down", "-v", "--remove-orphans")
        for name in ("controller", "holder"):
            _docker("rm", "-f", f"{project}-{name}")


def seed_hex(pem: str) -> str:
    body = "".join(line for line in pem.splitlines() if line and not line.startswith("-----"))
    seed = base64.b64decode(body)
    assert len(seed) == 32
    return seed.hex()


def did_key_of(seed: str) -> str:
    from awid.did import did_from_public_key  # noqa: PLC0415
    from nacl.signing import SigningKey  # noqa: PLC0415

    return did_from_public_key(bytes(SigningKey(bytes.fromhex(seed)).verify_key))


def enrolment_token(lane: ProtectedLane, machine: str) -> str:
    """The approver's enrolment link, read from the captured transport."""
    listing = _docker("exec", machine, "curl", "-fsS", "http://mail.svc.test:8025/api/v1/messages")
    assert listing.returncode == 0, listing.stderr
    messages = [m for m in json.loads(listing.stdout)["messages"] if any(t["Address"] == CONTACT for t in m["To"])]
    assert len(messages) == 1, messages
    message = _docker("exec", machine, "curl", "-fsS", f"http://mail.svc.test:8025/api/v1/message/{messages[0]['ID']}")
    link = re.search(re.escape(HUMAN) + r"/enrolment#token=(\S+)", json.loads(message.stdout)["Text"])
    assert link, message.stdout
    return unquote(link.group(1))


def start_revoke(machine: str, principal: str) -> tuple[pexpect.spawn, str, str, str]:
    """aw prepares the revoke as the requester; returns the page it names, the
    operation id and the digest it printed."""
    child = pexpect.spawn(
        "docker", ["exec", "-it", machine, "aw", "--json", "app", "role", "revoke", "secrets", "--role", ROLE,
                   "--principal", principal, "--protected-profile", PROFILE, "--approver", principal],
        encoding="utf-8", timeout=180, echo=False,
    )
    child.expect(r"Operation (\S+)\r?\n\s+digest:\s+([0-9a-f]{64})")
    operation, digest = child.match.group(1), child.match.group(2)
    child.expect(r"Approve it on this page: (\S+)")
    page = child.match.group(1)
    assert page.startswith(HUMAN + "/handoff/"), page
    return child, page, operation, digest


def finish(child: pexpect.spawn) -> tuple[int, str]:
    child.expect(pexpect.EOF, timeout=240)
    output = child.before
    child.close()
    return child.exitstatus, output


def test_a_human_approves_a_protected_revoke_in_a_real_browser(lane: ProtectedLane) -> None:
    holder = Holder(lane, lane.machine("holder"))
    # One machine holds the namespace controller (from prepare-controller), so
    # aw creates the root-parented requester there, beside H's human key.
    owner = holder.container

    # The namespace, its root human H (the approver) and the team, on H's machine.
    prepared = aw(holder.container, "id", "namespace", "prepare-controller", "--domain", DOMAIN, "--registry", REGISTRY)
    publish_awid_txt(lane, prepared["controller_did"])
    await_awid_txt(holder.container, prepared["controller_did"])
    child = holder.spawn("--json", "id", "human", "init", "--domain", DOMAIN, "--as-root")
    output = holder.answer_passphrases(child)
    child.close()
    assert child.exitstatus == 0, output
    approver = first_json(output)["id"]
    aw(holder.container, "id", "team", "create", "--name", TEAM, "--namespace", DOMAIN, "--registry", REGISTRY)
    team_key = lane.runtime / "holder" / ".awid" / "team-keys" / DOMAIN / f"{TEAM}.key"

    # The requester: a root-parented agent identity, a team member, connected.
    requester = aw(owner, "id", "create", "--name", "owner", "--domain", DOMAIN, "--root-parent", "--registry", REGISTRY)["did_aw"]
    invite = aw(owner, "id", "team", "invite", "--team", TEAM, "--namespace", DOMAIN, "--member-global")
    aw(owner, "id", "team", "accept-invite", invite["token"], "--name", "owner", "--global")
    aw(owner, "init", "--url", AWEB, "--name", "owner", "--do-not-touch-agents-md")

    # The fixture app, installed as its owner installs it.
    write_service_member(lane, owner)
    lane.up("secrets", "front")
    assert aw(owner, "plugin", "install", API)["approved"]

    # The protected server's ordinary member credential (never the controller).
    from nacl.signing import SigningKey  # noqa: PLC0415

    member_key = SigningKey.generate()
    added = aw(owner, "id", "team", "add-member", "--team", TEAM, "--namespace", DOMAIN,
               "--did", did_key_of(bytes(member_key).hex()), "--name", "protected-reader", "--global")
    assert added["certificate_id"]
    member_dir = lane.runtime / "protected" / "private-member"
    member_dir.mkdir(parents=True)
    (member_dir / "member.pem").write_text(
        "-----BEGIN ED25519 PRIVATE KEY-----\n" + base64.b64encode(bytes(member_key)).decode()
        + "\n-----END ED25519 PRIVATE KEY-----\n")
    (member_dir / "members.json").write_text(json.dumps({TEAM_ID: "member.pem"}))

    # Team administration is done: the controller key leaves both machines for
    # the protected server's custody volume, as the protected uid, mode 0400.
    seed = seed_hex(team_key.read_text())
    team_key.unlink()
    stored = subprocess.run(
        ["docker", "compose", "-p", lane.project, "-f", str(REPO / "naapp/secrets/docker-compose.e2e.yml"),
         "--profile", "protected", "run", "--rm", "-T", "--no-deps", "--entrypoint", "sh", "protected", "-c",
         "umask 077 && chmod 700 /private-controller && cat > /private-controller/controller.key "
         "&& chmod 400 /private-controller/controller.key"],
        env=lane.env, text=True, capture_output=True, input=seed + "\n", timeout=120, check=False)
    assert stored.returncode == 0, stored.stderr

    # The operator profile, its one binding, and the process configuration.
    scope = {"v": 1, "kind": "protected_key", "service_id": SERVICE_ID,
             "authority": {"kind": "team_controller", "id": TEAM_ID, "domain": DOMAIN},
             "human": {"id": approver, "domain": DOMAIN}, "generation": 1}
    config = lane.runtime / "protected" / "config"
    config.mkdir(parents=True)
    (config / "profile.json").write_text(json.dumps({
        "v": 1, "service_id": SERVICE_ID, "request_origin": SIGNER, "human_origin": HUMAN, "rp_id": "human.svc.test",
        "registry_origin": REGISTRY,
        "namespace_authorities": [{"domain": DOMAIN, "controller_did": prepared["controller_did"]}],
        "bindings": [{"scope": scope, "authority_key_did": did_key_of(seed),
                      "policy": {"ref": "aweb.human-assurance/1", "version": 1}}],
    }))
    (config / "scope.json").write_text(json.dumps(scope))
    (config / "smtp-password").write_text(secrets.token_urlsafe(16))
    for path in [*config.iterdir(), *member_dir.iterdir()]:
        path.chmod(0o644)
    (lane.runtime / "protected.env").write_text("".join(f"{k}={v}\n" for k, v in {
        "AWEB_PROTECTED_PROFILE_FILE": "/config/profile.json",
        "AWEB_PROTECTED_SCOPE_FILE": "/config/scope.json",
        "AWEB_PROTECTED_DATABASE_URL": "postgresql://secrets:disposable@postgres:5432/secrets",
        "AWEB_PROTECTED_DATABASE_SCHEMA": "protected_signer",
        "AWEB_PROTECTED_CONTROLLER_KEY_FILE": "/private-controller/controller.key",
        "AWEB_PROTECTED_MEMBER_KEYS_FILE": "/private-member/members.json",
        "AWEB_PROTECTED_WORKER_UIDS": "[1002]",
        "AWEB_PROTECTED_EMAIL_SMTP_HOST": "mail.svc.test",
        "AWEB_PROTECTED_EMAIL_SMTP_PORT": "1025",
        "AWEB_PROTECTED_EMAIL_USERNAME": "lane",
        "AWEB_PROTECTED_EMAIL_FROM": "signer@h.test",
        "AWEB_PROTECTED_EMAIL_PASSWORD_FILE": "/config/smtp-password",
        "AWEB_PROTECTED_EMAIL_CA_FILE": "/runtime/tls/ca.pem",
        "SSL_CERT_FILE": "/runtime/tls/ca.pem",
    }.items()))

    # HOST.md provisioning: declared rows, then B3 enrolment with the
    # browser's own attestation on the human origin.
    lane.provision("setup", "--human-id", approver, "--requester", requester, "--contact", CONTACT)
    token = enrolment_token(lane, owner)
    options = lane.provision("options", "--token", token)
    (lane.runtime / "enrolment-options.json").write_text(json.dumps(options))
    lane.up("front")
    started = lane.protected("up", "-d", "protected")
    assert started.returncode == 0, started.stdout + started.stderr
    lane.chromium(owner, "enrol", "--origin", HUMAN, "--options", "/runtime/enrolment-options.json",
                  "--attestation", "/runtime/attestation.json", "--device", "/runtime/approver-device.json")
    lane.provision("complete", "--token", token, stdin=(lane.runtime / "attestation.json").read_text())

    saved = lane.runtime / "holder" / ".config" / "aw" / "governance"

    # 1. The round trip: aw prepares, the page logs the human in, then the
    # human approves the exact act aw printed, and aw reports its receipt.
    child, page, operation, digest = start_revoke(owner, approver)
    report = lane.chromium(owner, "approve", "--url", page, "--device", "/runtime/approver-device.json")
    assert report["states"] == ["login-required", "ready", "navigated"], report
    assert report["digest"] == digest and report["act"] == "human-role.revoke", report
    status, output = finish(child)
    assert status == 0, output
    receipt = first_json(output)
    assert (receipt["operation_id"], receipt["state"]) == (operation, "committed"), receipt
    assert lane.provision("evidence", "--operation-id", operation)[operation] == {"signed": True, "refusal_code": None}
    assert not (saved / f"{operation}.json").exists(), "a committed operation's saved request remains"

    # 2. No user verification, at the login and then at the approval: nothing
    # is signed, and the operation stays pending with its saved request.
    pending = []
    for phase in ("login", "approve"):
        child, page, operation, _ = start_revoke(owner, approver)
        report = lane.chromium(owner, "approve", "--url", page, "--device", "/runtime/approver-device.json",
                               f"--{phase}-uv", "no")
        assert "navigated" not in report["states"], report
        assert report["states"][-1] == ("login-required" if phase == "login" else "ready"), report
        child.sendintr()
        finish(child)
        assert lane.provision("evidence", "--operation-id", operation)[operation]["signed"] is False
        assert (saved / f"{operation}.json").exists()
        pending.append(operation)

    # 3. A changed act under the same operation id: a validly encoded intent
    # with another role, resent from aw's saved request. The service refuses
    # operation_conflict and signs nothing.
    changed = pending[0]
    record = json.loads((saved / f"{changed}.json").read_text())
    body = json.loads(base64.b64decode(record["body"]))
    body["subject"]["role"] = ROLE + "-other"
    record["body"] = base64.b64encode(json.dumps(body, separators=(",", ":"), sort_keys=True).encode()).decode()
    (saved / f"{changed}.json").write_text(json.dumps(record))
    refused = _docker("exec", owner, "aw", "--json", "app", "role", "resume", changed, "--protected-profile", PROFILE)
    assert refused.returncode != 0, refused.stdout
    assert first_json(refused.stdout)["error"]["code"] == "operation_conflict", refused.stdout
    assert lane.provision("evidence", "--operation-id", changed)[changed]["signed"] is False

    # 4. A lost prepare answer: the front drops the committed prepare's
    # response once. aw reads the receipt instead of preparing again, keeps
    # the request, and the resume completes the original operation with one
    # signature.
    caddyfile = lane.runtime / "front" / "Caddyfile"
    original = caddyfile.read_text()
    caddyfile.write_text(original.replace(
        "signer.svc.test:443 {\n",
        "signer.svc.test:443 {\n  @prepare {\n    method POST\n    path /protected-operations\n  }\n"
        "  reverse_proxy @prepare protected:8080 {\n    @answered status 2xx\n"
        "    handle_response @answered {\n      abort\n    }\n  }\n", 1))
    reload_front(lane)
    lost = _docker("exec", owner, "aw", "--json", "app", "role", "revoke", "secrets", "--role", ROLE, "--principal",
                   approver, "--protected-profile", PROFILE, "--approver", approver, timeout=240)
    caddyfile.write_text(original)
    reload_front(lane)
    assert lost.returncode != 0, lost.stdout
    assert first_json(lost.stdout)["error"]["code"] == "prepare_unconfirmed", lost.stdout
    operation = re.search(r"Preparing operation (\S+)", lost.stderr).group(1)
    assert (saved / f"{operation}.json").exists()
    child = pexpect.spawn("docker", ["exec", "-it", owner, "aw", "--json", "app", "role", "resume", operation,
                                     "--protected-profile", PROFILE], encoding="utf-8", timeout=180, echo=False)
    child.expect(r"Approve it on this page: (\S+)")
    report = lane.chromium(owner, "approve", "--url", child.match.group(1), "--device", "/runtime/approver-device.json")
    assert report["states"] == ["login-required", "ready", "navigated"], report
    status, output = finish(child)
    assert status == 0, output
    receipt = first_json(output)
    assert (receipt["operation_id"], receipt["state"]) == (operation, "committed"), receipt
    assert lane.provision("evidence", "--operation-id", operation)[operation] == {"signed": True, "refusal_code": None}


def reload_front(lane: ProtectedLane) -> None:
    front = lane.compose("ps", "-q", "front").stdout.strip()
    reloaded = _docker("exec", front, "caddy", "reload", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile")
    assert reloaded.returncode == 0, reloaded.stderr
