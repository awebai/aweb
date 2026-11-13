"""The H owner-acts journey with the real aw, end to end (make e2e only).

Real: AWID with DNS verification, aweb, CoreDNS, SMTP, this app's production
image behind TLS on two public hostnames, the aw binary, the holder's human key
in a real Secret Service, and the shared handoff page and routes. The only
stand-in is the person: a software authenticator drives the page's JSON routes
from the holder's own network namespace, so aw's loopback receives the code.

Topology, as on H: the holder (a human) runs aw on their own machine, where the
browser is; the team owner signs with the team's controller key on another.
Setup authority (the namespace key that creates the team) is used only to set
the lane up, and the team key is then moved to the controller's machine.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pexpect
import pytest
from aweb_naapp_testing.network import make_certificates
from nacl.signing import SigningKey
from protected_round_trip import Holder as SharedHolder
from protected_round_trip import aw, aw_refused, first_json
from protected_round_trip import await_awid_txt as shared_await_awid_txt
from protected_round_trip import docker as _docker

pytestmark = pytest.mark.e2e

APP_DIR = Path(__file__).resolve().parents[1]
REPO = APP_DIR.parents[1]
DOMAIN = "h.test"
TEAM = "h"
# The lane's own app id: only the hosted origin may serve the hosted id "secrets".
APP_ID = "lane-secrets"
TEAM_ID = f"{TEAM}:{DOMAIN}"
REGISTRY = "http://awid.svc.test:8010"
AWEB = "http://aweb.svc.test:8000"
API = "https://api.secrets.svc.test"
CONSOLE = "https://console.secrets.svc.test"
ROLE = "secrets.owner"


@dataclass
class Lane:
    project: str
    runtime: Path
    env: dict[str, str]

    def compose(self, *args: str, timeout: int = 900) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["docker", "compose", "-p", self.project, "-f", str(APP_DIR / "docker-compose.e2e.yml"), *args],
            cwd=APP_DIR, env=self.env, text=True, capture_output=True, timeout=timeout, check=False,
        )

    def up(self, *services: str) -> None:
        result = self.compose("up", "-d", "--build", "--wait", *services)
        if result.returncode != 0:
            # The services' own last words, before the fixture's down -v.
            logs = self.compose("logs", "--no-color", "--tail", "60", *services)
            raise AssertionError(result.stderr[-4000:] + "\n--- service logs ---\n" + logs.stdout + logs.stderr)

    def machine(self, name: str) -> str:
        """Start a cli container as one person's machine; its HOME is /runtime/<name>."""
        container = f"{self.project}-{name}"
        (self.runtime / name).mkdir(mode=0o700)
        # The machine runs as the host user who owns the runtime directory, so
        # aw accepts the homes the test prepares there and the test can read
        # what aw writes. dbus needs that user in the passwd database.
        uid, gid = os.getuid(), os.getgid()
        accounts = self.runtime / "accounts"
        if not accounts.exists():
            accounts.mkdir(mode=0o755)
            (accounts / "passwd").write_text(f"root:x:0:0:root:/root:/bin/sh\nlane:x:{uid}:{gid}:lane:/runtime:/bin/sh\n")
            (accounts / "group").write_text(f"root:x:0:\nlane:x:{gid}:\n")
            for path in accounts.iterdir():
                path.chmod(0o644)
        result = self.compose(
            "run", "-d", "--name", container, "--user", f"{uid}:{gid}",
            "-v", f"{accounts / 'passwd'}:/etc/passwd:ro", "-v", f"{accounts / 'group'}:/etc/group:ro",
            "-e", f"HOME=/runtime/{name}", "-w", f"/runtime/{name}", "cli",
        )
        assert result.returncode == 0, result.stdout + result.stderr
        return container


def publish_awid_txt(lane: Lane, controller_did: str) -> None:
    zone = lane.runtime / "dns" / f"{DOMAIN}.zone"
    serial = int(time.time())
    zone.with_suffix(".tmp").write_text(
        f"$ORIGIN {DOMAIN}.\n$TTL 1\n"
        f"@ IN SOA ns.{DOMAIN}. hostmaster.{DOMAIN}. ({serial} 1 1 1 1)\n"
        f"@ IN NS ns.{DOMAIN}.\nns IN A 127.0.0.1\n"
        f'_awid IN TXT "awid=v1; controller={controller_did}; registry={REGISTRY};"\n'
    )
    zone.with_suffix(".tmp").replace(zone)


def await_awid_txt(machine: str, controller_did: str) -> None:
    shared_await_awid_txt(machine, DOMAIN, controller_did)


class Holder(SharedHolder):
    """The holder's machine, with the holder's own browser for this journey."""

    def __init__(self, lane: Lane, container: str) -> None:
        super().__init__(container, DOMAIN)
        self.lane = lane

    def browser(self, page: str, purpose: str, *, page_check: bool) -> None:
        """The holder's browser, in the holder's network namespace."""
        args = [
            "run", "--rm", f"--network=container:{self.container}",
            f"--volume={self.lane.runtime}:/runtime", f"{self.lane.project}-browser",
            "--page", page, "--purpose", purpose, "--device", "/runtime/holder/authenticator.json",
            "--ca", "/runtime/tls/ca.pem",
        ]
        if not page_check:
            args.append("--no-page")
        result = _docker(*args, timeout=180)
        assert result.returncode == 0, result.stdout + result.stderr


@pytest.fixture(scope="module")
def lane(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Lane]:
    if os.environ.get("SECRETS_E2E") != "1":
        pytest.skip("make e2e only")
    project = os.environ.get("NAAPP_E2E_PROJECT", "secrets-owner-acts-e2e")
    runtime = tmp_path_factory.mktemp("owner-acts")
    runtime.chmod(0o755)
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, text=True, capture_output=True, check=True).stdout.strip()
    lane = Lane(project, runtime, {**os.environ, "SECRETS_E2E_RUNTIME": str(runtime), "SECRETS_E2E_SOURCE_COMMIT": commit,
                                       "SECRETS_E2E_AWID_SERVICE_TOKEN": secrets.token_hex(32)})

    (runtime / "dns").mkdir()
    (runtime / "dns" / "Corefile").write_text(
        f"{DOMAIN}:53 {{\n  errors\n  file /zones/{DOMAIN}.zone {DOMAIN} {{ reload 1s }}\n}}\n"
        ".:53 {\n  errors\n  forward . 127.0.0.11\n}\n"
    )
    publish_awid_txt(lane, "did:key:z6MkpendingpendingpendingpendingpendingpendingpendingP")
    (runtime / "tls").mkdir()
    tls = make_certificates(runtime / "tls", ["api.secrets.svc.test", "console.secrets.svc.test"], [])
    (runtime / "front").mkdir()
    (runtime / "front" / "Caddyfile").write_text(
        "{\n  auto_https off\n}\n"
        + "".join(
            f"{host}:443 {{\n  tls /tls/{tls.cert_file.name} /tls/{tls.key_file.name}\n  reverse_proxy secrets:8770\n}}\n"
            for host in ("api.secrets.svc.test", "console.secrets.svc.test")
        )
    )
    try:
        lane.up("dns")
        dns = lane.compose("ps", "-q", "dns").stdout.strip()
        ip = _docker("inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", dns).stdout.strip()
        assert ip, "no DNS address"
        lane.env["SECRETS_E2E_DNS_IP"] = ip
        lane.up("postgres", "redis", "awid", "aweb", "smtp")
        result = lane.compose("--profile", "browser", "build", "cli", "browser")
        assert result.returncode == 0, result.stdout + result.stderr
        _docker("tag", f"{project}-browser", f"{project}-browser")
        yield lane
    finally:
        lane.compose("--profile", "browser", "down", "-v", "--remove-orphans")
        for name in ("controller", "holder"):
            _docker("rm", "-f", f"{project}-{name}")


def grant_install_owner(lane: Lane, did_key: str) -> None:
    """The server operator's local bootstrap of the team's first installation
    owner. Membership grants no install authority; only this does."""
    granted = lane.compose("exec", "-T", "aweb", "aweb", "install-admin", "grant", "--team-id", TEAM_ID,
                           "--principal-did", did_key, "--role", "owner")
    assert granted.returncode == 0, granted.stdout + granted.stderr


def write_service_member(lane: Lane, controller: str) -> None:
    """The app's own team member credential (no AWID service token), and its config."""
    keys = lane.runtime / "keys"
    keys.mkdir(mode=0o755)
    service_key = SigningKey.generate()
    from awid.did import did_from_public_key  # noqa: PLC0415

    did = did_from_public_key(bytes(service_key.verify_key))
    added = aw(controller, "id", "team", "add-member", "--team", TEAM, "--namespace", DOMAIN,
               "--did", did, "--name", "secrets-service", "--global")
    pem = (
        "-----BEGIN ED25519 PRIVATE KEY-----\n"
        + __import__("base64").b64encode(bytes(service_key)).decode()
        + "\n-----END ED25519 PRIVATE KEY-----\n"
    )
    (keys / "member.pem").write_text(pem)
    # The member fetches its own certificate with its key alone, as any
    # member does (aw id team fetch-cert), in an identity home of its own.
    home = keys / "service-home"
    home.mkdir(mode=0o700)
    (home / "signing.key").write_text(pem)
    (home / "signing.key").chmod(0o600)
    fetched = aw(controller, "--identity-home", "/runtime/keys/service-home", "id", "team", "fetch-cert",
                 "--namespace", DOMAIN, "--team", TEAM, "--cert-id", added["certificate_id"], "--registry", REGISTRY)
    shutil.copyfile(home / fetched["cert_path"], keys / "member-cert.json")
    for name in ("custody", "request", "params", "response", "runner", "smtp", "manifest", "event", "delivery", "grant", "resolve"):
        # The app's shared key-file format: 64 hex characters, each independent.
        (keys / name).write_text(secrets.token_hex(32) + "\n")
    for path in keys.iterdir():
        path.chmod(0o644)
    env = {
        "SECRETS_DATABASE_URL": "postgresql://secrets:disposable@postgres:5432/secrets",
        "SECRETS_DB_SCHEMA": "secrets",
        "SECRETS_APP_ID": APP_ID,
        "SECRETS_PUBLIC_ORIGIN": API,
        "SECRETS_CONSOLE_ORIGIN": CONSOLE,
        "SECRETS_AWID_REGISTRY_URL": REGISTRY,
        "SECRETS_AWID_MEMBER_CREDENTIALS": json.dumps({TEAM_ID: {
            "signing_key_file": "/run/secrets-keys/member.pem",
            "certificate_file": "/run/secrets-keys/member-cert.json"}}),
        "SECRETS_AUTH_CACHE_TTL_SECONDS": "1",
        "SECRETS_CUSTODY_KEY_FILE": "/run/secrets-keys/custody",
        "SECRETS_SECRET_REQUEST_KEY_FILE": "/run/secrets-keys/request",
        "SECRETS_SECRET_PARAMS_KEY_FILE": "/run/secrets-keys/params",
        "SECRETS_RESPONSE_KEY_FILE": "/run/secrets-keys/response",
        "SECRETS_RUNNER_SERVICE_KEY_FILE": "/run/secrets-keys/runner",
        "SECRETS_MANIFEST_REQUEST_KEY_FILE": "/run/secrets-keys/manifest",
        "SECRETS_APP_KEY_FILES": json.dumps({
            "secrets.hook-event-1": "/run/secrets-keys/event",
            "secrets.hook-delivery-1": "/run/secrets-keys/delivery",
            "secrets:grant-read-1": "/run/secrets-keys/grant",
            "secrets:hook-resolve-1": "/run/secrets-keys/resolve"}),
        "SECRETS_EMAIL_SMTP_HOST": "smtp.svc.test",
        "SECRETS_EMAIL_SMTP_PORT": "1025",
        "SECRETS_EMAIL_USERNAME": "lane",
        "SECRETS_EMAIL_PASSWORD_FILE": "/run/secrets-keys/smtp",
        "SECRETS_EMAIL_FROM": "secrets@svc.test",
        "SECRETS_EGRESS_DENIED_NETWORKS": "[]",
    }
    (lane.runtime / "secrets.env").write_text("".join(f"{k}={v}\n" for k, v in env.items()))


def test_the_owner_designates_a_human_holder_registered_on_another_machine(lane: Lane) -> None:
    controller = lane.machine("controller")
    holder = Holder(lane, lane.machine("holder"))

    # Setup authority: the namespace, its root human (the holder) and the team.
    prepared = aw(holder.container, "id", "namespace", "prepare-controller", "--domain", DOMAIN, "--registry", REGISTRY)
    publish_awid_txt(lane, prepared["controller_did"])
    await_awid_txt(holder.container, prepared["controller_did"])
    child = holder.spawn("--json", "id", "human", "init", "--domain", DOMAIN, "--as-root")
    output = holder.answer_passphrases(child)
    child.close()
    assert child.exitstatus == 0, output
    human = first_json(output)
    principal = human["id"]
    aw(holder.container, "id", "team", "create", "--name", TEAM, "--namespace", DOMAIN, "--registry", REGISTRY)

    # The team key moves to the owner's machine; the holder keeps none.
    team_key = lane.runtime / "holder" / ".awid" / "team-keys" / DOMAIN / f"{TEAM}.key"
    owner_keys = lane.runtime / "controller" / ".awid" / "team-keys" / DOMAIN
    owner_keys.mkdir(parents=True)
    shutil.move(str(team_key), owner_keys / f"{TEAM}.key")

    # The owner's own agent identity and membership, then the holder's.
    owner = aw(controller, "id", "create", "--name", "owner", "--domain", DOMAIN, "--root-parent", "--registry", REGISTRY)
    invite = aw(controller, "id", "team", "invite", "--team", TEAM, "--namespace", DOMAIN, "--member-global")
    aw(controller, "id", "team", "accept-invite", invite["token"], "--name", "owner", "--global")
    aw(controller, "init", "--url", AWEB, "--name", "owner", "--do-not-touch-agents-md")
    added = aw(controller, "id", "team", "add-member", "--team", TEAM, "--namespace", DOMAIN,
               "--did", human["did_key"], "--did-aw", principal, "--name", "holder", "--global")
    child = holder.act(principal, "--json", "id", "team", "fetch-cert",
                         "--namespace", DOMAIN, "--team", TEAM, "--cert-id", added["certificate_id"], "--registry", REGISTRY)
    output = holder.answer_passphrases(child)
    child.close()
    assert child.exitstatus == 0, output

    # The app, as its owner installs it.
    write_service_member(lane, controller)
    lane.up("secrets", "front")
    grant_install_owner(lane, owner["did_key"])
    installed = aw(controller, "plugin", "install", API)
    assert installed["approved"], installed
    # The holder's machine installs the app host-only: plugin install is not a
    # human act, and with no agent identity here nothing is registered. Then
    # the human connects to this server, so its --human commands reach it.
    aw(holder.container, "plugin", "install", API)
    child = holder.act(principal, "init", "--url", AWEB)
    output = holder.answer_passphrases(child)
    child.close()
    assert child.exitstatus == 0, output

    # The holder registers a passkey on their own machine and exports it.
    child = holder.act(principal, "app", "credential", "register",
                         APP_ID, "--role", ROLE, "--out", "/runtime/holder/export.json")
    output = holder.answer_passphrases(child, until=r"Open this page to continue: (\S+)")
    page = re.search(r"Open this page to continue: (\S+)", output).group(1)
    assert page.startswith(CONSOLE + "/handoff/"), page
    holder.browser(page, "credential", page_check=False)
    child.expect(pexpect.EOF)
    rest = child.before
    child.close()
    assert child.exitstatus == 0, rest
    fingerprint = re.search(r"Fingerprint: ([0-9a-f]{4} [0-9a-f]{4} [0-9a-f]{4} [0-9a-f]{4})", output + rest).group(1)

    # The owner signs only for that exact credential: the fingerprint matches.
    shutil.copyfile(lane.runtime / "holder" / "export.json", lane.runtime / "controller" / "export.json")
    result = _docker("exec", controller, "aw", "app", "role", "designate", APP_ID, "--role", ROLE,
                     "--principal", principal, "--credential", "/runtime/controller/export.json", "--yes", timeout=300)
    assert result.returncode == 0, result.stdout + result.stderr
    assert fingerprint in result.stderr, result.stderr
    assert "human-role.designate" in result.stdout

    # A second designation of the same holding is refused by the app.
    code = aw_refused(controller, "app", "role", "designate", APP_ID, "--role", ROLE, "--principal", principal,
                      "--credential", "/runtime/controller/export.json", "--yes")
    assert code == "owner_required", code

    # The holder holds the role: a session handoff starts for it.
    child = holder.act(principal, "--json", "app", "human", APP_ID, "--help")
    listed = holder.answer_passphrases(child)
    assert "confirm" in listed and "draft-change" in listed, listed
