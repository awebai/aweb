"""The H owner-acts journey with the real aw, end to end (make e2e only).

Real: AWID with DNS verification, aweb, CoreDNS, SMTP, this app's production
image behind TLS on two public hostnames, the Logs app as a team deployment
runs it (the audit target a designation's governance needs), the aw binary,
the holder's human key in a real Secret Service, and the shared handoff page
and routes. The only stand-in is the person: a software authenticator drives
the page's JSON routes from the holder's own network namespace, so aw's
loopback receives the code.

The owner signs the designation locally, so aw keeps no request to replay:
its proof is the app's own records (protected_round_trip.assert_designated),
and a refused duplicate leaves them unchanged.

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
from protected_round_trip import (
    Designation,
    Holding,
    activate_hooks,
    assert_designated,
    assert_unchanged,
    aw,
    aw_refused,
    credential_sha256,
    designate_command,
    designation_snapshot,
    first_json,
    install_app,
    publish_team_server,
    read_only_psql,
)
from protected_round_trip import Holder as SharedHolder
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
# The lane's Logs, and the network both apps' hooks stay inside.
LOGS_APP_ID = "lane-logs"
LOGS_API = "https://api.logs.svc.test"
LOGS_CONSOLE = "https://console.logs.svc.test"
LANE_SUBNET = "172.31.240.0/24"
# The lane's Secrets keeps its records in this schema of the lane's database.
SECRETS_SCHEMA = "secrets"
# The notice contact the owner designates the holder with.
CONTACT = "holder@h.test"
# Every setting the Logs base service names, as a deployment's .env gives
# them: Compose reads them when it loads the file, for every lane command.
LOGS_COMPOSE_ENV = {
    "LOGS_APP_ID": LOGS_APP_ID,
    "LOGS_PUBLIC_ORIGIN": LOGS_API,
    "LOGS_CONSOLE_ORIGIN": LOGS_CONSOLE,
    "TEAM_ID": TEAM_ID,
    "AWID_REGISTRY_URL": REGISTRY,
    "LOGS_EMAIL_SMTP_HOST": "mail.svc.test",
    "LOGS_EMAIL_SMTP_PORT": "1025",
    "LOGS_EMAIL_FROM": "logs@svc.test",
    "LOGS_EMAIL_CA_FILE": "/runtime/tls/ca.pem",
    "LOGS_EGRESS_DENIED_NETWORKS": "[]",
}
# What the TLS front serves, and the service behind each host.
UPSTREAMS = {
    "api.secrets.svc.test": "secrets:8770",
    "console.secrets.svc.test": "secrets:8770",
    "api.logs.svc.test": "logs:8765",
    "console.logs.svc.test": "logs:8765",
}


def front_caddyfile(upstreams: dict[str, str], cert: str, key: str) -> str:
    """The TLS front's configuration: each host on 443 with the lane's
    certificate, proxied to its service with the public Host kept."""
    return "{\n  auto_https off\n}\n" + "".join(
        f"{host}:443 {{\n  tls /tls/{cert} /tls/{key}\n  reverse_proxy {target}\n}}\n"
        for host, target in upstreams.items()
    )


def write_tls(runtime: Path, hosts: list[str]) -> tuple[str, str]:
    """The lane's certificate for every host, and the TLS mail transport's
    copy of it; all public to the lane's containers. Returns the
    certificate's and key's file names."""
    (runtime / "tls").mkdir()
    tls = make_certificates(runtime / "tls", hosts, [])
    shutil.copyfile(tls.cert_file, runtime / "tls" / "smtp.pem")
    shutil.copyfile(tls.key_file, runtime / "tls" / "smtp-key.pem")
    for path in (runtime / "tls").iterdir():
        path.chmod(0o644)
    return tls.cert_file.name, tls.key_file.name


def secrets_env() -> dict[str, str]:
    """The lane's Secrets settings: its own member credential (no AWID
    service token), its key files, its mail, and its hook events to the
    lane's Logs, inside the lane's network."""
    return {
        "SECRETS_DATABASE_URL": "postgresql://secrets:disposable@postgres:5432/secrets",
        "SECRETS_DB_SCHEMA": SECRETS_SCHEMA,
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
        "SECRETS_HOOK_INTERNAL_ORIGINS": json.dumps([LOGS_API]),
        "SECRETS_HOOK_INTERNAL_DESTINATIONS": "allowed",
        "SECRETS_HOOK_INTERNAL_CIDR": LANE_SUBNET,
        "SECRETS_HOOK_CA_FILE": "/run/secrets-keys/hook-ca.pem",
    }


def machine_dir(name: str) -> str:
    """A machine's HOME and working directory, as the machine sees it."""
    return f"/runtime/{name}"


def identity_folder(name: str) -> str:
    """The identity folder aw selects in a machine: its working directory's .aw."""
    return f"{machine_dir(name)}/.aw"


@dataclass
class Lane:
    project: str
    runtime: Path
    env: dict[str, str]

    def compose(self, *args: str, timeout: int = 900) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["docker", "compose", "-p", self.project, "-f", str(APP_DIR / "docker-compose.e2e.yml"),
             "--profile", "logs", *args],
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
            "-e", f"HOME={machine_dir(name)}", "-w", machine_dir(name), "cli",
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
                                       "SECRETS_E2E_AWID_SERVICE_TOKEN": secrets.token_hex(32), **LOGS_COMPOSE_ENV})

    (runtime / "dns").mkdir()
    (runtime / "dns" / "Corefile").write_text(
        f"{DOMAIN}:53 {{\n  errors\n  file /zones/{DOMAIN}.zone {DOMAIN} {{ reload 1s }}\n}}\n"
        ".:53 {\n  errors\n  forward . 127.0.0.11\n}\n"
    )
    publish_awid_txt(lane, "did:key:z6MkpendingpendingpendingpendingpendingpendingpendingP")
    cert, key = write_tls(runtime, [*UPSTREAMS, "mail.svc.test"])
    (runtime / "front").mkdir()
    (runtime / "front" / "Caddyfile").write_text(front_caddyfile(UPSTREAMS, cert, key))
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
        # Every service's own record of the run, kept beside the runtime.
        logs = lane.compose("logs", "--no-color", "--timestamps")
        (runtime / "compose.log").write_text(logs.stdout + logs.stderr)
        lane.compose("--profile", "browser", "down", "-v", "--remove-orphans")
        for name in ("controller", "holder"):
            _docker("rm", "-f", f"{project}-{name}")


def grant_install_owner(lane: Lane, did_key: str) -> None:
    """The server operator's local bootstrap of the team's first installation
    owner. Membership grants no install authority; only this does."""
    granted = lane.compose("exec", "-T", "aweb", "aweb", "install-admin", "grant", "--team-id", TEAM_ID,
                           "--principal-did", did_key, "--role", "owner")
    assert granted.returncode == 0, granted.stdout + granted.stderr


def admit_app_member(lane: Lane, controller: str, name: str, home: Path) -> tuple[str, Path]:
    """One app as an ordinary member of the team: its key, the owner's
    add-member, and the member's own fetch of its certificate with its key
    alone, as any member does, in an identity home of its own under the
    runtime. Returns the key's PEM and the certificate's path."""
    key = SigningKey.generate()
    from awid.did import did_from_public_key  # noqa: PLC0415

    did = did_from_public_key(bytes(key.verify_key))
    added = aw(controller, "id", "team", "add-member", "--team", TEAM, "--namespace", DOMAIN,
               "--did", did, "--name", name, "--global")
    pem = (
        "-----BEGIN ED25519 PRIVATE KEY-----\n"
        + __import__("base64").b64encode(bytes(key)).decode()
        + "\n-----END ED25519 PRIVATE KEY-----\n"
    )
    home.mkdir(mode=0o700)
    (home / "signing.key").write_text(pem)
    (home / "signing.key").chmod(0o600)
    fetched = aw(controller, "--identity-home", f"/runtime/{home.relative_to(lane.runtime)}", "id", "team",
                 "fetch-cert", "--namespace", DOMAIN, "--team", TEAM, "--cert-id", added["certificate_id"],
                 "--registry", REGISTRY)
    return pem, home / fetched["cert_path"]


def write_service_member(lane: Lane, controller: str) -> None:
    """The app's own team member credential (no AWID service token), and its config."""
    keys = lane.runtime / "keys"
    keys.mkdir(mode=0o755)
    pem, certificate = admit_app_member(lane, controller, "secrets-service", keys / "service-home")
    (keys / "member.pem").write_text(pem)
    shutil.copyfile(certificate, keys / "member-cert.json")
    for name in ("custody", "request", "params", "response", "runner", "smtp", "manifest", "event", "delivery", "grant", "resolve"):
        # The app's shared key-file format: 64 hex characters, each independent.
        (keys / name).write_text(secrets.token_hex(32) + "\n")
    # The lane's CA, which the app's hook deliveries to the lane's Logs trust.
    shutil.copyfile(lane.runtime / "tls" / "ca.pem", keys / "hook-ca.pem")
    for path in keys.iterdir():
        path.chmod(0o644)
    (lane.runtime / "secrets.env").write_text("".join(f"{k}={v}\n" for k, v in secrets_env().items()))


def write_logs_files(lane: Lane, controller: str) -> None:
    """The lane's Logs files, which the base service names: its member key
    and certificate, its own keys, its mail credentials and the URLs of its
    content and purge-ledger databases, each its own database."""
    files = lane.runtime / "logs"
    files.mkdir(mode=0o755)
    pem, certificate = admit_app_member(lane, controller, "logs-service", lane.runtime / "logs-member")
    (files / "awid-member-key").write_text(pem)
    shutil.copyfile(certificate, files / "awid-member-certificate")
    for name in ("logs-chain", "logs-resolve", "logs-grants", "logs-governance"):
        (files / name).write_text(secrets.token_hex(32) + "\n")
    (files / "smtp-username").write_text("logs-service")
    (files / "smtp-password").write_text(secrets.token_urlsafe(16))
    (files / "database-url").write_text("postgresql://secrets:disposable@postgres:5432/logs\n")
    (files / "purge-ledger-database-url").write_text("postgresql://secrets:disposable@postgres:5432/logsledger\n")
    for path in files.iterdir():
        path.chmod(0o644)


def create_logs_databases(lane: Lane) -> None:
    for database in ("logs", "logsledger"):
        created = lane.compose("exec", "-T", "postgres", "psql", "-U", "secrets", "-d", "secrets", "-v",
                               "ON_ERROR_STOP=1", "-c", f"CREATE DATABASE {database}")
        assert created.returncode == 0, created.stdout + created.stderr


def start_apps(lane: Lane, controller: str) -> None:
    """The lane's Secrets and Logs, with their members, files and databases,
    behind the TLS front."""
    write_service_member(lane, controller)
    write_logs_files(lane, controller)
    create_logs_databases(lane)
    lane.up("secrets", "logs", "front")


def install_apps(lane: Lane, controller: str, owner_did_key: str) -> None:
    """The owner publishes the team's coordination server, the operator
    grants the owner installation, and the owner installs Secrets and Logs
    from their internal origins."""
    publish_team_server(controller, TEAM, DOMAIN, AWEB, REGISTRY)
    grant_install_owner(lane, owner_did_key)
    install_app(controller, API)
    install_app(controller, LOGS_API)


def secrets_query(lane: Lane):
    def query(select: str) -> str:
        result = lane.compose("exec", "-T", "postgres", *read_only_psql("secrets", "secrets", select))
        assert result.returncode == 0, result.stdout + result.stderr
        return result.stdout.strip()
    return query


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

    # The owner's own agent identity: the namespace root issues it on the
    # holder's machine, where its controller key is, straight into the
    # owner's machine's identity folder (a fresh explicit target). Only the
    # owner's own key and certificate land there; the namespace controller key
    # stays where it is.
    owner = aw(holder.container, "--identity-home", identity_folder("controller"), "id", "create", "--name", "owner",
               "--domain", DOMAIN, "--root-parent", "--registry", REGISTRY)
    # Then the owner's membership, and the holder's.
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

    # The apps, as their owner installs them, from their internal origins.
    start_apps(lane, controller)
    install_apps(lane, controller, owner["did_key"])
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
    exported = json.loads((lane.runtime / "holder" / "export.json").read_text())

    # The designation's governance needs its audit target: the owner
    # activates the apps' hook bindings and waits until they are in effect.
    hooks = activate_hooks(controller, {"secrets": APP_ID, "logs": LOGS_APP_ID})
    installed = hooks["active"]["secrets/production/post-governance-hook"]
    holding = Holding(app_id=APP_ID, installation_id=installed["installation_id"],
                      generation=installed["generation"], team_id=TEAM_ID, role=ROLE, principal=principal)
    designation = Designation(holding=holding, audience=CONSOLE,
                              credential_sha256=credential_sha256(exported["credential"]), contact=CONTACT)
    query = secrets_query(lane)
    baseline = designation_snapshot(query, holding, schema=SECRETS_SCHEMA)

    # The owner signs only for that exact credential: the fingerprint matches.
    shutil.copyfile(lane.runtime / "holder" / "export.json", lane.runtime / "controller" / "export.json")
    command = designate_command(APP_ID, ROLE, principal, "/runtime/controller/export.json", CONTACT)
    result = _docker("exec", controller, *command, timeout=300)
    assert result.returncode == 0, result.stdout + result.stderr
    assert fingerprint in result.stderr, result.stderr
    assert "human-role.designate" in result.stdout
    designated = designation_snapshot(query, holding, schema=SECRETS_SCHEMA)
    assert_designated(baseline, designated, designation)

    # A second designation of the same holding, a fresh act, is refused by
    # the app, and leaves its records as the first one left them.
    code = aw_refused(controller, *command[1:])
    assert code == "owner_required", code
    assert_unchanged(designated, designation_snapshot(query, holding, schema=SECRETS_SCHEMA))

    # The holder holds the role: a session handoff starts for it.
    child = holder.act(principal, "--json", "app", "human", APP_ID, "--help")
    listed = holder.answer_passphrases(child)
    assert "confirm" in listed and "draft-change" in listed, listed
