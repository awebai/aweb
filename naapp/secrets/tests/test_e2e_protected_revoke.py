"""The protected round trip: aw prepares, the human approves in a real browser.

First the approver's holding of the app role, made the supported way while
the owner still holds the team's key: the owner publishes the team's server,
installs Secrets and Logs, and designates the approver's passkey once the
hook bindings the designation's governance needs are in effect. Then the
signer is provisioned with the team controller key, and the shared body runs:
the refusals, then one human-role.revoke through the independent protected
server (aweb.protected_signing.host, HOST.md) whose prepare answer and first
delivery answer are lost; aw resumes it, the approving human approves the
exact act in a fresh Chromium tab, the server signs it once, aw delivers it
and the app applies it; the exact replay is answered applied earlier, and the
app's own records show one effect.

Real: AWID with DNS verification, aweb, the secrets app installed as a
disposable fixture app, the Logs app as a team deployment runs it, the
protected server image with ProtectedControllerCustody, the aw binary,
Chromium running the console page's own script. Substituted: the outbound
notification transport (a TLS mailpit read by this test), and the person (a
CDP virtual authenticator). Provisioning follows HOST.md through B3's own
enrolment APIs; nothing inserts a credential, session or success row.

make e2e only, in an aweb-placed exclusive window.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest
from protected_round_trip import (
    AnswerDrop,
    Site,
    connect_requester,
    designate_holding,
    first_json,
    found_team,
    provision_signer,
    refusals,
    revoke_once,
    secrets_holding,
)

from tests.test_e2e_owner_acts import (
    APP_ID,
    AWEB,
    DOMAIN,
    LOGS_APP_ID,
    LOGS_COMPOSE_ENV,
    REGISTRY,
    REPO,
    ROLE,
    SECRETS_SCHEMA,
    TEAM,
    TEAM_ID,
    UPSTREAMS,
    Holder,
    Lane,
    _docker,
    front_caddyfile,
    install_apps,
    publish_awid_txt,
    secrets_query,
    start_apps,
    write_tls,
)

pytestmark = pytest.mark.e2e

SIGNER = "https://signer.svc.test"
HUMAN = "https://human.svc.test"
SERVICE_ID = "e2e-protected"
PROFILE = "/runtime/protected/config/profile.json"
CONTACT = "approver@h.test"
# The lane's front, with the protected server on its request and human hosts.
PROTECTED_UPSTREAMS = {**UPSTREAMS, "signer.svc.test": "protected:8080", "human.svc.test": "protected:8080"}


class ProtectedLane(Lane):
    def protected(self, *args: str, timeout: int = 900) -> subprocess.CompletedProcess[str]:
        return self.compose("--profile", "protected", *args, timeout=timeout)

    def evidence(self, operation: str) -> dict:
        """What the protected server signed for one operation, read from its
        database inside its container as its uid."""
        result = subprocess.run(
            ["docker", "compose", "-p", self.project, "-f", str(REPO / "naapp/secrets/docker-compose.e2e.yml"),
             "--profile", "protected", "run", "--rm", "-T", "--no-deps", "--entrypoint", "python",
             "protected", "/evidence.py", "--operation-id", operation],
            env=self.env, text=True, capture_output=True, timeout=300, check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        return first_json(result.stdout)[operation]

    def chromium(self, machine: str, *args: str) -> dict:
        """The approving human's Chromium, in the requester's network namespace."""
        # As the host user, so the test reads what the driver writes; its NSS
        # database lives in a HOME of its own.
        result = _docker("run", "--rm", f"--network=container:{machine}", f"--volume={self.runtime}:/runtime",
                         f"--user={os.getuid()}:{os.getgid()}", "--env=HOME=/tmp",
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
                                       "SECRETS_E2E_AWID_SERVICE_TOKEN": secrets.token_hex(32), **LOGS_COMPOSE_ENV})

    (runtime / "dns").mkdir()
    (runtime / "dns" / "Corefile").write_text(
        f"{DOMAIN}:53 {{\n  errors\n  file /zones/{DOMAIN}.zone {DOMAIN} {{ reload 1s }}\n}}\n"
        ".:53 {\n  errors\n  forward . 127.0.0.11\n}\n"
    )
    publish_awid_txt(lane, "did:key:z6MkpendingpendingpendingpendingpendingpendingpendingP")
    cert, key = write_tls(runtime, [*PROTECTED_UPSTREAMS, "mail.svc.test"])
    (runtime / "front").mkdir()
    (runtime / "front" / "Caddyfile").write_text(front_caddyfile(PROTECTED_UPSTREAMS, cert, key))
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
        # Every service's own record of the run, kept beside the runtime.
        logs = lane.compose("--profile", "protected", "logs", "--no-color", "--timestamps")
        (runtime / "compose.log").write_text(logs.stdout + logs.stderr)
        lane.compose("--profile", "protected", "--profile", "chromium", "--profile", "browser",
                     "down", "-v", "--remove-orphans")
        for name in ("controller", "holder"):
            _docker("rm", "-f", f"{project}-{name}")


def protected_site(lane: ProtectedLane) -> Site:
    """The round trip's Site in this lane: the protected service runs from
    docker-compose.e2e.yml with its configuration under the runtime."""
    config = lane.runtime / "protected" / "config"
    member_dir = lane.runtime / "protected" / "private-member"

    def store_member(pem: str) -> None:
        member_dir.mkdir(parents=True)
        (member_dir / "member.pem").write_text(pem)
        (member_dir / "members.json").write_text(json.dumps({TEAM_ID: "member.pem"}))
        for path in member_dir.iterdir():
            path.chmod(0o644)

    def protected_run(*args: str, user: str | None = None, mounts: tuple[str, ...] = ()) -> str:
        command = ["docker", "compose", "-p", lane.project, "-f", str(REPO / "naapp/secrets/docker-compose.e2e.yml"),
                   "--profile", "protected", "run", "--rm", "-T", "--no-deps"]
        command += ["--user", user] if user else []
        for mount in mounts:
            command += ["-v", mount]
        result = subprocess.run([*command, *args], env=lane.env, text=True, capture_output=True, timeout=300,
                                check=False)
        assert result.returncode == 0, result.stdout + result.stderr
        return result.stdout

    def operator(*args: str, mounts: tuple[str, ...] = ()) -> dict:
        """The package's local administrator command, as the protected uid with
        the protected host's own settings."""
        return first_json(protected_run("--entrypoint", "python", "protected", "-m", "aweb.protected_signing.operator",
                                        *args, mounts=mounts))

    def install_controller(pem: Path) -> None:
        """HOST.md, controller key installation: the custody volume's directory
        made the protected uid's, mode 0700, by trusted provisioning; the
        owner's existing PEM in a short-lived source only that uid reads; the
        package command converts it."""
        protected_run("--entrypoint", "sh", "protected", "-c",
                      "chown 1001:1001 /private-controller && chmod 0700 /private-controller", user="0")
        source = lane.runtime / "private-provisioning"
        source.mkdir(mode=0o700)
        shutil.copyfile(pem, source / "team-controller.pem")
        _docker("run", "--rm", "-v", f"{source}:/p", "alpine:3.22", "sh", "-c",
                "chown -R 1001:1001 /p && chmod 0400 /p/team-controller.pem")
        try:
            operator("install-controller", "--source-pem", "/private-provisioning/team-controller.pem",
                     mounts=(f"{source}:/private-provisioning:ro",))
        finally:
            _docker("run", "--rm", "-v", f"{lane.runtime}:/r", "alpine:3.22", "rm", "-rf", "/r/private-provisioning")

    def signer_evidence(operation: str) -> dict:
        return lane.evidence(operation)

    def configure_signer(profile: dict, scope: dict) -> None:
        config.mkdir(parents=True)
        (config / "profile.json").write_text(json.dumps(profile))
        (config / "scope.json").write_text(json.dumps(scope))
        (config / "smtp-password").write_text(secrets.token_urlsafe(16))
        for path in config.iterdir():
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

    def start_signer() -> None:
        lane.up("front")
        started = lane.protected("up", "-d", "protected")
        assert started.returncode == 0, started.stdout + started.stderr

    caddyfile = lane.runtime / "front" / "Caddyfile"

    def drop_prepare_answers() -> AnswerDrop:
        return AnswerDrop(caddyfile, "signer.svc.test", "POST", "/protected-operations", "protected:8080",
                          lambda: reload_front(lane))

    def drop_owner_act_answers() -> AnswerDrop:
        return AnswerDrop(caddyfile, "console.secrets.svc.test", "POST", "/.well-known/aweb-owner-act",
                          "secrets:8770", lambda: reload_front(lane))

    def signatures() -> int:
        return int(secrets_query(lane)("SELECT count(*) FROM protected_signer.protected_signer_operations"
                                       " WHERE result IS NOT NULL"))

    return Site(
        runtime=lane.runtime, mounted="/runtime", domain=DOMAIN, team=TEAM, registry=REGISTRY, aweb=AWEB,
        signer=SIGNER, human=HUMAN, service_id=SERVICE_ID, app_id=APP_ID, logs_app_id=LOGS_APP_ID,
        secrets_schema=SECRETS_SCHEMA, role=ROLE, contact=CONTACT,
        mail_api="http://mail.svc.test:8025", profile_in_machine=PROFILE,
        publish_controller=lambda did: publish_awid_txt(lane, did), store_member=store_member,
        configure_signer=configure_signer, install_controller=install_controller, operator=operator,
        start_signer=start_signer, signer_evidence=signer_evidence,
        signer_access_log=lambda: lane.protected("logs", "--no-color", "--no-log-prefix", "protected").stdout,
        chromium=lane.chromium, drop_prepare_answers=drop_prepare_answers, signatures=signatures,
        drop_owner_act_answers=drop_owner_act_answers, secrets_query=secrets_query(lane),
        app_log=lambda: lane.compose("logs", "--no-color", "--no-log-prefix", "secrets").stdout,
    )


def test_a_human_approves_a_protected_revoke_in_a_real_browser(lane: ProtectedLane) -> None:
    site = protected_site(lane)
    holder = Holder(lane, lane.machine("holder"))
    founded = found_team(site, holder)
    connect_requester(site, holder)
    owner = holder.container

    # The apps, as their owner installs them, and the approver's holding,
    # designated before the signer holds the team's key.
    start_apps(lane, owner)
    install_apps(lane, owner, founded.requester_did_key)
    designated = designate_holding(site, holder, founded)

    provision_signer(site, holder, founded)
    refusals(site, holder, founded)
    revoke_once(site, holder, founded, secrets_holding(site, designated["hooks"], founded.approver))


def reload_front(lane: ProtectedLane) -> None:
    front = lane.compose("ps", "-q", "front").stdout.strip()
    reloaded = _docker("exec", front, "caddy", "reload", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile")
    assert reloaded.returncode == 0, reloaded.stderr
