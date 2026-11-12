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

import json
import os
import secrets
import shutil
import subprocess
from collections.abc import Iterator

import pytest
from aweb_naapp_testing.network import make_certificates
from protected_round_trip import (
    Site,
    aw,
    first_json,
    found_team,
    provision_signer,
    refusals,
    round_trip,
)

from tests.test_e2e_owner_acts import (
    API,
    APP_ID,
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
    grant_install_owner,
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

    def store_controller(seed: str) -> None:
        # The protected server's custody volume, as the protected uid, mode 0400.
        stored = subprocess.run(
            ["docker", "compose", "-p", lane.project, "-f", str(REPO / "naapp/secrets/docker-compose.e2e.yml"),
             "--profile", "protected", "run", "--rm", "-T", "--no-deps", "--entrypoint", "sh", "protected", "-c",
             "umask 077 && chmod 700 /private-controller && cat > /private-controller/controller.key "
             "&& chmod 400 /private-controller/controller.key"],
            env=lane.env, text=True, capture_output=True, input=seed + "\n", timeout=120, check=False)
        assert stored.returncode == 0, stored.stderr

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
    original: list[str] = []

    def drop_prepare_answers(on: bool) -> None:
        if on:
            original.append(caddyfile.read_text())
            caddyfile.write_text(original[0].replace(
                "signer.svc.test:443 {\n",
                "signer.svc.test:443 {\n  @prepare {\n    method POST\n    path /protected-operations\n  }\n"
                "  reverse_proxy @prepare protected:8080 {\n    @answered status 2xx\n"
                "    handle_response @answered {\n      abort\n    }\n  }\n", 1))
        else:
            caddyfile.write_text(original.pop())
        reload_front(lane)

    return Site(
        runtime=lane.runtime, mounted="/runtime", domain=DOMAIN, team=TEAM, registry=REGISTRY, aweb=AWEB,
        signer=SIGNER, human=HUMAN, service_id=SERVICE_ID, app_id=APP_ID, role=ROLE, contact=CONTACT,
        mail_api="http://mail.svc.test:8025", profile_in_machine=PROFILE,
        publish_controller=lambda did: publish_awid_txt(lane, did), store_member=store_member,
        store_controller=store_controller, configure_signer=configure_signer, provision=lane.provision,
        start_signer=start_signer, chromium=lane.chromium, drop_prepare_answers=drop_prepare_answers,
    )


def test_a_human_approves_a_protected_revoke_in_a_real_browser(lane: ProtectedLane) -> None:
    site = protected_site(lane)
    holder = Holder(lane, lane.machine("holder"))
    founded = found_team(site, holder)
    owner = holder.container

    # The fixture app, installed as its owner installs it.
    write_service_member(lane, owner)
    lane.up("secrets", "front")
    grant_install_owner(lane, founded.requester_did_key)
    assert aw(owner, "plugin", "install", API)["approved"]

    provision_signer(site, holder, founded)
    round_trip(site, holder, founded)
    refusals(site, holder, founded)


def reload_front(lane: ProtectedLane) -> None:
    front = lane.compose("ps", "-q", "front").stdout.strip()
    reloaded = _docker("exec", front, "caddy", "reload", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile")
    assert reloaded.returncode == 0, reloaded.stderr
