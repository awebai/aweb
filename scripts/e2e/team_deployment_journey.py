"""The team deployment journey on one machine.

    uv run --project naapp/secrets python scripts/e2e/team_deployment_journey.py \\
        --run-dir DIR --project NAME --images IMAGES

IMAGES lists one pinned image per line, "<name> <repository@sha256:...>", for
aweb, aweb-protected, secrets, logs, awid, cli and chromium, all built from one
source commit.

Setup makes a disposable world in the deployment's own services network
(deploy/team/compose.test.yaml): an AWID registry, DNS for its namespace,
captured SMTP and a TLS front that refuses a Host its SNI does not name. On the
holder's machine the real aw founds the namespace, its root human (the
approver) and the team, and admits each service as an ordinary member; each
service holds only its own member key and certificate. The deployment starts
through the Compose adapter (scripts/e2e-team-deployment.sh), and the team's
owner installs Secrets and Logs after the operator's install-owner grant.

Then the protected round trip (naapp/secrets/e2e/protected_round_trip.py, the
same body the secrets e2e lane runs): the signer is configured, provisioned
and started, the approver's passkey is enrolled with Chromium, aw prepares a
human-role revoke, the approver approves it in the browser, aw reads the
committed receipt, and the refusals sign nothing they must not.

The agents wait for the egress boundary.

No credential is printed. Each one is a file the service that owns it mounts.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path

import yaml
from aweb_naapp_testing.network import make_certificates

REPO = Path(__file__).resolve().parents[2]
TEAM_DIR = REPO / "deploy" / "team"
ADAPTER = REPO / "scripts" / "e2e-team-deployment.sh"
EVIDENCE = REPO / "naapp" / "secrets" / "e2e" / "protected" / "evidence.py"
sys.path.insert(0, str(REPO / "naapp" / "secrets" / "e2e"))

from protected_round_trip import (  # noqa: E402
    Holder,
    Site,
    connect_requester,
    first_json,
    found_team,
    provision_signer,
    refusals,
    round_trip,
)

DOMAIN = "lf.test"
TEAM = "lfteam"
TEAM_ID = f"{TEAM}:{DOMAIN}"
HOSTS = {
    "registry": f"registry.{DOMAIN}",
    "aweb": f"aweb.{DOMAIN}",
    "secrets-api": f"api.secrets.{DOMAIN}",
    "secrets-console": f"console.secrets.{DOMAIN}",
    "logs-api": f"api.logs.{DOMAIN}",
    "logs-console": f"console.logs.{DOMAIN}",
    "signer": f"signer.{DOMAIN}",
    "human": f"human.{DOMAIN}",
}
UPSTREAMS = {
    "registry": "registry:8010",
    "aweb": "aweb:8000",
    "secrets-api": "secrets:8770",
    "secrets-console": "secrets:8770",
    "logs-api": "logs:8765",
    "logs-console": "logs:8765",
    "signer": "signer:8080",
    "human": "signer:8080",
}
MAIL = f"mail.{DOMAIN}"
# The role the round trip revokes, of this deployment's Secrets app.
ROLE = "secrets.owner"
# The agents' uid: the signer refuses custody a worker could read.
AGENT_UID = 20001


def origin(name: str) -> str:
    return f"https://{HOSTS[name]}"


def run(*args: str, env: dict[str, str] | None = None, input: str | None = None, timeout: int = 600) -> str:
    result = subprocess.run(args, env=env, input=input, text=True, capture_output=True, timeout=timeout, check=False)
    if result.returncode != 0:
        raise SystemExit(f"FAILED: {' '.join(args[:6])} ...\n{result.stdout[-3000:]}\n{result.stderr[-3000:]}")
    return result.stdout


def image_user(image: str) -> str:
    """The uid the image runs as, so its files belong to it."""
    user = run("docker", "image", "inspect", "--format", "{{.Config.User}}", image).strip()
    return user.split(":")[0]


class World:
    def __init__(self, run_dir: Path, project: str, images: dict[str, str], cidr: str):
        self.run_dir, self.project, self.images = run_dir, project, images
        self.world = run_dir / "world"
        self.deployment_path = run_dir / "deployment.yaml"
        self.secrets = run_dir / "secrets"
        self.signer_configured = False
        self.agents_configured = False
        self.oats_source: Path | None = None
        network = ipaddress.ip_network(cidr)
        self.cidr = cidr
        top = network.broadcast_address
        self.front_ip, self.dns_ip, self.smtp_ip = (str(top - 5), str(top - 4), str(top - 3))
        self.env = {
            **os.environ,
            "TEAM_DEPLOYMENT_PROJECT": project,
            "TEAM_DEPLOYMENT_RUN_DIR": str(run_dir),
            "TEAM_DEPLOYMENT_COMPOSE_FILES": f"{TEAM_DIR / 'compose.test.yaml'}:{self.world / 'compose.trust.yaml'}",
            "TEST_WORLD_DIR": str(self.world),
            "TEST_DNS_IP": self.dns_ip,
            "TEST_FRONT_IP": self.front_ip,
            "TEST_SMTP_IP": self.smtp_ip,
            "TEST_AWID_IMAGE": images["awid"],
            "TEST_CLI_IMAGE": images["cli"],
            "TEST_REGISTRY_ORIGIN": origin("registry"),
            # The front's certificates come from this world's own authority.
            "TEAM_DEPLOYMENT_INGRESS_CA": str(self.world / "tls" / "ca.pem"),
            # The world holds the machines' keys, the front's TLS keys and the
            # controller's provisioning copy: no agent mount may reach into it.
            "TEAM_DEPLOYMENT_PROTECTED_SOURCES": str(self.world),
        }

    # --- files ---------------------------------------------------------

    def write_world(self) -> None:
        (self.world / "dns").mkdir(parents=True)
        (self.world / "tls").mkdir()
        (self.world / "front").mkdir()
        (self.world / "signer").mkdir()
        (self.world / "dns" / "Corefile").write_text(
            f"{DOMAIN}:53 {{\n  errors\n  file /zones/{DOMAIN}.zone {DOMAIN} {{ reload 1s }}\n}}\n"
            ".:53 {\n  errors\n  forward . 127.0.0.11\n}\n"
        )
        self.publish_controller("did:key:z6MkpendingpendingpendingpendingpendingpendingpendingP")
        tls = make_certificates(self.world / "tls", [*HOSTS.values(), MAIL], [])
        self.caddyfile = (
            # A request whose Host its TLS SNI does not name is refused: the
            # signer's request host must never reach its human host. Caddy
            # compares hostnames alone, so each site also refuses, itself,
            # any authority but its own host on port 443.
            "{\n  auto_https off\n  servers {\n    strict_sni_host on\n  }\n}\n"
            + "".join(
                f"{HOSTS[name]}:443 {{\n  tls /tls/{tls.cert_file.name} /tls/{tls.key_file.name}\n"
                f"  @misdirected not header_regexp Host ^{re.escape(HOSTS[name])}(:443)?$\n"
                "  respond @misdirected 421\n"
                f"  reverse_proxy {UPSTREAMS[name]}\n}}\n"
                for name in HOSTS
            )
        )
        (self.world / "front" / "Caddyfile").write_text(self.caddyfile)
        for path in [*(self.world / "tls").iterdir(), *(self.world / "front").iterdir(), *(self.world / "dns").iterdir()]:
            path.chmod(0o644)

    def write_trust(self, services: list[str]) -> None:
        """Each deployed service resolves through this world's DNS and trusts
        its certificate authority, as it would the operator's."""
        trust = {
            name: {
                "dns": [self.dns_ip],
                "environment": {"SSL_CERT_FILE": "/etc/aweb-test/ca.pem"},
                "volumes": [f"{self.world / 'tls' / 'ca.pem'}:/etc/aweb-test/ca.pem:ro"],
            }
            for name in services
        }
        (self.world / "compose.trust.yaml").write_text(yaml.safe_dump({"services": trust}))

    def publish_controller(self, controller_did: str) -> None:
        zone = self.world / "dns" / f"{DOMAIN}.zone"
        records = "".join(f"{host.removesuffix('.' + DOMAIN)} IN A {self.front_ip}\n" for host in HOSTS.values())
        tmp = zone.with_suffix(".tmp")
        tmp.write_text(
            f"$ORIGIN {DOMAIN}.\n$TTL 1\n"
            f"@ IN SOA ns.{DOMAIN}. hostmaster.{DOMAIN}. ({int(time.time())} 1 1 1 1)\n"
            f"@ IN NS ns.{DOMAIN}.\nns IN A {self.dns_ip}\n"
            f"mail IN A {self.smtp_ip}\n{records}"
            f'_awid IN TXT "awid=v1; controller={controller_did}; registry={origin("registry")};"\n'
        )
        tmp.chmod(0o644)
        tmp.replace(zone)

    def write_database_files(self) -> None:
        """One role and database per component; the password is in the role's
        file for the bundled server and in the component's whole URL. The
        roles exist only from the bundled server's first start."""
        roles = self.secrets / "postgres" / "roles"
        roles.mkdir(parents=True)
        (self.secrets / "postgres" / "password").write_text(secrets.token_hex(24))
        for component in ("aweb", "secrets", "logs", "signer"):
            password = secrets.token_hex(24)
            (roles / component).write_text(password)
            (self.secrets / component).mkdir(exist_ok=True)
            (self.secrets / component / "database-url").write_text(
                f"postgresql://{component}:{password}@postgres:5432/{component}\n"
            )

    def deployment(self) -> Path:
        config: dict = {
            "team": {"id": TEAM_ID, "registryUrl": origin("registry")},
            "postgres": {"bundled": True},
            "network": {"servicesCidr": self.cidr},
            "aweb": {"image": self.images["aweb"], "publicOrigin": origin("aweb"),
                     "appInternalOrigins": [origin("secrets-api"), origin("logs-api")]},
            "compose": {"secretsDir": str(self.secrets)},
        }
        for app in ("secrets", "logs"):
            config[app] = {
                "image": self.images[app],
                "appId": f"{TEAM}-{app}",
                "publicOrigin": origin(f"{app}-api"),
                "consoleOrigin": origin(f"{app}-console"),
                "emailSmtpHost": MAIL,
                "emailSmtpPort": 1025,
                "emailFrom": f"{app}@{DOMAIN}",
                "emailCaFile": f"/run/secrets/{app}/smtp-ca.pem",
                "egressDeniedNetworks": ["169.254.0.0/16"],
            }
        # Secrets sends its use and governance events to this deployment's Logs.
        config["secrets"]["hookInternalOrigins"] = [origin("logs-api")]
        config["secrets"]["hookCaFile"] = "/run/secrets/secrets/hook-ca.pem"
        if self.signer_configured:
            config["signer"] = {
                "image": self.images["aweb-protected"],
                "profileFile": str(self.world / "signer" / "profile.json"),
                "scopeFile": str(self.world / "signer" / "scope.json"),
                "requestOrigin": origin("signer"),
                "humanOrigin": origin("human"),
                "workerUids": [AGENT_UID],
                "emailSmtpHost": MAIL,
                "emailSmtpPort": 1025,
                "emailUsername": "signer",
                "emailFrom": f"signer@{DOMAIN}",
                "emailCaFile": str(self.world / "tls" / "ca.pem"),
            }
        if self.agents_configured:
            config["agents"] = {
                "image": self.images["agent"],
                "uid": AGENT_UID,
                "gid": AGENT_UID,
                "resolverIp": "172.30.0.2",
                "network": {"address": "172.30.0.10"},
                "compose": {
                    "stateDir": str(self.world / "agent-state"),
                    "authorizedKeysFile": str(self.world / "agent-authorized-keys"),
                    "pidsLimit": 512,
                    "name": TEAM,
                    "oatsSource": str(self.oats_source),
                },
            }
            config["egress"] = {"image": self.images["egress"], "privateIngressAddresses": [self.front_ip]}
        path = self.run_dir / "deployment.yaml"
        path.write_text(yaml.safe_dump(config, sort_keys=False))
        self.write_trust(["aweb", *(name for name in ("secrets", "logs", "signer") if name in config)])
        self.render(path)
        return path

    # --- running --------------------------------------------------------

    def connect(self) -> dict:
        return json.loads(run(str(ADAPTER), "compose", "connect", str(self.deployment_path), env=self.env))

    def compose(self, *args: str, input: str | None = None) -> str:
        """The deployment's own docker compose command, as the adapter gives it."""
        return run(*self.connect()["compose"], *args, env=self.env, input=input)

    def render(self, deployment: Path) -> None:
        rendered = run(sys.executable, str(TEAM_DIR / "render_env.py"), str(deployment))
        (self.run_dir / ".env").write_text(rendered)
        self.deployment_path = deployment

    def up(self) -> int:
        """The adapter's up: every service healthy, internal origins inside
        the services range, every service ready. 3 means the agents are held."""
        result = subprocess.run([str(ADAPTER), "compose", "up", str(self.deployment_path)], env=self.env, text=True,
                                check=False)
        connect = json.dumps(self.connect(), indent=2)
        (self.run_dir / "connect.json").write_text(connect)
        return result.returncode

    def configure_agents(self) -> None:
        """The team container's state, SSH keys and login directory: state
        owned by the agents' uid, the login directory readable only by their
        group, and no harness login in it for this run."""
        (self.world / "agent-state").mkdir()
        (self.world / "agent-authorized-keys").write_text("")
        (self.secrets / "agents").mkdir()
        run("docker", "run", "--rm", "-v", f"{self.world / 'agent-state'}:/state",
            "-v", f"{self.secrets / 'agents'}:/login", "alpine:3.22", "sh", "-c",
            f"chown {AGENT_UID}:{AGENT_UID} /state && chown 0:{AGENT_UID} /login && chmod 0750 /login")
        self.agents_configured = True
        self.deployment()

    def machine(self, name: str) -> str:
        """A cli container as one machine; its HOME is /world/<name>."""
        container = f"{self.project}-{name}"
        (self.world / name).mkdir(mode=0o700)
        uid, gid = os.getuid(), os.getgid()
        accounts = self.world / "accounts"
        if not accounts.exists():
            accounts.mkdir(mode=0o755)
            (accounts / "passwd").write_text(f"root:x:0:0:root:/root:/bin/sh\nworld:x:{uid}:{gid}:world:/world:/bin/sh\n")
            (accounts / "group").write_text(f"root:x:0:\nworld:x:{gid}:\n")
            for path in accounts.iterdir():
                path.chmod(0o644)
        self.compose(
            "--profile", "cli", "run", "-d", "--no-deps", "--name", container, "--user", f"{uid}:{gid}",
            "-v", f"{accounts / 'passwd'}:/etc/passwd:ro", "-v", f"{accounts / 'group'}:/etc/group:ro",
            "-e", f"HOME=/world/{name}", "-w", f"/world/{name}", "cli",
        )
        return container

    def aw(self, machine: str, *args: str, home: str | None = None) -> dict:
        """aw --json in a machine, as its own person or, with home, as another
        identity whose home is there."""
        where = ["-e", f"HOME={home}", "-w", f"{home}/identity"] if home else []
        return first_json(run("docker", "exec", *where, machine, "aw", "--json", *args, timeout=300))

    def admit_service(self, machine: str, name: str) -> tuple[str, Path]:
        """One service as an ordinary member: aw creates its key in its own
        identity, the team owner adds it, and the member fetches its
        certificate with its own key. Returns the key file's text and the
        certificate's path."""
        home = f"/world/{name}-member"
        (self.world / f"{name}-member" / "identity").mkdir(parents=True, mode=0o700)
        requested = self.aw(machine, "id", "team", "request", "--create-local-key", "--team", TEAM_ID,
                            "--name", f"{name}-service", home=home)
        added = self.aw(machine, "id", "team", "add-member", "--team", TEAM, "--namespace", DOMAIN,
                        "--did", requested["did_key"], "--name", f"{name}-service", "--local")
        fetched = self.aw(machine, "id", "team", "fetch-cert", "--namespace", DOMAIN, "--team", TEAM,
                          "--cert-id", added["certificate_id"], "--registry", origin("registry"), home=home)
        # Both are in the identity's .aw: the certificate path aw reports is relative to it.
        keys = self.world / f"{name}-member" / "identity" / ".aw"
        return (keys / "signing.key").read_text(), keys / fetched["cert_path"]

    def write_service_files(self, machine: str) -> None:
        pem, _ = self.admit_service(machine, "aweb")
        (self.secrets / "aweb" / f"{TEAM}.key").write_text(pem)
        (self.secrets / "aweb" / "member-keys.json").write_text(json.dumps({TEAM_ID: f"{TEAM}.key"}))
        ca = self.world / "tls" / "ca.pem"
        keys = {
            "secrets": ["custody-key", "request-seal-key", "params-seal-key", "response-seal-key",
                        "runner-service-key", "manifest-request-key", "hook-event", "hook-delivery",
                        "grant-read", "hook-resolve"],
            "logs": ["logs-chain", "logs-resolve", "logs-grants", "logs-governance"],
        }
        for app, names in keys.items():
            pem, certificate = self.admit_service(machine, app)
            directory = self.secrets / app
            (directory / "awid-member-key").write_text(pem)
            shutil.copyfile(certificate, directory / "awid-member-certificate")
            for name in names:
                (directory / name).write_text(secrets.token_hex(32) + "\n")
            (directory / "smtp-username").write_text(f"{app}-service")
            (directory / "smtp-password").write_text(secrets.token_urlsafe(16))
            shutil.copyfile(ca, directory / "smtp-ca.pem")
            shutil.copyfile(ca, directory / "hook-ca.pem")

    def own(self, owners: dict[str, str]) -> None:
        """Each component's files belong to the uid its image runs as, mode 0400;
        the public trust files are 0444."""
        script = " && ".join(
            f"chown -R {uid}:{uid} /s/{component} && find /s/{component} -type f ! -name '*-ca.pem' -exec chmod 0400 {{}} +"
            f" && find /s/{component} -type f -name '*-ca.pem' -exec chmod 0444 {{}} +"
            for component, uid in owners.items()
        )
        run("docker", "run", "--rm", "-v", f"{self.secrets}:/s", "alpine:3.22", "sh", "-c", script)

    def own_service_files(self) -> dict[str, str]:
        owners = {
            "postgres": run("docker", "run", "--rm", "postgres:16-alpine", "id", "-u", "postgres").strip(),
            "aweb": image_user(self.images["aweb"]),
            "secrets": image_user(self.images["secrets"]),
            "logs": image_user(self.images["logs"]),
        }
        self.own(owners)
        return owners

    def install_apps(self, machine: str, owner_did_key: str) -> None:
        """The operator's explicit install-owner grant, then the owner installs
        Secrets and Logs from their internal origins. Membership alone grants
        no install authority."""
        self.compose("exec", "-T", "aweb", "aweb", "install-admin", "grant", "--team-id", TEAM_ID,
                     "--principal-did", owner_did_key, "--role", "owner")
        for app in ("secrets", "logs"):
            installed = self.aw(machine, "plugin", "install", origin(f"{app}-api"))
            if not installed.get("approved"):
                raise SystemExit(f"BOUNDARY: {app} was not installed: {json.dumps(installed)}")
            print(f"INSTALLED: {app} from {origin(app + '-api')}")

    # --- the protected round trip's Site --------------------------------

    def site(self) -> Site:
        signer_uid = image_user(self.images["aweb-protected"])
        signer_secrets = self.secrets / "signer"

        def store_member(pem: str) -> None:
            (signer_secrets / "member-signer.pem").write_text(pem)
            (signer_secrets / "members.json").write_text(json.dumps({TEAM_ID: "member-signer.pem"}))

        def install_controller(pem: Path) -> None:
            """HOST.md, controller key installation: the owner's existing PEM in
            a short-lived source only the signer's uid reads, converted into
            its private directory by the package command, then removed."""
            source = self.world / "private-provisioning"
            source.mkdir(mode=0o700)
            shutil.copyfile(pem, source / "team-controller.pem")
            run("docker", "run", "--rm", "-v", f"{source}:/p", "alpine:3.22", "sh", "-c",
                f"chown -R {signer_uid}:{signer_uid} /p && chmod 0400 /p/team-controller.pem")
            try:
                # The signer's secrets are read-only to it; this one trusted
                # provisioning step writes its private controller directory.
                operator_command("install-controller", "--source-pem", "/private-provisioning/team-controller.pem",
                                 mounts=["-v", f"{source}:/private-provisioning:ro",
                                         "-v", f"{signer_secrets / 'private-controller'}:"
                                               "/run/secrets/signer/private-controller"])
            finally:
                run("docker", "run", "--rm", "-v", f"{self.world}:/w", "alpine:3.22", "rm", "-rf",
                    "/w/private-provisioning")

        def configure_signer(profile: dict, scope: dict) -> None:
            for name, document in (("profile.json", profile), ("scope.json", scope)):
                (self.world / "signer" / name).write_text(json.dumps(document))
                (self.world / "signer" / name).chmod(0o644)
            (signer_secrets / "smtp-password").write_text(secrets.token_urlsafe(16))
            # The private controller directory, created as its owner before
            # the controller is installed into it.
            run("docker", "run", "--rm", "-v", f"{signer_secrets}:/s", "alpine:3.22", "sh", "-c",
                f"chown {signer_uid}:{signer_uid} /s/database-url /s/smtp-password /s/members.json "
                f"/s/member-signer.pem && chmod 0400 /s/database-url /s/smtp-password /s/members.json "
                f"/s/member-signer.pem && install -d -m 0700 -o {signer_uid} -g {signer_uid} /s/private-controller")
            self.signer_configured = True
            self.deployment()

        def operator_command(*args: str, mounts: list[str] | None = None) -> dict:
            """The package's local administrator command in the signer's
            container, as its uid, with the signer's own settings and mounts."""
            output = self.compose("run", "--rm", "-T", "--no-deps", *(mounts or []), "--entrypoint", "python",
                                  "signer", "-m", "aweb.protected_signing.operator", *args)
            return first_json(output)

        def signer_evidence(operation: str) -> dict:
            output = self.compose("run", "--rm", "-T", "--no-deps", "-v", f"{EVIDENCE}:/evidence.py:ro",
                                  "--entrypoint", "python", "signer", "/evidence.py", "--operation-id", operation)
            return first_json(output)[operation]

        def start_signer() -> None:
            if self.up() != 0:
                raise SystemExit("BOUNDARY: the signer did not come up ready; see compose.log in the run directory")
            print("UP: the signer is ready")

        def chromium(machine: str, *args: str) -> dict:
            # As the host user, so the journey reads what the driver writes; its
            # NSS database lives in a HOME of its own.
            out = run("docker", "run", "--rm", f"--network=container:{machine}", "-v", f"{self.world}:/world",
                      "--user", f"{os.getuid()}:{os.getgid()}", "-e", "HOME=/tmp",
                      self.images["chromium"], *args, "--ca", "/world/tls/ca.pem", timeout=300).strip()
            return first_json(out) if "{" in out else {}

        def drop_prepare_answers(on: bool) -> None:
            caddyfile = self.caddyfile
            if on:
                caddyfile = caddyfile.replace(
                    f"{HOSTS['signer']}:443 {{\n",
                    f"{HOSTS['signer']}:443 {{\n  @prepare {{\n    method POST\n    path /protected-operations\n  }}\n"
                    "  reverse_proxy @prepare signer:8080 {\n    @answered status 2xx\n"
                    "    handle_response @answered {\n      abort\n    }\n  }\n", 1)
            (self.world / "front" / "Caddyfile").write_text(caddyfile)
            self.compose("exec", "-T", "front", "caddy", "reload", "--config", "/etc/caddy/Caddyfile",
                         "--adapter", "caddyfile")

        return Site(
            runtime=self.world, mounted="/world", domain=DOMAIN, team=TEAM, registry=origin("registry"),
            aweb=origin("aweb"), signer=origin("signer"), human=origin("human"), service_id=f"{TEAM}-signer",
            app_id=f"{TEAM}-secrets", role=ROLE, contact=f"approver@{DOMAIN}", mail_api=f"http://{MAIL}:8025",
            profile_in_machine="/world/signer/profile.json", publish_controller=self.publish_controller,
            store_member=store_member, configure_signer=configure_signer, install_controller=install_controller,
            operator=operator_command, start_signer=start_signer, signer_evidence=signer_evidence,
            signer_access_log=lambda: self.compose("logs", "--no-color", "--no-log-prefix", "signer"),
            chromium=chromium, drop_prepare_answers=drop_prepare_answers,
        )


def load_images(path: Path) -> dict[str, str]:
    images = {}
    for line in path.read_text().splitlines():
        name, _, reference = line.partition(" ")
        if "@sha256:" in reference:
            images[name] = reference
    missing = {"aweb", "aweb-protected", "secrets", "logs", "awid", "cli", "chromium"} - set(images)
    if missing:
        raise SystemExit(f"FAILED: no pinned image for {', '.join(sorted(missing))} in {path}")
    return images


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--images", type=Path, required=True)
    parser.add_argument("--services-cidr", default="172.31.0.0/24")
    parser.add_argument("--oats-source", type=Path, help="checkout of the pinned OATS source, for the agents")
    parser.add_argument("--keep", action="store_true", help="leave the deployment running for inspection")
    args = parser.parse_args()
    run_dir = args.run_dir.resolve()
    if run_dir.exists():
        raise SystemExit(f"FAILED: {run_dir} exists; each run has its own directory")
    run_dir.mkdir(parents=True)
    world = World(run_dir, args.project, load_images(args.images), args.services_cidr)
    world.oats_source = args.oats_source.resolve() if args.oats_source else None
    if ("agent" in world.images) != (world.oats_source is not None):
        raise SystemExit("FAILED: the agents need both their images and --oats-source")
    # The settings the adapter needs for this run, none secret, for a later
    # connect or down: set -a; . world.env; scripts/e2e-team-deployment.sh ...
    (run_dir / "world.env").write_text(
        "".join(f"{name}={world.env[name]}\n" for name in sorted(world.env) if name.startswith(("TEAM_DEPLOYMENT_", "TEST_")))
    )
    try:
        return journey(world)
    finally:
        if not args.keep:
            print("=== Teardown")
            down = subprocess.run([str(ADAPTER), "compose", "down", str(world.deployment_path)], env=world.env,
                                  text=True, check=False)
            print("DOWN: nothing of the project is left" if down.returncode == 0 else "DOWN FAILED: see above")


def journey(world: World) -> int:
    print("=== Setup: the test world")
    world.write_world()
    world.write_database_files()
    world.deployment()
    world.compose("up", "-d", "--wait", "dns", "registry", "front", "smtp")
    site = world.site()
    holder = Holder(world.machine("holder"), DOMAIN)

    print("=== Setup: namespace, root human, team and service members, through the real aw")
    founded = found_team(site, holder)
    world.write_service_files(holder.container)
    owners = world.own_service_files()
    print("service file owners:", json.dumps(owners, sort_keys=True))

    print("=== Step 1: bring up the deployment")
    if world.up() != 0:
        print("BOUNDARY: the deployment did not come up; see compose.log in the run directory")
        return 1
    print("UP: aweb, secrets and logs are ready")
    connect_requester(site, holder)
    print("=== Setup: the team owner installs Secrets and Logs from their internal origins")
    world.install_apps(holder.container, founded.requester_did_key)

    print("=== Step 5: the protected act")
    provision_signer(site, holder, founded)
    operation = round_trip(site, holder, founded)
    print(f"SIGNED: {operation} committed, approved in the browser, receipt read by aw")
    refusals(site, holder, founded)
    print("REFUSED: no UV signs nothing; a changed act is operation_conflict; a lost prepare completes once")

    if "agent" not in world.images:
        print("AGENTS: not in this run (no agent or egress image)")
        return 0
    print("=== Step 2: the agents, behind egress")
    world.configure_agents()
    status = world.up()
    if status == 3:
        print("AGENTS HELD: egress is healthy, the agents network isolated, and the ingress refusal and boundary"
              " probes passed; no agent is admitted yet")
        return 0
    print("BOUNDARY: the agents stage did not come up; see the adapter's output")
    return 1


if __name__ == "__main__":
    sys.exit(main())
