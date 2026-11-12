"""The team deployment journey on one machine: Setup and step 1, bring-up.

    uv run --project server python scripts/e2e/team_deployment_journey.py \\
        --run-dir DIR --project NAME --images IMAGES

IMAGES lists one pinned image per line, "<name> <repository@sha256:...>", for
aweb, secrets, logs, awid and cli, all built from one source commit.

Setup makes a disposable world in the deployment's own services network
(deploy/team/compose.test.yaml): an AWID registry, DNS for its namespace,
captured SMTP and a TLS front. The real aw, in a cli machine, prepares the
namespace, creates the team and admits each service as an ordinary member;
each service holds only its own member key and certificate. Then the
deployment starts through the Compose adapter (scripts/e2e-team-deployment.sh).

The protected signer needs its human root, authority rows and B3 enrolment
through a real browser, which this journey does not perform yet: it is left
out of the deployment and reported. The agents wait for the egress boundary.

No credential is printed. Each one is a file the service that owns it mounts.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
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
}
UPSTREAMS = {
    "registry": "registry:8010",
    "aweb": "aweb:8000",
    "secrets-api": "secrets:8770",
    "secrets-console": "secrets:8770",
    "logs-api": "logs:8765",
    "logs-console": "logs:8765",
}
MAIL = f"mail.{DOMAIN}"


def origin(name: str) -> str:
    return f"https://{HOSTS[name]}"


def run(*args: str, env: dict[str, str] | None = None, input: str | None = None, timeout: int = 600) -> str:
    result = subprocess.run(args, env=env, input=input, text=True, capture_output=True, timeout=timeout, check=False)
    if result.returncode != 0:
        raise SystemExit(f"FAILED: {' '.join(args[:6])} ...\n{result.stdout[-3000:]}\n{result.stderr[-3000:]}")
    return result.stdout


def first_json(text: str):
    return json.JSONDecoder().raw_decode(text[text.index("{") :])[0]


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
        }

    # --- files ---------------------------------------------------------

    def write_world(self) -> None:
        (self.world / "dns").mkdir(parents=True)
        (self.world / "tls").mkdir()
        (self.world / "front").mkdir()
        (self.world / "dns" / "Corefile").write_text(
            f"{DOMAIN}:53 {{\n  errors\n  file /zones/{DOMAIN}.zone {DOMAIN} {{ reload 1s }}\n}}\n"
            ".:53 {\n  errors\n  forward . 127.0.0.11\n}\n"
        )
        self.publish_controller("did:key:z6MkpendingpendingpendingpendingpendingpendingpendingP")
        tls = make_certificates(self.world / "tls", [*HOSTS.values(), MAIL], [])
        (self.world / "front" / "Caddyfile").write_text(
            "{\n  auto_https off\n}\n"
            + "".join(
                f"{HOSTS[name]}:443 {{\n  tls /tls/{tls.cert_file.name} /tls/{tls.key_file.name}\n"
                f"  reverse_proxy {UPSTREAMS[name]}\n}}\n"
                for name in HOSTS
            )
        )
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
        file for the bundled server and in the component's whole URL."""
        roles = self.secrets / "postgres" / "roles"
        roles.mkdir(parents=True)
        (self.secrets / "postgres" / "password").write_text(secrets.token_hex(24))
        for component in ("aweb", "secrets", "logs"):
            password = secrets.token_hex(24)
            (roles / component).write_text(password)
            (self.secrets / component).mkdir(exist_ok=True)
            (self.secrets / component / "database-url").write_text(
                f"postgresql://{component}:{password}@postgres:5432/{component}\n"
            )

    def deployment(self, *, apps: bool) -> Path:
        config: dict = {
            "team": {"id": TEAM_ID, "registryUrl": origin("registry")},
            "postgres": {"bundled": True},
            "network": {"servicesCidr": self.cidr},
            "aweb": {"image": self.images["aweb"], "publicOrigin": origin("aweb")},
            "compose": {"secretsDir": str(self.secrets)},
        }
        if apps:
            config["aweb"]["appInternalOrigins"] = [origin("secrets-api"), origin("logs-api")]
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
        path = self.run_dir / "deployment.yaml"
        path.write_text(yaml.safe_dump(config, sort_keys=False))
        self.write_trust(["aweb", *(name for name in ("secrets", "logs", "signer") if name in config)])
        return path

    # --- running --------------------------------------------------------

    def connect(self) -> dict:
        return json.loads(run(str(ADAPTER), "compose", "connect", str(self.deployment_path), env=self.env))

    def compose(self, *args: str) -> str:
        """The deployment's own docker compose command, as the adapter gives it."""
        return run(*self.connect()["compose"], *args, env=self.env)

    def render(self, deployment: Path) -> None:
        rendered = run(sys.executable, str(TEAM_DIR / "render_env.py"), str(deployment))
        (self.run_dir / ".env").write_text(rendered)
        self.deployment_path = deployment

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

    def await_controller(self, machine: str, controller_did: str) -> None:
        for _ in range(30):
            answer = subprocess.run(["docker", "exec", machine, "nslookup", "-type=txt", f"_awid.{DOMAIN}"],
                                    text=True, capture_output=True, check=False)
            if controller_did in answer.stdout:
                return
            time.sleep(0.5)
        raise SystemExit(f"FAILED: _awid.{DOMAIN} never named {controller_did}")

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
                        "--did", requested["did_key"], "--name", f"{name}-service", "--global")
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

    def own_service_files(self) -> dict[str, str]:
        """Each component's files belong to the uid its image runs as, mode 0400;
        the public trust files are 0444."""
        owners = {
            "postgres": run("docker", "run", "--rm", "postgres:16-alpine", "id", "-u", "postgres").strip(),
            "aweb": image_user(self.images["aweb"]),
            "secrets": image_user(self.images["secrets"]),
            "logs": image_user(self.images["logs"]),
        }
        script = " && ".join(
            f"chown -R {uid}:{uid} /s/{component} && find /s/{component} -type f ! -name '*-ca.pem' -exec chmod 0400 {{}} +"
            f" && find /s/{component} -type f -name '*-ca.pem' -exec chmod 0444 {{}} +"
            for component, uid in owners.items()
        )
        run("docker", "run", "--rm", "-v", f"{self.secrets}:/s", "alpine:3.22", "sh", "-c", script)
        return owners


def load_images(path: Path) -> dict[str, str]:
    images = {}
    for line in path.read_text().splitlines():
        name, _, reference = line.partition(" ")
        if "@sha256:" in reference:
            images[name] = reference
    missing = {"aweb", "secrets", "logs", "awid", "cli"} - set(images)
    if missing:
        raise SystemExit(f"FAILED: no pinned image for {', '.join(sorted(missing))} in {path}")
    return images


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--images", type=Path, required=True)
    parser.add_argument("--services-cidr", default="172.31.0.0/24")
    parser.add_argument("--keep", action="store_true", help="leave the deployment running for inspection")
    args = parser.parse_args()
    run_dir = args.run_dir.resolve()
    if run_dir.exists():
        raise SystemExit(f"FAILED: {run_dir} exists; each run has its own directory")
    run_dir.mkdir(parents=True)
    world = World(run_dir, args.project, load_images(args.images), args.services_cidr)
    # The settings the adapter needs for this run, none secret, for a later
    # connect or down: set -a; . world.env; scripts/e2e-team-deployment.sh ...
    (run_dir / "world.env").write_text(
        "".join(f"{name}={world.env[name]}\n" for name in sorted(world.env) if name.startswith(("TEAM_DEPLOYMENT_", "TEST_")))
    )

    print("=== Setup: the test world")
    world.write_world()
    world.write_database_files()
    world.render(world.deployment(apps=False))
    world.compose("up", "-d", "--wait", "dns", "registry", "front", "smtp")
    controller = world.machine("controller")

    print("=== Setup: namespace, team and service members, through the real aw")
    prepared = world.aw(controller, "id", "namespace", "prepare-controller", "--domain", DOMAIN,
                        "--registry", origin("registry"))
    world.publish_controller(prepared["controller_did"])
    world.await_controller(controller, prepared["controller_did"])
    world.aw(controller, "id", "team", "create", "--name", TEAM, "--namespace", DOMAIN, "--registry", origin("registry"))
    world.write_service_files(controller)
    owners = world.own_service_files()
    print("service file owners:", json.dumps(owners, sort_keys=True))

    print("=== Step 1: bring up the deployment")
    deployment = world.deployment(apps=True)
    up = subprocess.run([str(ADAPTER), "compose", "up", str(deployment)], env=world.env, text=True, check=False)
    world.deployment_path = deployment
    connect = json.dumps(world.connect(), indent=2)
    (run_dir / "connect.json").write_text(connect)
    print(connect)
    if up.returncode != 0:
        print("BOUNDARY: the deployment did not come up; see compose.log in the run directory")
    else:
        print("UP: aweb, secrets and logs are healthy; signer and agents are not in this run")
    if args.keep:
        return up.returncode
    print("=== Teardown")
    down = subprocess.run([str(ADAPTER), "compose", "down", str(deployment)], env=world.env, text=True, check=False)
    print("DOWN: nothing of the project is left" if down.returncode == 0 else "DOWN FAILED: see above")
    return up.returncode or down.returncode


if __name__ == "__main__":
    sys.exit(main())
