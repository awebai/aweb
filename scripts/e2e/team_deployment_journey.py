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
import datetime
import hashlib
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

import pexpect
import yaml
from aweb_naapp_testing.network import make_certificates

REPO = Path(__file__).resolve().parents[2]
TEAM_DIR = REPO / "deploy" / "team"
ADAPTER = REPO / "scripts" / "e2e-team-deployment.sh"
EVIDENCE = REPO / "naapp" / "secrets" / "e2e" / "protected" / "evidence.py"
sys.path.insert(0, str(REPO / "naapp" / "secrets" / "e2e"))

from protected_round_trip import (  # noqa: E402
    Founded,
    Holder,
    Site,
    approve,
    changed_act,
    connect_requester,
    did_key_window,
    docker,
    finish,
    first_json,
    found_team,
    provision_signer,
    refusals,
    round_trip,
    start_revoke,
)

DOMAIN = "lf.test"
TEAM = "lfteam"
# The agents' two seats: ordinary members of the team.
SEATS = ["agent-one", "agent-two"]
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
            # No agent mount may reach into the world (the machines' keys, the
            # front's TLS keys, the controller's provisioning copy) or the
            # operator's directory (its private SSH key).
            "TEAM_DEPLOYMENT_PROTECTED_SOURCES": f"{self.world}:{run_dir / 'operator'}",
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

    def write_redis_files(self) -> None:
        """Redis holds the password's SHA-256 in its ACL file; aweb holds the
        password in its whole Redis URL."""
        password = secrets.token_hex(24)
        (self.secrets / "redis").mkdir()
        (self.secrets / "redis" / "users.acl").write_text(
            f"user default on #{hashlib.sha256(password.encode()).hexdigest()} ~* &* +@all\n"
        )
        (self.secrets / "aweb").mkdir(exist_ok=True)
        (self.secrets / "aweb" / "redis-url").write_text(f"redis://default:{password}@redis:6379/0\n")

    def redis_isolation(self, required: set[str]) -> dict:
        """aweb reaches Redis with its password; from aweb's own network a
        client without it, or with a wrong one, is refused, which shows Redis
        is up and reachable there; and from every other running service of
        the deployment, the required ones among them, Redis's address does
        not answer at all."""
        containers = dict(
            line.split()
            for line in run("docker", "ps", "--filter", f"label=com.docker.compose.project={self.project}",
                            "--format", '{{.Label "com.docker.compose.service"}} {{.ID}}').splitlines()
        )
        missing = required - set(containers)
        assert not missing, f"redis isolation: not running: {sorted(missing)}"
        address = run("docker", "inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}",
                      containers["redis"]).split()
        assert len(address) == 1, f"redis isolation: Redis is on {len(address)} networks"

        def ask(service: str, commands: str) -> subprocess.CompletedProcess:
            return subprocess.run(
                ["docker", "run", "--rm", "-i", "--network", f"container:{containers[service]}", "redis:7-alpine",
                 "timeout", "5", "redis-cli", "-h", address[0], "-p", "6379"],
                input=commands, text=True, capture_output=True, timeout=60, check=False)

        ready = json.loads(self.compose("exec", "-T", "aweb", "curl", "-fsS", "http://localhost:8000/ready"))
        assert ready["checks"]["redis"] == "ok", f"redis isolation: aweb's /ready: {ready}"
        anonymous = ask("aweb", "PING\r\n")
        assert anonymous.stdout.startswith("NOAUTH"), (
            f"redis isolation: no password from aweb's network: {anonymous.stdout!r} {anonymous.stderr[-300:]!r}")
        wrong = ask("aweb", f"AUTH default {secrets.token_hex(24)}\r\nPING\r\n")
        assert wrong.stdout.startswith("WRONGPASS") and "NOAUTH" in wrong.stdout, (
            f"redis isolation: a wrong password from aweb's network: {wrong.stdout!r} {wrong.stderr[-300:]!r}")
        unreachable = {}
        for service in sorted(set(containers) - {"aweb", "redis"}):
            answer = ask(service, "PING\r\n")
            assert answer.returncode != 0 and not answer.stdout.strip(), (
                f"redis isolation: {service} reaches Redis: {answer.stdout!r}")
            unreachable[service] = {"exit": answer.returncode, "error": answer.stderr.strip()[-120:]}
        return {"redis": address[0], "aweb_ready": ready["checks"]["redis"],
                "aweb_network_without_password": anonymous.stdout.split()[0],
                "aweb_network_wrong_password": wrong.stdout.split()[0], "unreachable_from": unreachable}

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
                # The world's public CA, copied outside every protected root.
                "caFile": str(self.run_dir / "agent-ca.pem"),
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
        (self.run_dir / "operator").mkdir(mode=0o700)
        shutil.copyfile(self.world / "tls" / "ca.pem", self.run_dir / "agent-ca.pem")
        (self.run_dir / "agent-ca.pem").chmod(0o644)
        (self.secrets / "agents").mkdir()
        run("docker", "run", "--rm", "-v", f"{self.world / 'agent-state'}:/state",
            "-v", f"{self.secrets / 'agents'}:/login", "alpine:3.22", "sh", "-c",
            f"chown {AGENT_UID}:{AGENT_UID} /state && chown 0:{AGENT_UID} /login && chmod 0750 /login")
        self.agents_configured = True
        self.deployment()

    def operator_ssh(self) -> Path:
        """The operator's SSH into the running agent (OATS docs/container.md,
        isolated bridge): a disposable key outside every agent mount, only its
        public half in the agent's authorized keys (written in place, root
        owned, as sshd's strict modes require), the agent's host key pinned
        through the engine, and stdio relayed by docker exec, so the agents
        network gains no endpoint and no port is published. Returns the SSH
        config; a wrong pinned host key is refused."""
        operator = self.run_dir / "operator"
        key = operator / "id_ed25519"
        run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "deploy-team-operator", "-f", str(key))
        authorized = self.world / "agent-authorized-keys"
        run("docker", "run", "--rm", "-v", f"{authorized}:/authorized_keys", "-v", f"{key}.pub:/operator.pub:ro",
            "alpine:3.22", "sh", "-c",
            "cat /operator.pub > /authorized_keys && chown 0:0 /authorized_keys && chmod 0644 /authorized_keys")
        container = f"oats-agent-{TEAM}"
        host_key = run("docker", "exec", container, "cat", "/state/ssh/ssh_host_ed25519_key.pub").split()[:2]
        (operator / "known_hosts").write_text(f"[oats-agent]:2222 {' '.join(host_key)}\n")
        relay = ('const s=require("node:net").connect(2222,"127.0.0.1");'
                 'process.stdin.pipe(s);s.pipe(process.stdout);s.on("error",()=>process.exit(1));')
        config = operator / "ssh_config"
        config.write_text(
            "Host team-agent\n  HostName oats-agent\n  User agent\n  Port 2222\n"
            f"  IdentityFile {key}\n  IdentitiesOnly yes\n  UserKnownHostsFile {operator / 'known_hosts'}\n"
            "  StrictHostKeyChecking yes\n  BatchMode yes\n"
            f"  ProxyCommand docker exec -i {container} node -e '{relay}'\n"
        )
        print("operator ssh:", run("ssh", "-F", str(config), "team-agent", "id -un; hostname").split())
        (operator / "wrong_known_hosts").write_text(f"[oats-agent]:2222 {' '.join(key.with_suffix('.pub').read_text().split()[:2])}\n")
        wrong = subprocess.run(["ssh", "-F", str(config), "-o", f"UserKnownHostsFile={operator / 'wrong_known_hosts'}",
                                "team-agent", "true"], capture_output=True, text=True, timeout=60, check=False)
        (operator / "wrong_known_hosts").unlink()
        if wrong.returncode != 255 or "host key" not in wrong.stderr.lower():
            raise SystemExit("FAILED: the operator's SSH reached the agent under a host key it does not hold")
        return config

    def admit_seat(self, owner: str, alias: str) -> dict:
        """One agent seat: an ordinary member whose key aw creates on its own
        machine, admitted by the team owner while the owner still holds the
        team's key (owner-issued and local, not a global identity), with its
        certificate. Returns the member's public provenance."""
        machine = self.machine(f"seat-{alias}")
        requested = self.aw(machine, "id", "team", "request", "--create-local-key", "--team", TEAM_ID, "--name", alias)
        added = self.aw(owner, "id", "team", "add-member", "--team", TEAM, "--namespace", DOMAIN,
                        "--did", requested["did_key"], "--name", alias, "--local")
        self.aw(machine, "id", "team", "fetch-cert", "--namespace", DOMAIN, "--team", TEAM,
                "--cert-id", added["certificate_id"], "--registry", origin("registry"))
        return {"alias": alias, "did_key": requested["did_key"], "certificate_id": added["certificate_id"]}

    def stage_seats(self, aliases: list[str]) -> None:
        """Each seat member connects to the team's aweb from its own machine,
        then only its own .aw goes into the agent's state, at
        /state/seats/<alias>/.aw, owned by the agents' uid and private."""
        for alias in aliases:
            self.aw(f"{self.project}-seat-{alias}", "workspace", "connect", "--service", origin("aweb"))
            run("docker", "run", "--rm", "-v", f"{self.world / f'seat-{alias}' / '.aw'}:/member:ro",
                "-v", f"{self.world / 'agent-state'}:/state", "alpine:3.22", "sh", "-c",
                f"mkdir -p /state/seats/{alias} && cp -a /member /state/seats/{alias}/.aw"
                f" && chown -R {AGENT_UID}:{AGENT_UID} /state/seats && chmod 0700 /state/seats /state/seats/{alias}"
                f" && find /state/seats/{alias}/.aw -type d -exec chmod 0700 {{}} +"
                f" && find /state/seats/{alias}/.aw -type f -exec chmod 0600 {{}} +")

    def designate_holding(self, site: Site, holder: Holder, founded: Founded) -> dict:
        """The approver's holding of the app role the round trip revokes, made
        the supported way while the owner still holds the team's key: the
        owner adds the human to the team; the human, with its own key, fetches
        its certificate, connects to the team's aweb and registers a passkey on
        the app's own human origin in the browser, for the app the owner installed on this machine; the owner
        designates that exact credential. Checked in the app's own tables."""
        machine, human = holder.container, founded.approver
        # --global for this human holder only (services and seats stay --local):
        # aw binds a holder only if its team certificate names its did:aw
        # (verifyHolderEvidence), and a did:aw on a member certificate is a
        # global identity's.
        added = self.aw(machine, "id", "team", "add-member", "--team", TEAM, "--namespace", DOMAIN,
                        "--did", founded.approver_did_key, "--did-aw", human, "--name", "approver", "--global")

        def as_human(*args: str, until: str | None = None) -> tuple[pexpect.spawn, str]:
            child = holder.act(human, *args)
            return child, holder.answer_passphrases(child, until=until)

        for args in (("--json", "id", "team", "fetch-cert", "--namespace", DOMAIN, "--team", TEAM, "--cert-id",
                      added["certificate_id"], "--registry", origin("registry")),
                     # The human's own connection to the team's aweb: the
                     # requester's does not serve this separate identity.
                     ("--json", "init", "--url", origin("aweb"), "--human-name", "approver")):
            child, output = as_human(*args)
            child.close()
            assert child.exitstatus == 0, output
        # The app is already installed on this machine: the owner installed it
        # here, in the same aw plugin directory. aw takes no --human install.
        export = f"{site.mounted}/holder/app-export.json"
        child, output = as_human("app", "credential", "register", site.app_id, "--role", site.role, "--out", export,
                                 until=r"Open this page to continue: (\S+)")
        linked = re.search(r"Open this page to continue: (\S+)", output)
        if not linked:
            child.close()
            raise SystemExit(f"FAILED: the holder's credential registration showed no page (exit {child.exitstatus}):\n{output}")
        page = linked.group(1)
        report = site.chromium(machine, "credential", "--url", page, "--device",
                               f"{site.mounted}/holder-app-device.json")
        assert report["states"] == ["ready", "navigated"] and report["credentials"] == 1, report
        child.expect(pexpect.EOF)
        rest = child.before
        child.close()
        assert child.exitstatus == 0, rest
        printed = re.search(r"Fingerprint: ([0-9a-f]{4}(?: [0-9a-f]{4}){3})", output + rest)
        assert printed, output + rest
        fingerprint = printed.group(1)
        # The owner signs only for that exact credential: aw shows its fingerprint.
        designated = docker("exec", machine, "aw", "app", "role", "designate", site.app_id, "--role", site.role,
                            "--principal", human, "--credential", export, "--yes", timeout=300)
        assert designated.returncode == 0, designated.stdout + designated.stderr
        assert fingerprint in designated.stderr, designated.stderr
        held = self.compose("exec", "-T", "postgres", "psql", "-U", "postgres", "-d", "secrets", "-At", "-c",
                            "select count(*) from public.role_assignments where role = '" + site.role
                            + "' and principal_did = '" + human + "'").strip()
        assert held == "1", held
        return {"role": site.role, "principal": human, "fingerprint": fingerprint}

    # --- the registry's real limiter, for the throttle legs -----------------

    def fill_did_key_window(self) -> dict:
        """Fill AWID's did_key window for the front's address to its limit, in
        this run's own registry Redis, with the limiter's own key, limit and
        expiry: every later read from that address in the window is refused 429
        with the limiter's own Retry-After. Waits first for a fresh window when
        too little of this one is left. Returns what it wrote and when."""
        def now() -> float:
            seconds, micros = self.compose("exec", "-T", "registry-redis", "redis-cli", "TIME").split()
            return int(seconds) + int(micros) / 1e6
        seed = did_key_window(now(), self.front_ip)
        if seed["wait"]:
            time.sleep(seed["wait"] + 0.5)
            seed = did_key_window(now(), self.front_ip)
        self.compose("exec", "-T", "registry-redis", "redis-cli", "SET", seed["key"], str(seed["limit"]),
                     "EX", str(seed["ttl"]))
        return {**seed, "seeded_at": now()}

    def since(self) -> str:
        return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    def service_log(self, service: str, since: str) -> str:
        return self.compose("logs", "--no-color", "--no-log-prefix", "--since", since, service)

    def signer_table(self) -> dict:
        """The signer's own record: each operation's id, whether it holds a
        signature, and its expiry."""
        rows = self.compose("exec", "-T", "postgres", "psql", "-U", "postgres", "-d", "signer", "-At", "-F", " ", "-c",
                            "select operation_id, result is not null, expires_at from "
                            "protected_signer.protected_signer_operations")
        table = {}
        for line in rows.splitlines():
            operation, signed, expires = line.split(" ", 2)
            table[operation] = {"signed": signed == "t", "expires_at": expires}
        return table

    def control_aw(self, machine: str) -> str:
        """The aw of the control CLI image (the caller without its throttle
        retry), copied into the machine beside its own aw. Returns its path."""
        created = run("docker", "create", self.images["cli-control"]).strip()
        try:
            run("docker", "cp", f"{created}:/usr/local/bin/aw", str(self.run_dir / "aw-control"))
        finally:
            run("docker", "rm", created)
        run("docker", "cp", str(self.run_dir / "aw-control"), f"{machine}:/tmp/aw-control")
        return "/tmp/aw-control"

    def requalify_agent(self, founded: Founded, seat: str) -> dict:
        """The real agent, over the operator's SSH, as a staged seat: aw's own
        application answer from aweb (an Inbound mode, not unknown), aw (Go)
        reading the registry, and Node reaching the registry and aweb, all over
        verified HTTPS with the agents' public CA and nothing relaxed."""
        config = str(self.run_dir / "operator" / "ssh_config")
        home = f"/state/seats/{seat}/.aw"

        def ssh(command: str) -> subprocess.CompletedProcess:
            return subprocess.run(["ssh", "-F", config, "team-agent", command], capture_output=True, text=True,
                                  timeout=120, check=False)

        trust = ssh('printf "%s %s" "$SSL_CERT_FILE" "$NODE_EXTRA_CA_CERTS"').stdout.split()
        assert trust == ["/etc/agent-trust/ca.pem", "/etc/agent-trust/ca.pem"], trust
        whoami = ssh(f"aw --identity-home {home} whoami")
        inbound = re.search(r"^Inbound:\s+(\S.*)$", whoami.stdout, re.MULTILINE)
        assert whoami.returncode == 0 and inbound and not inbound.group(1).startswith("unknown"), (
            whoami.stdout + whoami.stderr)
        resolved = ssh(f"aw --identity-home {home} --json id resolve {founded.approver}")
        assert resolved.returncode == 0, resolved.stdout + resolved.stderr
        reach = ("const https=require('node:https');const get=u=>new Promise((ok,no)=>https.get(u,r=>{r.resume();"
                 "ok(r.statusCode)}).on('error',no));"
                 f"Promise.all([get('{origin('registry')}/health'),get('{origin('aweb')}/ready')])"
                 ".then(s=>{console.log(s.join(' '))},e=>{console.error(e.code||e.message);process.exit(1)})")
        node = ssh(f'node -e "{reach}"')
        assert node.returncode == 0 and node.stdout.split() == ["200", "200"], node.stdout + node.stderr
        return {"seat": seat, "trust": trust, "inbound": inbound.group(1), "resolved": first_json(resolved.stdout),
                "node": node.stdout.split()}

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
            "redis": run("docker", "run", "--rm", "redis:7-alpine", "id", "-u", "redis").strip(),
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


# --- critical calls under the registry's real limiter ------------------------

THROTTLED = re.compile(r"RegistryThrottled: .*retry_after_seconds=([0-9.]+)")
PREPARES = re.compile(r'"POST /protected-operations HTTP/[\d.]+" (\d{3})')


def throttle_evidence(world: World, since: str) -> dict:
    """What the registry and the signer recorded since: the registry's 429s,
    the hints the signer was given, and the signer's answers to prepares."""
    registry = world.service_log("registry", since)
    signer = world.service_log("signer", since)
    return {
        "registry_429": registry.count(" 429 "),
        "hints": [float(h) for h in THROTTLED.findall(signer)],
        "prepares": [int(code) for code in PREPARES.findall(signer)],
    }


def resume(machine: str, aw_bin: str, operation: str, site: Site) -> subprocess.CompletedProcess:
    return docker("exec", machine, aw_bin, "--json", "app", "role", "resume", operation,
                  "--protected-profile", site.profile_in_machine, timeout=300)


def changed_act_leg(world: World, site: Site, holder: Holder, founded: Founded, aw_bin: str) -> dict:
    """Run 22's failure, made certain: a changed act resent from aw's saved
    request while the registry refuses the signer's key lookups. The signer
    answers 503 with the registry's Retry-After; aw waits it and resends the
    same changed bytes, which the signer refuses operation_conflict, signing
    nothing."""
    machine, approver = holder.container, founded.approver
    saved = site.runtime / "holder" / ".config" / "aw" / "governance"
    child, page, operation, _ = start_revoke(site, machine, approver)
    report = approve(site, machine, page, "--approve-uv", "no")
    assert report["states"][-1] == "ready", report
    child.sendintr()
    finish(child)
    written = json.dumps(changed_act(json.loads((saved / f"{operation}.json").read_text()), site.role + "-other"))
    (saved / f"{operation}.json").write_text(written)
    expires = world.signer_table()[operation]["expires_at"]
    seed = world.fill_did_key_window()
    since, started = world.since(), time.monotonic()
    result = resume(machine, aw_bin, operation, site)
    elapsed = time.monotonic() - started
    after = world.signer_table()[operation]
    return {
        "operation": operation, "seed": seed, "elapsed": round(elapsed, 1), **throttle_evidence(world, since),
        "code": first_json(result.stdout).get("error", {}).get("code") if result.returncode else "ok",
        "signed": after["signed"], "expires_unchanged": after["expires_at"] == expires,
        "saved_unchanged": (saved / f"{operation}.json").read_text() == written,
    }


def lost_prepare_leg(world: World, site: Site, holder: Holder, founded: Founded, aw_bin: str) -> dict:
    """A lost prepare answer resumed while the registry refuses the signer's
    key lookups: aw waits the hint, resends the saved bytes, and once
    approved the original operation completes with one signature."""
    machine, approver = holder.container, founded.approver
    saved = site.runtime / "holder" / ".config" / "aw" / "governance"
    site.drop_prepare_answers(True)
    try:
        lost = docker("exec", machine, "aw", "--json", "app", "role", "revoke", site.app_id, "--role", site.role,
                      "--principal", approver, "--protected-profile", site.profile_in_machine, "--approver", approver,
                      timeout=240)
    finally:
        site.drop_prepare_answers(False)
    assert first_json(lost.stdout)["error"]["code"] == "prepare_unconfirmed", lost.stdout
    operation = re.search(r"Preparing operation (\S+)", lost.stderr).group(1)
    request = (saved / f"{operation}.json").read_text()
    before = world.signer_table()
    signed_before = sum(row["signed"] for row in before.values())
    seed = world.fill_did_key_window()
    since, started = world.since(), time.monotonic()
    child = pexpect.spawn("docker", ["exec", "-it", machine, aw_bin, "--json", "app", "role", "resume", operation,
                                     "--protected-profile", site.profile_in_machine],
                          encoding="utf-8", timeout=300, echo=False)
    evidence = {"operation": operation, "seed": seed}
    index = child.expect([r"Approve it on this page: (\S+)", pexpect.EOF])
    evidence["waited"] = round(time.monotonic() - started, 1)
    if index == 0:
        report = approve(site, machine, child.match.group(1))
        assert report["states"] == ["login-required", "ready", "navigated"], report
        status, output = finish(child)
        receipt = first_json(output)
        evidence["state"] = receipt.get("state") if status == 0 else first_json(output)["error"]["code"]
    else:
        child.close()
        evidence["state"] = first_json(child.before)["error"]["code"]
    after = world.signer_table()
    evidence.update(throttle_evidence(world, since))
    evidence.update({
        "rows_for_operation": sum(1 for op in after if op == operation),
        "signed": after[operation]["signed"],
        "new_signatures": sum(row["signed"] for row in after.values()) - signed_before,
        "expires_unchanged": after[operation]["expires_at"] == before[operation]["expires_at"],
        "request_was_saved": bool(request),
    })
    return evidence


def throttled_calls(world: World, site: Site, holder: Holder, founded: Founded) -> None:
    """Both legs with the candidate's aw, then with the control aw, whose
    caller does not wait out the hint and so must not recover."""
    for name, aw_bin in (("candidate", "aw"), ("control", world.control_aw(holder.container))):
        changed = changed_act_leg(world, site, holder, founded, aw_bin)
        lost = lost_prepare_leg(world, site, holder, founded, aw_bin)
        (world.run_dir / f"throttle-{name}.json").write_text(json.dumps({"changed_act": changed, "lost_prepare": lost},
                                                                       indent=2))
        print(f"throttle {name}:", json.dumps({"changed_act": changed, "lost_prepare": lost}, sort_keys=True))
        for leg in (changed, lost):
            # The fixture worked only if the registry really refused, past the SDK's budget.
            assert leg["registry_429"] >= 1 and leg["hints"] and min(leg["hints"]) > 5, leg
            assert leg["prepares"][0] == 503, leg
            assert leg["expires_unchanged"], leg
        if name == "candidate":
            assert changed["code"] == "operation_conflict" and changed["prepares"][-1] == 409, changed
            assert changed["elapsed"] >= min(changed["hints"]) - 1, changed
            assert changed["signed"] is False and changed["saved_unchanged"], changed
            assert lost["state"] == "committed" and lost["waited"] >= min(lost["hints"]) - 1, lost
            assert lost["signed"] and lost["rows_for_operation"] == 1 and lost["new_signatures"] == 1, lost
        else:
            assert changed["code"] != "operation_conflict" and changed["signed"] is False, changed
            assert lost["state"] != "committed" and lost["new_signatures"] == 0, lost


# Every image scripts/e2e/team-deployment-images.sh builds for the journey;
# cli-control is the CLI the throttle legs expect not to recover (no caller retry).
REQUIRED_IMAGES = {"aweb", "aweb-protected", "secrets", "logs", "awid", "cli", "cli-control", "chromium"}


def load_images(path: Path) -> dict[str, str]:
    images = {}
    for line in path.read_text().splitlines():
        name, _, reference = line.partition(" ")
        if "@sha256:" in reference:
            images[name] = reference
    missing = REQUIRED_IMAGES - set(images)
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
    parser.add_argument("--agents-only", action="store_true",
                        help="provision the signer, then go straight to the agents stage: no holding, protected"
                             " round trip, refusals or throttle legs")
    parser.add_argument("--stop-after", choices=["holding"],
                        help="end the journey after this setup step: holding, the approver's app holding")
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
        return journey(world, stop_after=args.stop_after, agents_only=args.agents_only)
    finally:
        if not args.keep:
            print("=== Teardown")
            down = subprocess.run([str(ADAPTER), "compose", "down", str(world.deployment_path)], env=world.env,
                                  text=True, check=False)
            print("DOWN: nothing of the project is left" if down.returncode == 0 else "DOWN FAILED: see above")


def journey(world: World, stop_after: str | None = None, agents_only: bool = False) -> int:
    print("=== Setup: the test world")
    world.write_world()
    world.write_database_files()
    world.write_redis_files()
    world.deployment()
    world.compose("up", "-d", "--wait", "dns", "registry", "front", "smtp")
    site = world.site()
    holder = Holder(world.machine("holder"), DOMAIN)

    print("=== Setup: namespace, root human, team and service members, through the real aw")
    founded = found_team(site, holder)
    world.write_service_files(holder.container)
    # The agents' seats are admitted now, while the owner holds the team's
    # key; the protected act below moves it into the signer's custody.
    seats = [world.admit_seat(holder.container, alias) for alias in SEATS]
    print("seats admitted:", json.dumps(seats, sort_keys=True))
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
    if not agents_only:
        print("=== Setup: the owner designates the approver's holding of the app role, before the signer holds the key")
        designated = world.designate_holding(site, holder, founded)
        print("HOLDING:", json.dumps({k: designated[k] for k in ("role", "principal")}))
        if stop_after == "holding":
            print("STOPPED: after the approver's holding, as asked")
            return 0

    print("=== Step 5: the protected act")
    provision_signer(site, holder, founded)
    isolated = world.redis_isolation({"aweb", "redis", "secrets", "logs", "signer"})
    print("REDIS ISOLATED:", json.dumps(isolated, sort_keys=True))
    if agents_only:
        print("AGENTS ONLY: the signer is provisioned; no round trip, refusals or throttle legs in this run")
    else:
        protected_act(world, site, holder, founded)
    if "agent" not in world.images:
        print("AGENTS: not in this run (no agent or egress image)")
        return 0
    return agents_stage(world, founded)


def protected_act(world: World, site: Site, holder: Holder, founded: Founded) -> None:
    operation = round_trip(site, holder, founded)
    print(f"SIGNED: {operation} committed, approved in the browser, receipt read by aw")
    refusals(site, holder, founded)
    print("REFUSED: no UV signs nothing; a changed act is operation_conflict; a lost prepare completes once")

    print("=== Step 6: critical calls under the registry's real limiter")
    throttled_calls(world, site, holder, founded)
    print("THROTTLED: a changed act waits out the registry's Retry-After and is operation_conflict; a lost prepare"
          " waits it out and completes once; the control aw recovers from neither")


def agents_stage(world: World, founded: Founded) -> int:
    print("=== Step 2: the agents, behind egress")
    world.configure_agents()
    status = world.up()
    if status != 3:
        print("BOUNDARY: the agents stage did not come up; see the adapter's output")
        return 1
    world.operator_ssh()
    world.stage_seats(SEATS)
    print("AGENTS: the ingress and boundary probes passed, the agent container passed its acceptance, the operator"
          " reaches it over pinned SSH and two member seats are staged")
    requalified = world.requalify_agent(founded, SEATS[0])
    print("REQUALIFIED:", json.dumps(requalified, sort_keys=True))
    isolated = world.redis_isolation({"aweb", "redis", "secrets", "logs", "signer", "egress", "agent"})
    print("REDIS ISOLATED:", json.dumps(isolated, sort_keys=True))
    print("AGENTS HELD: no harness login, deployment or session; wake and model are not run")
    return 0


if __name__ == "__main__":
    sys.exit(main())
