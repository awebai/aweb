"""The team deployment journey on one machine.

    uv run --project naapp/secrets python scripts/e2e/team_deployment_journey.py \\
        --run-dir DIR --project NAME --images IMAGES

IMAGES lists one pinned image per line, "<name> <repository@sha256:...>", for
aweb, secrets, logs, awid, cli and chromium, all built from one
source commit.

Setup makes a disposable world in the deployment's own services network
(deploy/team/compose.test.yaml): an AWID registry, DNS for its namespace,
captured SMTP and a TLS front that refuses a Host its SNI does not name. On the
holder's machine the real aw founds the namespace, its root human (the
approver) and the team, and admits each service as an ordinary member; each
service holds only its own member key and certificate. The deployment starts
through the Compose adapter (scripts/e2e-team-deployment.sh), and the team's
owner installs Secrets and Logs after the operator's install-owner grant.

The owner activates the apps' hook bindings and optionally designates the
approver's holding. The ordinary deployment and agents stages then continue. Approval-service refusal, revoke, throttle and replay acceptance is
deferred to adcl.6; this journey establishes none of those gates.

The agents wait for the egress boundary.

No credential is printed. Each one is a file the service that owns it mounts.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

import yaml
from aweb_naapp_contracts_testing.network import make_certificates

REPO = Path(__file__).resolve().parents[2]
TEAM_DIR = REPO / "deploy" / "team"
ADAPTER = REPO / "scripts" / "e2e-team-deployment.sh"
TEAMCTL = REPO / "deploy" / "team" / "teamctl"
sys.path.insert(0, str(REPO / "naapp" / "secrets" / "e2e"))

from team_journey_support import (  # noqa: E402
    Founded,
    Holder,
    Site,
    activate_hooks,
    connect_requester,
    designate_holding,
    first_json,
    found_team,
    hook_app_ids,
    install_app,
    publish_team_server,
    read_only_psql,
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
# The deployment's front and the world's registry front run this Caddy.
FRONT_IMAGE = "caddy:2.10-alpine"
# The role assigned by the designate setup for this deployment's Secrets app.
ROLE = "secrets.owner"
# The uid used by the ordinary member agents.
AGENT_UID = 20001
# The component directories an operator-provided secrets directory holds,
# pre-created by root for the staging user, who cannot create them in a
# root-owned parent. agents/ is the OATS credential receiver's.
OPERATOR_COMPONENTS = ("postgres", "redis", "aweb", "secrets", "logs", "front")


def check_operator_secrets(secrets: Path, *, root_uid: int = 0, staging_uid: int | None = None,
                           agents_gid: int = AGENT_UID) -> None:
    """An operator-provided secrets directory (--secrets-dir), checked before
    anything is staged: root-owned and writable by root alone, as the OATS
    credential receiver requires of its login directory's ancestors; each
    component directory pre-created, empty, the staging user's and private (0700); and
    agents/ the receiver's (root:<agents' gid> 0750), whose contents are never
    read. The parent is checked first, so the children of a directory that is
    not root's (a kept run's own secrets, say) are never examined."""
    staging_uid = os.getuid() if staging_uid is None else staging_uid
    if not secrets.is_absolute():
        raise SystemExit(f"FAILED: --secrets-dir {secrets} must be absolute")
    try:
        parent = os.lstat(secrets)
    except FileNotFoundError:
        raise SystemExit(f"FAILED: the secrets directory {secrets} does not exist") from None
    if stat.S_ISLNK(parent.st_mode) or not stat.S_ISDIR(parent.st_mode):
        raise SystemExit(f"FAILED: the secrets directory {secrets} is a symlink or not a directory")
    if parent.st_uid != root_uid:
        raise SystemExit(f"FAILED: the secrets directory {secrets} is not root-owned")
    if parent.st_mode & 0o022:
        raise SystemExit(f"FAILED: the secrets directory {secrets} is group- or other-writable")
    for component in OPERATOR_COMPONENTS:
        try:
            child = os.lstat(secrets / component)
        except FileNotFoundError:
            raise SystemExit(f"FAILED: {component}: not pre-created in {secrets}") from None
        if stat.S_ISLNK(child.st_mode) or not stat.S_ISDIR(child.st_mode):
            raise SystemExit(f"FAILED: {component}: not a directory")
        if child.st_uid != staging_uid:
            raise SystemExit(f"FAILED: {component}: not owned by the staging user")
        # Credentials are written with the caller's umask before own()
        # chowns and chmods them: only a private directory keeps them out of
        # reach meanwhile.
        if child.st_mode & 0o077:
            raise SystemExit(f"FAILED: {component}: must be private to the staging user (0700)")
        if any((secrets / component).iterdir()):
            raise SystemExit(f"FAILED: {component}: not empty")
    try:
        login = os.lstat(secrets / "agents")
    except FileNotFoundError:
        login = None
    if (login is None or stat.S_ISLNK(login.st_mode) or not stat.S_ISDIR(login.st_mode)
            or login.st_uid != root_uid or login.st_gid != agents_gid or stat.S_IMODE(login.st_mode) != 0o750):
        raise SystemExit(f"FAILED: agents: must be root-owned, group {agents_gid}, mode 0750: the credential"
                         " receiver's login directory")


def origin(name: str) -> str:
    return f"https://{HOSTS[name]}"


# One role and database per name, created at the bundled server's first start,
# and the file under the secrets directory that holds its whole DSN. Logs'
# purge ledger is a database of its own: Logs refuses a ledger DSN that
# reaches its content database.
DATABASES = {
    "aweb": "aweb/database-url",
    "secrets": "secrets/database-url",
    "logs": "logs/database-url",
    "logsledger": "logs/purge-ledger-database-url",
}

def run(*args: str, env: dict[str, str] | None = None, input: str | None = None, timeout: int = 600) -> str:
    result = subprocess.run(args, env=env, input=input, text=True, capture_output=True, timeout=timeout, check=False)
    if result.returncode != 0:
        raise SystemExit(f"FAILED: {' '.join(args[:6])} ...\n{result.stdout[-3000:]}\n{result.stderr[-3000:]}")
    return result.stdout


def front_image() -> str:
    """The front's Caddy image, by the digest it was pulled at."""
    if subprocess.run(["docker", "image", "inspect", FRONT_IMAGE], capture_output=True, check=False).returncode != 0:
        run("docker", "pull", "-q", FRONT_IMAGE)
    return run("docker", "image", "inspect", "--format", "{{index .RepoDigests 0}}", FRONT_IMAGE).strip()


def image_user(image: str) -> str:
    """The uid the image runs as, so its files belong to it."""
    user = run("docker", "image", "inspect", "--format", "{{.Config.User}}", image).strip()
    return user.split(":")[0]


class World:
    def __init__(self, run_dir: Path, project: str, images: dict[str, str], cidr: str,
                 secrets_dir: Path | None = None):
        self.run_dir, self.project, self.images = run_dir, project, images
        self.world = run_dir / "world"
        self.deployment_path = run_dir / "deployment.yaml"
        # The run's own secrets directory, or an operator-provided one
        # (check_operator_secrets) whose component directories already exist
        # and whose agents/ login directory is the credential receiver's.
        self.operator_secrets = secrets_dir is not None
        self.secrets = secrets_dir if secrets_dir is not None else run_dir / "secrets"
        self.agents_configured = False
        self.oats_source: Path | None = None
        network = ipaddress.ip_network(cidr)
        self.cidr = cidr
        top = network.broadcast_address
        # The world's front serves the registry alone, as the operator's
        # registry is served apart from the team's deployment; the bundle's
        # own front (deploy/team/compose.front.yaml) serves every origin of
        # the deployment at ingress_ip.
        self.registry_front_ip, self.dns_ip, self.smtp_ip = (str(top - 5), str(top - 4), str(top - 3))
        self.ingress_ip = str(top - 6)
        self.env = {
            **os.environ,
            "TEAM_DEPLOYMENT_PROJECT": project,
            "TEAM_DEPLOYMENT_RUN_DIR": str(run_dir),
            "TEAM_DEPLOYMENT_COMPOSE_FILES": f"{TEAM_DIR / 'compose.test.yaml'}:{self.world / 'compose.trust.yaml'}",
            "TEST_WORLD_DIR": str(self.world),
            "TEST_DNS_IP": self.dns_ip,
            "TEST_FRONT_IP": self.registry_front_ip,
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
        (self.world / "tls-renewal").mkdir()
        (self.world / "front").mkdir()
        (self.world / "dns" / "Corefile").write_text(
            f"{DOMAIN}:53 {{\n  errors\n  file /zones/{DOMAIN}.zone {DOMAIN} {{ reload 1s }}\n}}\n"
            ".:53 {\n  errors\n  forward . 127.0.0.11\n}\n"
        )
        self.publish_controller("did:key:z6MkpendingpendingpendingpendingpendingpendingpendingP")
        tls = make_certificates(self.world / "tls", [*HOSTS.values(), MAIL], [])
        # The certificate the deployment's front is renewed to, from an
        # authority every client of this world trusts from the start beside
        # the first.
        renewal = make_certificates(self.world / "tls-renewal", [HOSTS[name] for name in HOSTS if name != "registry"], [])
        tls.ca_file.write_bytes(tls.ca_file.read_bytes() + renewal.ca_file.read_bytes())
        (self.world / "front" / "Caddyfile").write_text(
            # As the deployment's front has it (render_env.py --front).
            "{\n  auto_https off\n  servers {\n    strict_sni_host on\n  }\n}\n"
            f"{HOSTS['registry']}:443 {{\n  tls /tls/{tls.cert_file.name} /tls/{tls.key_file.name}\n"
            f"  @misdirected not header_regexp Host ^{re.escape(HOSTS['registry'])}(:443)?$\n"
            "  respond @misdirected 421\n"
            f"  reverse_proxy {UPSTREAMS['registry']}\n}}\n"
        )
        for path in [*(self.world / "tls").iterdir(), *(self.world / "tls-renewal").iterdir(),
                     *(self.world / "front").iterdir(), *(self.world / "dns").iterdir()]:
            path.chmod(0o644)
        # The services read these as their own non-root users, whatever the
        # launching shell's umask made of the directories.
        for directory in ("tls", "tls-renewal", "front", "dns"):
            (self.world / directory).chmod(0o755)

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
        # The deployment's front at the address this world's DNS gives every
        # origin of the deployment.
        trust["front"] = {"networks": {"services": {"ipv4_address": self.ingress_ip}}}
        (self.world / "compose.trust.yaml").write_text(yaml.safe_dump({"services": trust}))

    def publish_controller(self, controller_did: str) -> None:
        self.controller_did = controller_did
        zone = self.world / "dns" / f"{DOMAIN}.zone"
        records = "".join(
            f"{host.removesuffix('.' + DOMAIN)} IN A {self.registry_front_ip if name == 'registry' else self.ingress_ip}\n"
            for name, host in HOSTS.items()
        )
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
        """One role and database per name in DATABASES; the password is in the
        role's file for the bundled server and in the whole URL its component
        reads. The roles exist only from the bundled server's first start."""
        roles = self.secrets / "postgres" / "roles"
        roles.mkdir(parents=True)
        (self.secrets / "postgres" / "password").write_text(secrets.token_hex(24))
        for role, dsn_file in DATABASES.items():
            password = secrets.token_hex(24)
            (roles / role).write_text(password)
            (self.secrets / dsn_file).parent.mkdir(exist_ok=True)
            (self.secrets / dsn_file).write_text(f"postgresql://{role}:{password}@postgres:5432/{role}\n")

    def write_redis_files(self) -> None:
        """Redis holds the password's SHA-256 in its ACL file; aweb holds the
        password in its whole Redis URL."""
        password = secrets.token_hex(24)
        self.component("redis")
        (self.secrets / "redis" / "users.acl").write_text(
            f"user default on #{hashlib.sha256(password.encode()).hexdigest()} ~* &* +@all\n"
        )
        (self.secrets / "aweb").mkdir(exist_ok=True)
        (self.secrets / "aweb" / "redis-url").write_text(f"redis://default:{password}@redis:6379/0\n")

    def local_members(self) -> dict:
        """Every service and seat member holds a local certificate: it names
        no did:aw and no address, so no registry address routes to it."""
        certificates = [*self.world.glob("*-member/identity/.aw/team-certs/*.pem"),
                        *self.world.glob("seat-*/.aw/team-certs/*.pem")]
        scopes = {}
        for certificate in certificates:
            body = json.loads(certificate.read_text())
            assert not body.get("member_did_aw") and not body.get("member_address"), (
                f"member scope: {body['alias']} names a did:aw or an address")
            scopes[body["alias"]] = body["identity_scope"]
        expected = {f"{name}-service" for name in ("aweb", "secrets", "logs")} | set(SEATS)
        assert scopes == {alias: "local" for alias in expected}, f"member scope: {scopes}"
        return scopes

    def member_mail(self, holder: str) -> dict:
        """A seat's mail reaches the other seat; a non-member's does not. The
        non-member is a member of another team of the namespace, with its own
        certificate, so the real aw takes its requests to the team's aweb: the
        server refuses its session, and with none it has nothing to send
        from. No registry address names a seat, so no route from another
        server leads to one. The positive controls: a member's mail arrives,
        and the owner's address resolves."""
        first, second = (f"{self.project}-seat-{alias}" for alias in SEATS)
        for alias in SEATS:
            self.aw(f"{self.project}-seat-{alias}", "workspace", "connect", "--service", origin("aweb"))
        member_subject = f"member-{secrets.token_hex(4)}"
        self.aw(second, "mail", "send", "--to", SEATS[0], "--subject", member_subject, "--body", "a member's mail")

        def resolved(name: str) -> dict:
            return self.aw(holder, "id", "namespace", "resolve", f"{DOMAIN}/{name}")["payload"]

        owner = resolved("owner")
        assert owner.get("address", {}).get("name") == "owner", f"member mail: the owner's address: {owner}"
        seat = resolved(SEATS[0])
        assert seat["status"] == "fail" and seat["error"]["code"] == "target.not_found", (
            f"member mail: a seat's address resolves: {seat}")

        # The outsider: a local member of another team, admitted by the same owner.
        self.aw(holder, "id", "team", "create", "--name", "outside", "--namespace", DOMAIN,
                "--registry", origin("registry"))
        (self.world / "outsider").mkdir(mode=0o700)

        def as_outsider(*args: str) -> subprocess.CompletedProcess:
            return subprocess.run(["docker", "exec", "-w", "/world/outsider", holder, "aw", "--json", *args],
                                  capture_output=True, text=True, timeout=300, check=False)

        requested = first_json(as_outsider("id", "team", "request", "--create-local-key", "--team",
                                           f"outside:{DOMAIN}", "--name", "outsider").stdout)
        added = self.aw(holder, "id", "team", "add-member", "--team", "outside", "--namespace", DOMAIN,
                        "--did", requested["did_key"], "--name", "outsider", "--local")
        fetched = as_outsider("id", "team", "fetch-cert", "--namespace", DOMAIN, "--team", "outside",
                              "--cert-id", added["certificate_id"], "--registry", origin("registry"))
        assert fetched.returncode == 0, fetched.stdout + fetched.stderr

        def refused(result: subprocess.CompletedProcess, what: str) -> str:
            output = result.stdout + result.stderr
            assert result.returncode != 0, f"member mail: the outsider's {what} was not refused: {output[-500:]}"
            error = first_json(output).get("error", {}).get("message", "") if "{" in output else output.strip()
            return error[-300:]

        connect = refused(as_outsider("workspace", "connect", "--service", origin("aweb")), "connect")
        assert "/v1/connect returned 403" in connect and "is not served by this server" in connect, (
            f"member mail: aweb did not refuse the outsider's connect as a team it does not serve: {connect}")
        outsider_subject = f"outsider-{secrets.token_hex(4)}"
        send = refused(as_outsider("mail", "send", "--to", SEATS[0], "--subject", outsider_subject,
                                   "--body", "a non-member's mail"), "mail")
        inbox = json.dumps(self.aw(first, "mail", "inbox", "--show-all"))
        assert member_subject in inbox, "member mail: the member's mail did not arrive"
        assert outsider_subject not in inbox, "member mail: the non-member's mail arrived"
        whoami = self.aw(first, "whoami")
        return {"member_delivered": True, "owner_address": owner["address"]["name"],
                "seat_address": seat["error"]["code"], "outsider_team": f"outside:{DOMAIN}",
                "outsider_connect": connect, "outsider_send": send, "outsider_delivered": False,
                "seat_scope": whoami.get("identity_scope"), "seat_inbound": whoami.get("inbound_mode"),
                "seat_inbound_configurable": whoami.get("inbound_configurable")}

    def served_front_certificate(self, host: str) -> str:
        """The SHA-256 of the certificate the deployment's front serves for
        host, asked over TLS with that SNI from the services network."""
        return run("docker", "run", "--rm", "--network", f"{self.project}_services", "--entrypoint", "python",
                   self.images["aweb"], "-c",
                   "import hashlib, socket, ssl, sys\n"
                   "context = ssl.create_default_context()\n"
                   "context.check_hostname = False\n"
                   "context.verify_mode = ssl.CERT_NONE\n"
                   "with socket.create_connection(('front', 443), timeout=10) as raw,"
                   " context.wrap_socket(raw, server_hostname=sys.argv[1]) as tls:\n"
                   "    print(hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest())\n",
                   host).strip()

    def front_renewal(self) -> dict:
        """The operator renews the front's certificate: with a key that is not
        the new certificate's, teamctl reload-tls refuses and the front keeps
        serving the old one; with both new files, it reloads and every host
        serves the new certificate."""
        host = HOSTS["aweb"]
        before = self.served_front_certificate(host)

        def install(certificate: Path, key: Path) -> None:
            run("docker", "run", "--rm", "-v", f"{self.secrets / 'front'}:/front", "-v", f"{certificate}:/new.pem:ro",
                "-v", f"{key}:/new.key:ro", "alpine:3.22", "sh", "-c",
                "cat /new.pem > /front/certificate.pem && cat /new.key > /front/key.pem"
                " && chown 0:0 /front/certificate.pem /front/key.pem && chmod 0400 /front/certificate.pem /front/key.pem")

        def reload() -> subprocess.CompletedProcess:
            return subprocess.run([str(TEAMCTL), "reload-tls", str(self.deployment_path)], env=self.env,
                                  capture_output=True, text=True, timeout=300, check=False)

        renewal = self.world / "tls-renewal"
        install(renewal / "server.pem", self.world / "tls" / "server.key")
        mismatched = reload()
        assert mismatched.returncode != 0 and "not the certificate key" in mismatched.stderr, (
            mismatched.stdout + mismatched.stderr)
        kept = self.served_front_certificate(host)
        assert kept == before, "front renewal: a refused reload changed the served certificate"
        install(renewal / "server.pem", renewal / "server.key")
        renewed = reload()
        assert renewed.returncode == 0, renewed.stdout + renewed.stderr
        after = self.served_front_certificate(host)
        assert after != before, "front renewal: the front still serves the old certificate"
        return {"before": before[:16], "refused": mismatched.stderr.strip().splitlines()[-1],
                "kept": kept == before, "after": after[:16], "reload": renewed.stdout.strip().splitlines()[-1]}

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
                # --init: without it redis-cli is the container's PID 1, which
                # the timeout's TERM cannot stop (seen on run32).
                ["docker", "run", "--rm", "-i", "--init", "--network", f"container:{containers[service]}",
                 "redis:7-alpine", "timeout", "5", "redis-cli", "-h", address[0], "-p", "6379"],
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
            "team": {"id": TEAM_ID, "registryUrl": origin("registry"), "registryRoute": "local",
                     "namespaceAuthorities": [{"domain": DOMAIN, "controllerDidKey": self.controller_did}]},
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
            config["egress"] = {"image": self.images["egress"],
                                "privateIngressAddresses": [self.ingress_ip, self.registry_front_ip]}
        # Published on the lab machine's loopback alone: its clients are on
        # the services network.
        config["front"] = {"image": front_image(), "compose": {"bindAddress": "127.0.0.1", "port": 18443}}
        path = self.run_dir / "deployment.yaml"
        path.write_text(yaml.safe_dump(config, sort_keys=False))
        self.write_trust(["aweb", *(name for name in ("secrets", "logs") if name in config)])
        self.render(path)
        return path

    # --- running --------------------------------------------------------

    def connect(self) -> dict:
        return json.loads(run(str(ADAPTER), "compose", "connect", str(self.deployment_path), env=self.env))

    def compose(self, *args: str, input: str | None = None) -> str:
        """The deployment's own docker compose command, as the adapter gives it."""
        return run(*self.connect()["compose"], *args, env=self.env, input=input)

    def render(self, deployment: Path) -> None:
        """What Compose reads, written the operator's way (teamctl render)."""
        run(str(TEAMCTL), "render", str(deployment), env=self.env)
        self.deployment_path = deployment

    def up(self) -> int:
        """The adapter's up: every service healthy, internal origins inside
        the services range, every service ready. 3 means the agents are held."""
        result = subprocess.run([str(ADAPTER), "compose", "up", str(self.deployment_path)], env=self.env, text=True,
                                check=False)
        connect = json.dumps(self.connect(), indent=2)
        (self.run_dir / "connect.json").write_text(connect)
        return result.returncode

    def component(self, name: str) -> Path:
        """A component's secrets directory: made here for the run's own
        secrets directory, pre-created by root in an operator's."""
        path = self.secrets / name
        if not self.operator_secrets:
            path.mkdir()
        return path

    def configure_agents(self) -> None:
        """The team container's state, SSH keys and login directory: state
        owned by the agents' uid, the login directory readable only by their
        group, and no harness login in it for this run."""
        (self.world / "agent-state").mkdir()
        (self.world / "agent-authorized-keys").write_text("")
        (self.run_dir / "operator").mkdir(mode=0o700)
        shutil.copyfile(self.world / "tls" / "ca.pem", self.run_dir / "agent-ca.pem")
        (self.run_dir / "agent-ca.pem").chmod(0o644)
        if self.operator_secrets:
            # The receiver owns the login directory and its token.
            run("docker", "run", "--rm", "-v", f"{self.world / 'agent-state'}:/state", "alpine:3.22", "sh", "-c",
                f"chown {AGENT_UID}:{AGENT_UID} /state")
        else:
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
        # The same calls with trust that leaves the agents' CA out fail
        # certificate verification: the positives above rest on that CA. The
        # trust is changed for these processes only; the session's files stay.
        system = ssh("test -s /etc/ssl/certs/ca-certificates.crt")
        assert system.returncode == 0, "the agent image has no system CA bundle to stand for trust without the agents' CA"
        go = ssh(f"SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt SSL_CERT_DIR=/nonexistent "
                 f"aw --identity-home {home} --json id resolve {founded.approver}")
        go_output = go.stdout + go.stderr
        assert go.returncode != 0 and "x509: certificate signed by unknown authority" in go_output, go_output
        untrusted = ssh(f'env -u NODE_EXTRA_CA_CERTS -u SSL_CERT_FILE node -e "{reach}"')
        node_refusal = untrusted.stderr.strip()
        assert untrusted.returncode != 0 and node_refusal in {
            "UNABLE_TO_VERIFY_LEAF_SIGNATURE", "UNABLE_TO_GET_ISSUER_CERT_LOCALLY", "SELF_SIGNED_CERT_IN_CHAIN",
        }, untrusted.stdout + untrusted.stderr
        return {"seat": seat, "trust": trust, "inbound": inbound.group(1), "resolved": first_json(resolved.stdout),
                "node": node.stdout.split(),
                "without_the_agents_ca": {"go": "x509: certificate signed by unknown authority", "node": node_refusal}}

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

    def write_front_files(self) -> None:
        """The deployment's front holds this world's certificate for every
        origin, as an operator's front holds theirs."""
        self.component("front")
        shutil.copyfile(self.world / "tls" / "server.pem", self.secrets / "front" / "certificate.pem")
        shutil.copyfile(self.world / "tls" / "server.key", self.secrets / "front" / "key.pem")

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
            # Caddy runs as root.
            "front": "0",
            "aweb": image_user(self.images["aweb"]),
            "secrets": image_user(self.images["secrets"]),
            "logs": image_user(self.images["logs"]),
        }
        self.own(owners)
        return owners

    def install_apps(self, machine: str, owner_did_key: str) -> None:
        """The owner publishes the team's coordination server at the registry,
        signed by the team's key, which installed apps read to reach it; the
        operator's explicit install-owner grant; then the owner installs
        Secrets and Logs from their internal origins. Membership alone grants
        no install authority."""
        print("TEAM SERVER:", json.dumps(publish_team_server(machine, TEAM, DOMAIN, origin("aweb"), origin("registry")),
                                           sort_keys=True))
        self.compose("exec", "-T", "aweb", "aweb", "install-admin", "grant", "--team-id", TEAM_ID,
                     "--principal-did", owner_did_key, "--role", "owner")
        for app in ("secrets", "logs"):
            install_app(machine, origin(f"{app}-api"))
            print(f"INSTALLED: {app} from {origin(app + '-api')}")

    # --- shared ordinary app setup --------------------------------

    def site(self) -> Site:
        def chromium(machine: str, *args: str) -> dict:
            # As the host user, so the journey reads what the driver writes; its
            # NSS database lives in a HOME of its own.
            out = run("docker", "run", "--rm", f"--network=container:{machine}", "-v", f"{self.world}:/world",
                      "--user", f"{os.getuid()}:{os.getgid()}", "-e", "HOME=/tmp",
                      self.images["chromium"], *args, "--ca", "/world/tls/ca.pem", timeout=300).strip()
            return first_json(out) if "{" in out else {}


        def reload_front() -> None:
            self.compose("exec", "-T", "front", "caddy", "reload", "--config", "/etc/caddy/Caddyfile",
                         "--adapter", "caddyfile")


        def secrets_query(select: str) -> str:
            return self.compose("exec", "-T", "postgres", *read_only_psql("postgres", "secrets", select)).strip()

        return Site(
            runtime=self.world, mounted="/world", domain=DOMAIN, team=TEAM, registry=origin("registry"),
            aweb=origin("aweb"),
            app_id=f"{TEAM}-secrets", logs_app_id=f"{TEAM}-logs", secrets_schema="public", role=ROLE,
            contact=f"approver@{DOMAIN}", mail_api=f"http://{MAIL}:8025",
            publish_controller=self.publish_controller,
            chromium=chromium,
            secrets_query=secrets_query,
            front_log=lambda: self.compose("logs", "--no-color", "--no-log-prefix", "front"),
        )


# --- critical calls under the registry's real limiter ------------------------


# Every image scripts/e2e/team-deployment-images.sh builds for the journey;
REQUIRED_IMAGES = {"aweb", "secrets", "logs", "awid", "cli", "chromium"}


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
    parser.add_argument("--secrets-dir", type=Path,
                        help="an operator-provided, root-owned secrets directory whose component directories root"
                             " pre-created and whose agents/ the OATS credential receiver owns; default: the run's own")
    parser.add_argument("--keep", action="store_true", help="leave the deployment running for inspection")
    parser.add_argument("--agents-only", action="store_true",
                        help="skip the approver's holding (designate); hooks are activated directly")
    parser.add_argument("--stop-after", choices=["holding"],
                        help="end the journey after this setup step: holding, the approver's app holding")
    args = parser.parse_args()
    run_dir = args.run_dir.resolve()
    if run_dir.exists():
        raise SystemExit(f"FAILED: {run_dir} exists; each run has its own directory")
    if args.secrets_dir is not None:
        check_operator_secrets(args.secrets_dir)
    run_dir.mkdir(parents=True)
    world = World(run_dir, args.project, load_images(args.images), args.services_cidr, secrets_dir=args.secrets_dir)
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
    world.write_front_files()
    world.deployment()
    world.compose("up", "-d", "--wait", "dns", "registry", "world-front", "smtp")
    site = world.site()
    holder = Holder(world.machine("holder"), DOMAIN)

    print("=== Setup: namespace, root human, team and service members, through the real aw")
    founded = found_team(site, holder)
    world.write_service_files(holder.container)
    # The agents' seats are admitted now, while the owner holds the team's
    # key, using ordinary team admission.
    seats = [world.admit_seat(holder.container, alias) for alias in SEATS]
    print("seats admitted:", json.dumps(seats, sort_keys=True))
    owners = world.own_service_files()
    print("service file owners:", json.dumps(owners, sort_keys=True))

    print("=== Step 1: bring up the deployment")
    if world.up() != 0:
        print("BOUNDARY: the deployment did not come up; see compose.log in the run directory")
        return 1
    print("UP: aweb, secrets and logs are ready")
    print("FRONT RENEWED:", json.dumps(world.front_renewal(), sort_keys=True))
    connect_requester(site, holder)
    print("LOCAL MEMBERS:", json.dumps(world.local_members(), sort_keys=True))
    print("MEMBER MAIL:", json.dumps(world.member_mail(holder.container), sort_keys=True))
    print("=== Setup: the team owner installs Secrets and Logs from their internal origins")
    world.install_apps(holder.container, founded.requester_did_key)
    if agents_only:
        print("=== Setup: the owner activates the apps' hook bindings")
        world.activated_hooks = activate_hooks(holder.container, hook_app_ids(site))
        print("HOOKS ACTIVE:", json.dumps(world.activated_hooks, sort_keys=True))
    else:
        print("=== Setup: the owner designates the approver's holding of the app role, using the owner's team key")
        designated = designate_holding(site, holder, founded)
        world.activated_hooks = designated["hooks"]
        print("REFUSED BEFORE ACTIVATION:", designated["refused_before_activation"])
        print("HOOKS ACTIVE:", json.dumps(designated["hooks"], sort_keys=True))
        print("HOLDING:", json.dumps({k: designated[k] for k in ("role", "principal", "contact")}))
        if stop_after == "holding":
            print("STOPPED: after the approver's holding, as asked")
            return 0

    isolated = world.redis_isolation({"aweb", "redis", "secrets", "logs"})
    print("REDIS ISOLATED:", json.dumps(isolated, sort_keys=True))
    print("Approval-service revoke gates are deferred to adcl.6; no revoke is claimed by this journey.")
    if "agent" not in world.images:
        print("AGENTS: not in this run (no agent or egress image)")
        return 0
    return agents_stage(world, founded)


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
    isolated = world.redis_isolation({"aweb", "redis", "secrets", "logs", "egress", "agent"})
    print("REDIS ISOLATED:", json.dumps(isolated, sort_keys=True))
    print("AGENTS HELD: no harness login, deployment or session; wake and model are not run")
    return 0


if __name__ == "__main__":
    sys.exit(main())
