"""A disposable lab that proves a naapp's packaged image; run explicitly under
the suite lock.

It uses only generated lab keys, internal Docker networking and real
PostgreSQL, Redis and AWID. There are no customer inputs, DNS override hooks,
insecure TLS or production access. A service describes itself with
:class:`PackagedService`: the key files it reads, its environment and the probe
that runs inside its image. The probe builds on
:mod:`aweb_naapp_testing.packaged_probe`, which the lab copies next to it.
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import tempfile
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from awid.dns_verify import awid_txt_value
from awid_service.testing import signed_team_server_record

from aweb_naapp_testing import Member
from aweb_naapp_testing.network import make_certificates

REGISTRY_URL = "https://registry.lab.test:8010"


@dataclass(frozen=True)
class Lab:
    """What a service's environment can name: the lab database, the lab
    registry and each generated key file, by name, at its path in the image."""

    database_url: str
    registry_url: str
    keys: Mapping[str, str]


@dataclass(frozen=True)
class PackagedService:
    """``name`` is the service's container alias and the lab's prefix."""

    name: str
    keys: tuple[str, ...]
    environment: Callable[[Lab], Mapping[str, str]]
    probe: Path


def docker(*args, input=None):
    result = subprocess.run(
        ["docker", *map(str, args)], input=input, text=True, capture_output=True
    )
    if result.returncode:
        raise RuntimeError("docker operation failed: " + str(args[0]))
    return result.stdout.strip()


def wait_until(check, seconds=90):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(0.2)
    raise TimeoutError("lab readiness")


def run_package_lab(image: str, service: PackagedService) -> None:
    if os.getuid() == 0:
        raise ValueError("run the disposable lab as a non-root user")
    prefix = f"{service.name}-package-" + uuid.uuid4().hex[:10]
    network, containers = prefix, []
    with tempfile.TemporaryDirectory(prefix=f"{service.name}-package-") as directory:
        lab = Path(directory)
        lab.chmod(0o700)
        (lab / "tls").mkdir()
        make_certificates(lab / "tls", ["registry.lab.test"], [])
        # Certificates and all generated key files are mounted, never built in.
        member = Member(team_id="lab:customer.lab.test")
        public = {
            "team_id": member.team_id,
            "team_did_key": member.team_did_key,
            "certificate_id": member.certificate_id,
            "member_did_key": member.did_key,
            "publication": signed_team_server_record(
                member.team_id,
                member.team_key,
                server_url="https://coordinator.lab.test",
                issued_at=datetime.now(UTC),
            ),
        }
        (lab / "authority.json").write_text(json.dumps(public))
        key_paths = {}
        for name in service.keys:
            (lab / name).write_text(secrets.token_hex(32))
            (lab / name).chmod(0o600)
            key_paths[name] = "/lab/" + name
        password = secrets.token_urlsafe(32)
        database_url = f"postgresql://lab:{password}@postgres:5432/lab"
        env = {
            **service.environment(
                Lab(database_url=database_url, registry_url=REGISTRY_URL, keys=key_paths)
            ),
            "SSL_CERT_FILE": "/lab/tls/ca.pem",
        }
        # The lab readiness proof does not send mail or claim SMTP acceptance.
        (lab / "service.env").write_text("".join(f"{k}={v}\n" for k, v in env.items()))
        (lab / "postgres.env").write_text(
            f"POSTGRES_USER=lab\nPOSTGRES_PASSWORD={password}\nPOSTGRES_DB=lab\n"
        )
        (lab / "registry.env").write_text(
            f"AWID_DATABASE_URL={database_url}\nAWID_REDIS_URL=redis://redis:6379/0\nAWID_DB_SCHEMA=awid\n"
        )
        for filename in ("service.env", "postgres.env", "registry.env"):
            (lab / filename).chmod(0o600)
        (lab / "probe.py").write_bytes(service.probe.read_bytes())
        shared_probe = Path(__file__).with_name("packaged_probe.py")
        (lab / shared_probe.name).write_bytes(shared_probe.read_bytes())
        docker(
            "network",
            "create",
            "--internal",
            "--subnet",
            f"10.253.{secrets.randbelow(256)}.0/24",
            network,
        )
        try:

            def start(name, container_image, *args, options=()):
                full = prefix + "-" + name
                docker(
                    "run",
                    "-d",
                    "--name",
                    full,
                    "--network",
                    network,
                    "--network-alias",
                    name,
                    *options,
                    container_image,
                    *args,
                )
                containers.append(full)
                return full

            pg = start(
                "postgres", "postgres:16-alpine", options=("--env-file", lab / "postgres.env")
            )
            start("redis", "redis:7-alpine")
            wait_until(
                lambda: (
                    subprocess.run(
                        ["docker", "exec", pg, "pg_isready", "-U", "lab"], capture_output=True
                    ).returncode
                    == 0
                )
            )
            # The app resolver has only owned lab records and no upstream.
            txt = awid_txt_value(member.team_did_key, registry_url=REGISTRY_URL)
            (lab / "customer.zone").write_text(
                "$ORIGIN customer.lab.test.\n@ 0 IN SOA ns.customer.lab.test. hostmaster.customer.lab.test. 1 60 60 60 0\n"
                '@ 0 IN NS ns.customer.lab.test.\n_awid 0 IN TXT "' + txt + '"\n'
            )
            dns_config = ".:53 {\n errors\n hosts /lab/hosts {\n fallthrough\n }\n file /lab/customer.zone customer.lab.test\n}\n"
            uid = f"{os.getuid()}:{os.getgid()}"
            registry = start(
                "registry",
                image,
                "awid_service.main:create_app",
                "--factory",
                "--host",
                "0.0.0.0",
                "--port",
                "8010",
                "--ssl-keyfile",
                "/lab/tls/server.key",
                "--ssl-certfile",
                "/lab/tls/server.pem",
                "--no-access-log",
                options=(
                    "--user",
                    uid,
                    "--env-file",
                    lab / "registry.env",
                    "-v",
                    f"{lab}:/lab:ro",
                    "--entrypoint",
                    "/app/.venv/bin/uvicorn",
                ),
            )
            registry_ip = docker(
                "inspect",
                "-f",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                registry,
            )
            # CoreDNS hosts + TXT, all addresses and keys are this disposable lab.
            (lab / "Corefile").write_text(dns_config)
            pg_ip = docker(
                "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", pg
            )
            (lab / "hosts").write_text(registry_ip + " registry.lab.test\n" + pg_ip + " postgres\n")
            dns = start(
                "dns",
                "coredns/coredns:1.11.3",
                "-conf",
                "/lab/Corefile",
                options=("-v", f"{lab}:/lab:ro"),
            )
            dns_ip = docker(
                "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", dns
            )
            app = start(
                service.name,
                image,
                options=(
                    "--user",
                    uid,
                    "--dns",
                    dns_ip,
                    "--health-interval",
                    "2s",
                    "--env-file",
                    lab / "service.env",
                    "-v",
                    f"{lab}:/lab",
                ),
            )
            wait_until(
                lambda: docker("inspect", "-f", "{{.State.Health.Status}}", app) == "healthy"
            )
            probe_process = subprocess.Popen(
                ["docker", "exec", app, "/app/.venv/bin/python", "/lab/probe.py"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                wait_until(
                    lambda: (lab / "outage-requested").exists() or probe_process.poll() is not None
                )
                if probe_process.poll() is None:
                    docker("stop", "--time", "5", registry)
                    (lab / "outage-ready").touch()
                stdout, stderr = probe_process.communicate(timeout=90)
                print(stdout, end="")
                if probe_process.returncode:
                    raise RuntimeError("packaged registry probe failed")
            finally:
                if probe_process.poll() is None:
                    probe_process.terminate()
                    probe_process.wait(timeout=10)
        finally:
            for container in reversed(containers):
                docker("rm", "-f", container)
            docker("network", "rm", network)
        print("owned containers/network/private generated files cleaned PASS")
