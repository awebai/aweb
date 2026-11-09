"""Disposable synthetic Oracle lab; credentials only travel through private stdin."""

import json
import os
import re
import secrets
import subprocess
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ORACLE_IMAGE = (
    "container-registry.oracle.com/database/free@sha256:"
    "13a933b9a5d5551d9c2516ebbd43a97806e035116399ea2db873331cbb2e7af7"
)


def docker(*args, incoming=None, timeout=60):
    transient = args[0] == "run" and "--rm" in args
    name = "oracle-report-control-" + secrets.token_hex(6)
    command = ["docker", *args]
    if transient:
        command[2:2] = ["--name", name]
    try:
        result = subprocess.run(
            command, input=incoming, capture_output=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("Oracle lab operation timed out") from None
    finally:
        if transient:
            subprocess.run(
                ["docker", "rm", "-f", name], capture_output=True, timeout=60, check=False
            )
    if result.returncode:
        # SQL/driver/runtime errors may contain input values. Never expose them.
        codes = sorted(set(re.findall(rb"(?:ORA|SP2)-[0-9]{4,5}", result.stdout + result.stderr)))
        raise RuntimeError("Oracle lab operation refused " + b",".join(codes).decode())
    return result.stdout


@dataclass(repr=False)
class Lab:
    network: str
    database: str
    password: str
    private_payload: str

    def permissions(self):
        image = json.loads((ROOT / "job.json").read_bytes())["oci"]["image"].split("@", 1)[1]
        raw = docker(
            "run",
            "--rm",
            "-i",
            "--network",
            self.network,
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--read-only",
            "--user",
            "10000:10000",
            "--mount",
            f"type=bind,src={ROOT / 'database_probe.py'},dst=/probe.py,readonly",
            "--entrypoint",
            "/usr/local/bin/python",
            image,
            "-I",
            "-B",
            "/probe.py",
            incoming=json.dumps({"password": self.password}).encode(),
        )
        return json.loads(raw)

    def count(self):
        return self.permissions()["before"]

    def execute(self, params):
        raw = docker(
            "run",
            "--rm",
            "-i",
            "--init",
            "--network",
            self.network,
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--security-opt=seccomp=unconfined",
            "--security-opt=systempaths=unconfined",
            "--tmpfs",
            "/memory:rw,exec,uid=10000,gid=10000,mode=0700,size=768m",
            "--mount",
            f"type=bind,src={ROOT / '.artifacts/layout'},dst=/oci-source,readonly",
            "--mount",
            f"type=bind,src={ROOT / 'runner-config.json'},dst=/pins/runner-config.json,readonly",
            "aweb-oracle-job-proof:06e61",
            "/venv/bin/python",
            "-I",
            "-B",
            "/proof/proof.py",
            incoming=json.dumps(
                {
                    "password": self.password,
                    "agent_uid": os.getuid(),
                    "params": params,
                }
            ).encode(),
            timeout=90,
        )
        result = json.loads(raw)
        if self.password in raw.decode() or self.private_payload in raw.decode():
            raise RuntimeError("private lab value reached output")
        return result

    def sql(self, script):
        return docker(
            "exec",
            "-i",
            self.database,
            "/bin/bash",
            "-c",
            'exec "$ORACLE_HOME/bin/sqlplus" -s / as sysdba',
            incoming=(
                "SET ECHO OFF VERIFY OFF FEEDBACK OFF\n"
                "WHENEVER SQLERROR EXIT FAILURE ROLLBACK\n" + script + "\nEXIT\n"
            ).encode(),
        )


@contextmanager
def oracle_lab():
    suffix = secrets.token_hex(6)
    network, database, volume = (
        f"oracle-report-{suffix}-{kind}" for kind in ("net", "db", "secret")
    )
    # Alphanumeric values are generated privately, never committed or logged.
    lab = Lab(network, database, "Qq9" + secrets.token_hex(24), secrets.token_hex(24))
    try:
        docker("network", "create", "--internal", "--subnet", "10.203.0.0/24", network)
        docker(
            "volume",
            "create",
            "--driver",
            "local",
            "--opt",
            "type=tmpfs",
            "--opt",
            "device=tmpfs",
            "--opt",
            "o=uid=54321,gid=54321,mode=0700",
            volume,
        )
        docker(
            "run",
            "--rm",
            "-i",
            "--network=none",
            "-v",
            f"{volume}:/secrets",
            "alpine@sha256:3f4d6b32e26703c6082839234f43769d5046b3ac7c910033911d1e71d8cd630a",
            "/bin/sh",
            "-c",
            "umask 077; cat > /secrets/oracle_pwd; chown 54321:54321 /secrets/oracle_pwd",
            incoming=("Qq9" + secrets.token_hex(24)).encode(),
        )
        docker(
            "run",
            "-d",
            "--name",
            database,
            "--network",
            network,
            "--ip",
            "10.203.0.2",
            "--cpus",
            "2",
            "--memory",
            "3g",
            "--mount",
            f"type=volume,src={volume},dst=/run/secrets,readonly",
            "--mount",
            f"type=bind,src={ROOT / 'lab-ready.sh'},dst=/opt/oracle/scripts/startup/99-lab-ready.sh,readonly",
            ORACLE_IMAGE,
        )
        # Readiness only; raw Oracle startup output is never evidence.
        deadline = time.monotonic() + 240
        while time.monotonic() < deadline:
            health = json.loads(docker("inspect", "--format", "{{json .State}}", database))
            if health.get("Health", {}).get("Status") == "healthy":
                ready = subprocess.run(
                    ["docker", "exec", database, "test", "-f", "/tmp/oracle-lab-ready"],
                    capture_output=True,
                    timeout=5,
                    check=False,
                )
                if ready.returncode == 0:
                    break
            if not health.get("Running"):
                raise RuntimeError("Oracle lab database did not start")
            time.sleep(1)
        else:
            raise RuntimeError("Oracle lab readiness deadline exceeded")
        owner_password = "Qq9" + secrets.token_hex(24)
        lab.sql(f"""
ALTER SESSION SET CONTAINER = FREEPDB1;
CREATE TABLESPACE LAB_DATA DATAFILE '/opt/oracle/oradata/lab-data.dbf' SIZE 16M AUTOEXTEND OFF;
CREATE USER LAB_OWNER IDENTIFIED BY "{owner_password}" DEFAULT TABLESPACE LAB_DATA QUOTA 1M ON LAB_DATA;
CREATE TABLE LAB_OWNER.REPORT_EVENTS (
  dataset_id VARCHAR2(16), observed_at DATE, required_value VARCHAR2(128), status VARCHAR2(16)
) TABLESPACE LAB_DATA;
INSERT INTO LAB_OWNER.REPORT_EVENTS VALUES ('orders', DATE '2026-11-02', '{lab.private_payload}', 'ready');
INSERT INTO LAB_OWNER.REPORT_EVENTS VALUES ('orders', DATE '2026-11-03', NULL, 'ready');
INSERT INTO LAB_OWNER.REPORT_EVENTS VALUES ('orders', DATE '2026-11-08', 'synthetic', 'invalid');
INSERT INTO LAB_OWNER.REPORT_EVENTS VALUES ('orders', DATE '2026-11-08', 'synthetic', 'rejected');
INSERT INTO LAB_OWNER.REPORT_EVENTS VALUES ('inventory', DATE '2026-11-03', 'synthetic', 'ready');
INSERT INTO LAB_OWNER.REPORT_EVENTS VALUES ('orders', DATE '2026-11-01', NULL, 'invalid');
INSERT INTO LAB_OWNER.REPORT_EVENTS VALUES ('orders', DATE '2026-11-09', NULL, 'invalid');
COMMIT;
CREATE USER LAB_REPORT IDENTIFIED BY "{lab.password}";
GRANT CREATE SESSION TO LAB_REPORT;
GRANT READ ON LAB_OWNER.REPORT_EVENTS TO LAB_REPORT;
ALTER USER LAB_REPORT READ ONLY;
""")
        yield lab
    finally:
        # Only these randomly named disposable resources belong to this lab.
        for args in (("rm", "-f", database), ("volume", "rm", volume), ("network", "rm", network)):
            subprocess.run(["docker", *args], capture_output=True, timeout=60, check=False)
