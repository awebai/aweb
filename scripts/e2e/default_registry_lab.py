#!/usr/bin/env python3
"""ONE root-operated Linux lab epoch for the published-client default path.

Requires a separately admitted, exclusive ephemeral host. This does not allocate
a provider resource, change production DNS or run the Cloud discovery journey.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time

from default_registry_client import BINARY_SHA256, write_zone
from lab_lifecycle import Resources, load_json


IMAGES = {
    "product": "ghcr.io/awebai/aweb-server@sha256:96b64829839945f42e43b16910abff9cb26fc11faa456279107559c230bc7b56",
    "dns": "coredns/coredns@sha256:f0b8c589314ed010a0c326e987a52b50801f0145ac9b75423af1b5c66dbd6d50",
    "postgres": "postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777",
    "redis": "redis@sha256:e7723ff73d963f5cc6d9c4643ea3d989527a402a319239054e9472a7fb9219a2",
}
PRODUCT_SOURCE = "cba8754f21ce826e1bf61d58c1766c4b3e13adbc"


def checked(args, deadline, log, timeout=60):
    left = deadline - time.monotonic()
    if left <= 0:
        raise TimeoutError("standalone whole-stage deadline")
    result = subprocess.run(args, capture_output=True, text=True, timeout=min(left, timeout))
    with log.open("a") as stream:
        stream.write(json.dumps({"args": args, "exit": result.returncode,
                                 "stdout": result.stdout, "stderr": result.stderr}) + "\n")
    if result.returncode:
        raise RuntimeError("lab command failed; retain the private command receipt")
    return result.stdout


def tls_files(root, deadline, log):
    root.mkdir(mode=0o755)
    checked(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
             "-subj", "/CN=Disposable default registry CA", "-addext", "basicConstraints=critical,CA:TRUE",
             "-keyout", str(root / "ca.key"), "-out", str(root / "ca.pem")], deadline, log)
    checked(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=api.awid.ai",
             "-keyout", str(root / "server.key"), "-out", str(root / "server.csr")], deadline, log)
    (root / "extensions").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:api.awid.ai,DNS:server.adaz.test,DNS:localhost\n")
    checked(["openssl", "x509", "-req", "-days", "1", "-in", str(root / "server.csr"),
             "-CA", str(root / "ca.pem"), "-CAkey", str(root / "ca.key"), "-CAcreateserial",
             "-extfile", str(root / "extensions"), "-out", str(root / "server.pem")], deadline, log)
    for name in ("ca.key", "ca.srl", "server.csr", "extensions"):
        (root / name).unlink()
    for name in ("ca.pem", "server.pem"):
        (root / name).chmod(0o644)
    os.chown(root / "server.key", 1001, 1001)
    (root / "server.key").chmod(0o400)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--admission", type=Path, required=True)
    parser.add_argument("--admission-sha256", required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or os.uname().sysname != "Linux":
        parser.error("exclusive admitted Linux lab root is required")
    assert hashlib.sha256(args.admission.read_bytes()).hexdigest() == args.admission_sha256
    admission = load_json(args.admission)
    address = str(ipaddress.IPv4Address(admission["public_ipv4"]))
    assert ipaddress.ip_address(address).is_global
    assert hashlib.file_digest(args.binary.open("rb"), "sha256").hexdigest() == BINARY_SHA256
    # The whole 900 seconds includes image preparation and TLS; cleanup gets
    # a separate 120 seconds inside the enclosing placement's total budget.
    started = time.monotonic()
    body_end, end = started + 900, started + 1020
    assert time.time() + 1020 < admission["execute_before_unix_seconds"] < admission["expires_unix_seconds"]
    args.out.mkdir(mode=0o700, parents=False, exist_ok=False)
    log = args.out / "commands.private.jsonl"
    label = "adaz-default-" + admission["fixture_id"][5:]
    work = args.out / "work"
    work.mkdir(mode=0o700)
    os.chown(work, 1000, 1000)
    plan = {"schema_version": 1, "fixture_id": admission["fixture_id"], "provider_run_id": admission["provider_run_id"],
            "cloud_source_sha": admission["cloud_source_sha"], "created_unix_seconds": time.time(),
            "owner_label": {"key": "aweb.adaz.default", "value": label}, "compose_projects": [],
            "runner_name": label + "-client", "network_name": label,
            "volume_names": [], "published_listener": {"project": "", "service": "awid",
                "container_name": label + "-awid", "host_ip": address, "published_port": 443,
                "target_port": 8010, "protocol": "tcp"}}
    with (args.out / "resources.plan.json").open("x") as stream:
        json.dump(plan, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    resources = Resources(args.out, plan, body_end)
    result = {"primary": "FAIL", "cleanup": {"verdict": "UNKNOWN"}, "images": IMAGES}
    def interrupted(signum, _frame):
        raise InterruptedError(f"signal {signum}")
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, interrupted)
    try:
        # Confirm actual local assignment; never bind an unrelated public IP.
        local = json.loads(checked(["ip", "-j", "address", "show"], body_end, log))
        assert any(x.get("local") == address for link in local for x in link["addr_info"])
        for image in IMAGES.values():
            checked(["docker", "pull", image], body_end, log, timeout=180)
            data = json.loads(checked(["docker", "image", "inspect", image], body_end, log))[0]
            assert data["Os"] == "linux" and data["Architecture"] == "amd64"
            assert image in data["RepoDigests"]
            if image == IMAGES["product"]:
                labels = data["Config"]["Labels"]
                assert labels["org.opencontainers.image.revision"] == PRODUCT_SOURCE
                assert labels["org.opencontainers.image.version"] == "1.27.51rc2"
        tls_files(args.out / "tls", body_end, log)
        dns = work / "dns"
        dns.mkdir(mode=0o755)
        os.chown(dns, 1000, 1000)
        (dns / "Corefile").write_text(".:53 {\n errors\n log\n file /zones/authority.zone . { reload 1s }\n}\n")
        (dns / "Corefile").chmod(0o644)
        write_zone(dns / "authority.zone", address, {})
        os.chown(dns / "authority.zone", 1000, 1000)
        published = args.out / "published-aw"
        shutil.copyfile(args.binary, published)
        published.chmod(0o555)
        script = Path(__file__).with_name("default_registry_client.py").resolve()
        label_args = ["--label", "aweb.adaz.default=" + label]
        network = checked(["docker", "network", "create", *label_args, label], body_end, log).strip()
        def container(name, image, command, *, env=None, ports=(), mounts=(), cpus="1", memory="1g", aliases=()):
            argv = ["docker", "run", "-d", "--pull=never", "--name", label + "-" + name,
                    *label_args, "--network", network, "--cpus", cpus, "--memory", memory, "--pids-limit", "256"]
            for alias in aliases:
                argv += ["--network-alias", alias]
            if name not in {"postgres", "redis", "dns"}:
                argv += ["--dns", dns_ip]
            for key, value in (env or {}).items():
                argv += ["-e", key + "=" + value]
            for value in mounts:
                argv += ["-v", value]
            for port in ports:
                argv += ["-p", address + ":" + port]
            argv += ["--entrypoint", command[0], image, *command[1:]]
            ref = checked(argv, body_end, log)
            resources.discover()
            return ref.strip()
        dns_id = container("dns", IMAGES["dns"], ["/coredns", "-conf", "/zones/Corefile"],
                           mounts=[str(dns) + ":/zones:ro"], cpus="0.2", memory="64m")
        inspected = json.loads(checked(["docker", "inspect", dns_id], body_end, log))[0]
        dns_ip = inspected["NetworkSettings"]["Networks"][label]["IPAddress"]
        password = os.urandom(24).hex()
        pg = container("postgres", IMAGES["postgres"], ["docker-entrypoint.sh", "postgres"], aliases=["postgres"],
                       env={"POSTGRES_USER": "aweb", "POSTGRES_PASSWORD": password, "POSTGRES_DB": "aweb"}, memory="2g")
        redis = container("redis", IMAGES["redis"], ["docker-entrypoint.sh", "redis-server", "--save", "", "--appendonly", "no"],
                          aliases=["redis"], cpus="0.5", memory="256m")
        ready = time.monotonic() + 60
        while True:
            value = subprocess.run(["docker", "exec", pg, "pg_isready", "-U", "aweb"], capture_output=True, timeout=5)
            if value.returncode == 0:
                break
            assert time.monotonic() < ready, "private PostgreSQL did not become ready"
            time.sleep(0.2)
        for db in ("postgres", "template1", "aweb"):
            checked(["docker", "exec", pg, "psql", "-X", "-v", "ON_ERROR_STOP=1", "-U", "aweb", "-d", db,
                     "-c", "CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public"], body_end, log)
        checked(["docker", "exec", pg, "psql", "-X", "-v", "ON_ERROR_STOP=1", "-U", "aweb", "-d", "postgres",
                 "-c", "ALTER ROLE aweb SET search_path=pg_catalog", "-c", "CREATE DATABASE registry"], body_end, log)
        tls_mount = str(args.out / "tls") + ":/tls:ro"
        registry_env = {"AWID_DATABASE_URL": f"postgresql://aweb:{password}@postgres:5432/registry",
                        "AWID_REDIS_URL": "redis://redis:6379/0", "AWID_DB_SCHEMA": "awid",
                        "AWID_PUBLIC_ORIGINS": "https://api.awid.ai", "AWID_RATE_LIMIT_BACKEND": "redis",
                        "AWID_RATE_LIMIT_DISABLED": "0", "AWID_SKIP_DNS_VERIFY": "0",
                        "AWID_ALLOW_INSECURE_DELIVERY_ORIGIN": "0", "APP_ENV": "production"}
        awid = container("awid", IMAGES["product"], ["/app/.venv/bin/python", "-m", "uvicorn", "awid_service.main:app",
                         "--host", "0.0.0.0", "--port", "8010", "--ssl-keyfile", "/tls/server.key", "--ssl-certfile", "/tls/server.pem"],
                         env=registry_env, ports=["443:8010"], mounts=[tls_mount], cpus="2", memory="2g")
        checked(["docker", "exec", awid, "/app/.venv/bin/python", "-c",
                 "import importlib.metadata as m; assert m.version('aweb')=='1.27.51rc2'; assert m.version('awid-service')=='0.5.40rc2'; print('locked stock aweb1.27.51rc2/awid-service0.5.40rc2')"], body_end, log)
        server = container("server", IMAGES["product"], ["/app/.venv/bin/python", "-m", "uvicorn", "aweb.api:create_app", "--factory",
                           "--host", "0.0.0.0", "--port", "8000", "--ssl-keyfile", "/tls/server.key", "--ssl-certfile", "/tls/server.pem"],
                           env={"AWEB_DATABASE_URL": f"postgresql://aweb:{password}@postgres:5432/aweb", "AWEB_REDIS_URL": "redis://redis:6379/1",
                                "AWID_REGISTRY_URL": "https://api.awid.ai", "AWEB_PUBLIC_ORIGIN": "https://server.adaz.test:8443",
                                "SSL_CERT_FILE": "/tls/ca.pem", "APP_ENV": "production"},
                           ports=["8443:8000"], mounts=[tls_mount], cpus="2", memory="2g")
        for ref, port in ((awid, 8010), (server, 8000)):
            ready = min(body_end, time.monotonic() + 90)
            code = f"import ssl,urllib.request; r=urllib.request.urlopen('https://localhost:{port}/health',context=ssl.create_default_context(cafile='/tls/ca.pem'),timeout=2); assert r.status==200"
            while True:
                value = subprocess.run(["docker", "exec", ref, "/app/.venv/bin/python", "-c", code], capture_output=True, timeout=5)
                if value.returncode == 0:
                    break
                assert time.monotonic() < ready, "stock service health failed"
                time.sleep(0.5)
        # The root bootstrap installs only the public CA in this disposable
        # container's OS store, then irreversibly drops to the fixture UID.
        bootstrap = ("import os,shutil,subprocess; shutil.copyfile('/fixture-ca.pem','/usr/local/share/ca-certificates/adaz.crt');"
                     "subprocess.run(['update-ca-certificates'],check=True); os.setgroups([]);os.setgid(1000);os.setuid(1000);"
                     f"os.execv('/app/.venv/bin/python',['python','/client.py','--work','/lane','--public-ip','{address}'])")
        client = container("client", IMAGES["product"], ["/app/.venv/bin/python", "-c", bootstrap],
                           mounts=[str(work) + ":/lane", str(published) + ":/published/aw:ro", str(script) + ":/client.py:ro",
                                   str(script.with_name("registry_quota_probe.py")) + ":/registry_quota_probe.py:ro",
                                   str(args.out / "tls/ca.pem") + ":/fixture-ca.pem:ro"], memory="512m")
        while True:
            state = json.loads(checked(["docker", "inspect", client], body_end, log))[0]["State"]
            # Read-only Redis accounting: no FLUSH/DEL/expiry or quota edits.
            keys = checked(["docker", "exec", redis, "redis-cli", "--scan", "--pattern", "aweb:rl:*"], body_end, log).splitlines()
            values = {}
            for key in keys:
                count = checked(["docker", "exec", redis, "redis-cli", "GET", key], body_end, log).strip()
                ttl = checked(["docker", "exec", redis, "redis-cli", "TTL", key], body_end, log).strip()
                values[key] = {"count": count, "ttl": ttl}
            with (args.out / "redis-usage.jsonl").open("a") as stream:
                stream.write(json.dumps({"time": time.time(), "keys": values}) + "\n")
            if not state["Running"]:
                result["client_exit"] = state["ExitCode"]
                break
            time.sleep(0.5)
        checked(["docker", "logs", client], body_end, log)
        result["client"] = load_json(work / "client-result.json")
        assert result["client_exit"] == 0 and result["client"]["verdict"] == "PASS"
        result["primary"] = "PASS"
    except BaseException as error:
        result["error"] = type(error).__name__
    finally:
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, signal.SIG_IGN)
        try:
            # Retain stock access logs, including original status/path/peer;
            # explicit limiter exercise retains real Retry-After headers too.
            for ref in (locals().get("awid"), locals().get("server")):
                if ref:
                    checked(["docker", "logs", ref], end, log, timeout=5)
            resources.deadline = end
            result["cleanup"] = resources.reconcile()
            if result["primary"] != "PASS":
                result["cleanup"]["possible_unanswered_child_mutation"] = True
                result["cleanup"]["verdict"] = "UNKNOWN"
        except BaseException as error:
            result["cleanup"] = {"verdict": "UNKNOWN", "error": type(error).__name__}
        result["final"] = "PASS" if result["primary"] == "PASS" and result["cleanup"]["verdict"] == "CLEAN" else "FAIL"
        with (args.out / "standalone-result.json").open("x") as stream:
            json.dump(result, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
    return 0 if result["final"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
