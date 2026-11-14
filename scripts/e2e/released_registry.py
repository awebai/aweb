#!/usr/bin/env python3
"""Run the published 0.5.39 registry, without importing the candidate checkout.

Use the old package's own interpreter with -I. See released_registry.md for
installation and the disposable database/Redis interface. This launcher neither
provisions authority nor replaces routes, configuration, migrations or quotas.
"""

import argparse
from contextlib import contextmanager
import hashlib
import http.client
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import time
from zipfile import ZipFile


WHEEL_SHA256 = "41238e71d92cbe9ad5be9bb7f1ffa317ed9d55e0db7255e2599832c8ad43de30"
VERSION = "0.5.39"


@contextmanager
def old_registry_listener(*, python, wheel, run_root, port, database_url, redis_url,
                          schema, public_origins, startup_timeout=45):
    """Own the stock loopback process for one serial, disposable registry epoch.

    The caller owns PG/Redis and the public TLS/DNS topology. Receipts contain
    package/health/process facts, never connection credentials. No client gets
    the backend URL as its registry configuration.
    """
    if not 1 <= port <= 65535 or startup_timeout <= 0:
        raise ValueError("use a valid fixed port and positive startup timeout")
    public_origins = tuple(public_origins)
    root = Path(run_root).resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    backend = f"http://127.0.0.1:{port}"
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("AW", "PYTHON")) and key not in ("APP_ENV", "ENVIRONMENT", "WEB_CONCURRENCY")}
    env.update(AWID_DATABASE_URL=database_url, AWID_REDIS_URL=redis_url,
               AWID_DB_SCHEMA=schema, AWID_PUBLIC_ORIGINS=",".join(public_origins))
    command = [str(Path(python).absolute()), "-I", str(Path(__file__).resolve()),
               "--wheel", str(Path(wheel).resolve()), "--receipt", str(root / "package.json"),
               "--host", "127.0.0.1", "--port", str(port)]
    receipt = {"state": "STARTING", "backend_url": backend, "version": VERSION,
               "installation": "published-wheel", "image": None,
               "public_origins": list(public_origins), "pid": None,
               "stopped": False, "process_group_absent": False,
               "listener_reserved": False, "listener_closed": False}

    def record():
        (root / "process.json").write_text(json.dumps(receipt, indent=2) + "\n")

    record()
    process = None
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener, (root / "service.log").open("wb") as log:
        try:
            # Bind before launching, and keep the reservation until cleanup.
            # No health answer from an earlier epoch can reach this socket.
            listener.bind(("127.0.0.1", port))
            listener.listen(128)
            receipt["listener_reserved"] = True
            descriptor = listener.fileno()
            command.extend(["--fd", str(descriptor)])
            process = subprocess.Popen(command, cwd=root, env=env, stdout=log,
                                       stderr=subprocess.STDOUT, start_new_session=True,
                                       pass_fds=(descriptor,))
            receipt["pid"] = process.pid
            record()
            deadline = time.monotonic() + startup_timeout
            while True:
                if process.poll() is not None:
                    raise RuntimeError("old registry exited during startup; inspect the private service.log")
                health = None
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
                try:
                    connection.request("GET", "/health")
                    response = connection.getresponse()
                    if response.status == 200:
                        health = json.loads(response.read(65536))
                except (OSError, http.client.HTTPException, ValueError):
                    pass
                finally:
                    connection.close()
                if health is not None:
                    checks = health.get("checks", {})
                    if (health.get("version") != VERSION or health.get("status") != "ok"
                            or checks.get("database") != "ok" or checks.get("redis") != "ok"
                            or checks.get("schema") != schema
                            or checks.get("rate_limiter") != "RedisFixedWindowRateLimiter"):
                        raise RuntimeError("old registry health does not match the selected stock epoch")
                    receipt.update(state="READY", health=health)
                    record()
                    break
                if time.monotonic() >= deadline:
                    raise TimeoutError("old registry did not become ready")
                time.sleep(0.1)
            yield backend
        except BaseException:
            receipt["state"] = "FAILED"
            raise
        finally:
            if process is not None:
                if process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=5)
                receipt["stopped"] = process.poll() is not None
                receipt["exit_code"] = process.returncode
                try:
                    os.killpg(process.pid, 0)
                except ProcessLookupError:
                    receipt["process_group_absent"] = True
            listener.close()
            receipt["listener_closed"] = True
            record()
            if process is not None and not receipt["process_group_absent"]:
                raise RuntimeError("old registry process group remains; epoch cleanup is incomplete")


def verify_package(wheel):
    if not sys.flags.isolated:
        raise RuntimeError("run this launcher with the old interpreter and -I")
    if hashlib.sha256(wheel.read_bytes()).hexdigest() != WHEEL_SHA256:
        raise RuntimeError("the old registry wheel does not match the frozen published artifact")
    if importlib.metadata.version("awid-service") != VERSION:
        raise RuntimeError("the selected interpreter does not contain awid-service 0.5.39")
    roots = {}
    for package in ("awid", "awid_service"):
        spec = importlib.util.find_spec(package)
        if spec is None or spec.origin is None:
            raise RuntimeError(f"missing installed package: {package}")
        roots[package] = Path(spec.origin).resolve().parent
    files = {}
    with ZipFile(wheel) as archive:
        for name in archive.namelist():
            package, _, relative = name.partition("/")
            if package not in roots or not relative or name.endswith("/"):
                continue
            installed = roots[package] / relative
            expected = archive.read(name)
            if not installed.is_file() or installed.read_bytes() != expected:
                raise RuntimeError(f"installed old-registry file differs from the wheel: {name}")
            files[name] = hashlib.sha256(expected).hexdigest()
    return {
        "version": VERSION,
        "wheel_sha256": WHEEL_SHA256,
        "python": sys.version,
        "executable": sys.executable,
        "package_roots": {name: str(path) for name, path in roots.items()},
        "files": files,
        "distributions": dict(sorted(
            (distribution.metadata["Name"], distribution.version)
            for distribution in importlib.metadata.distributions()
        )),
    }


def service_environment():
    # Do not inherit candidate source paths, development shortcuts, limiter
    # overrides or a default production registry from the caller's shell.
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("AW", "PYTHON")) and key not in ("APP_ENV", "ENVIRONMENT")}
    required = ("AWID_DATABASE_URL", "AWID_REDIS_URL", "AWID_DB_SCHEMA", "AWID_PUBLIC_ORIGINS")
    for key in required:
        value = os.environ.get(key)
        if not value:
            raise RuntimeError(f"disposable fixture requires {key}")
        env[key] = value
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", env["AWID_DB_SCHEMA"]):
        raise RuntimeError("use a distinct simple schema name for the disposable old registry")
    if token := os.environ.get("AWID_SERVICE_TOKEN"):
        env["AWID_SERVICE_TOKEN"] = token
    env.update(AWID_RATE_LIMIT_BACKEND="redis", AWID_RELOAD="false", AWID_LOG_LEVEL="info")
    return env


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--check-only", action="store_true", help="verify installation without DB or network I/O")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8010)
    parser.add_argument("--fd", type=int, help="Owned, inherited loopback listening socket")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    receipt = verify_package(args.wheel.resolve())
    args.receipt.write_text(json.dumps(receipt, indent=2) + "\n")
    if not args.check_only:
        env = service_environment()
        binding = ["--host", args.host, "--port", str(args.port)]
        if args.fd is not None:
            inherited = socket.socket(fileno=args.fd)
            try:
                if (inherited.family != socket.AF_INET or inherited.getsockname() != ("127.0.0.1", args.port)
                        or inherited.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1):
                    raise RuntimeError("inherited registry descriptor is not its owned loopback listener")
            finally:
                inherited.detach()  # uvicorn inherits the original descriptor through exec.
            binding = ["--fd", str(args.fd)]
        os.execve(sys.executable, [sys.executable, "-I", "-m", "uvicorn",
                  "awid_service.main:create_app", "--factory", *binding], env)


if __name__ == "__main__":
    main()
