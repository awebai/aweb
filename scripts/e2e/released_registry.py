#!/usr/bin/env python3
"""Run the published 0.5.39 registry, without importing the candidate checkout.

Use the old package's own interpreter with -I. See released_registry.md for
installation and the disposable database/Redis interface. This launcher neither
provisions authority nor replaces routes, configuration, migrations or quotas.
"""

import argparse
import hashlib
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
from zipfile import ZipFile


WHEEL_SHA256 = "41238e71d92cbe9ad5be9bb7f1ffa317ed9d55e0db7255e2599832c8ad43de30"
VERSION = "0.5.39"


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
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    receipt = verify_package(args.wheel.resolve())
    args.receipt.write_text(json.dumps(receipt, indent=2) + "\n")
    if not args.check_only:
        env = service_environment()
        os.execve(sys.executable, [sys.executable, "-I", "-m", "uvicorn",
                  "awid_service.main:create_app", "--factory", "--host", args.host,
                  "--port", str(args.port)], env)


if __name__ == "__main__":
    main()
