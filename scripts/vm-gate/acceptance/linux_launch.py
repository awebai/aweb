#!/usr/bin/env python3
"""Focused Linux root-upload/UID1000 launch regression; no provider access."""

import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tarfile
import tempfile
import types
import unittest
import uuid
from unittest.mock import patch

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
sys.path.insert(0, str(BASE / "tests"))
from test_source import GitFixture
from vm_gate import executor
from vm_gate.backend import PREFIX
from vm_gate.source import git, prepare


class Fixture(GitFixture, unittest.TestCase):
    pass


class DockerTransport:
    container = None
    copies = []

    def __init__(self, *args):
        pass

    def run(self, command, *, timeout, check=True):
        result = subprocess.run(
            ["docker", "exec", self.container, "bash", "-c", "umask 022; " + command],
            text=True,
            capture_output=True,
            timeout=timeout,
        )
        if check and result.returncode:
            raise RuntimeError(result.stderr)
        return result

    def copy(self, source, target, *, timeout, download=False):
        pair = (
            [self.container + ":" + str(source), str(target)]
            if download
            else [str(source), self.container + ":" + str(target)]
        )
        subprocess.run(
            ["docker", "cp", *pair], check=True, capture_output=True, timeout=timeout
        )
        if not download:
            receipt = self.run(
                'stat -c "%u %g %a" ' + shlex.quote(str(target)), timeout=10
            ).stdout.strip()
            self.copies.append({"path": str(target), "root_upload_stat": receipt})


def run_case(fixture, cls, name):
    label = "vm-gate-launch-" + uuid.uuid4().hex
    cid = subprocess.check_output(
        [
            "docker",
            "run",
            "-d",
            "--name",
            label,
            "--label",
            "aweb.vm-gate-launch-control=" + label,
            "python:3.12-slim",
            "sleep",
            "900",
        ],
        text=True,
    ).strip()
    DockerTransport.container = cid
    DockerTransport.copies = []
    transport = DockerTransport()
    directory = fixture.root / name
    directory.mkdir(mode=0o700)
    source = prepare(fixture.repo, fixture.sha, directory, observed=fixture.observed)
    (directory / "ledger-before.tsv").write_bytes(b"")
    with tarfile.open(directory / "ledger-logs-before.tar.gz", "w:gz"):
        pass
    try:
        setup = transport.run(
            "apt-get update -qq && apt-get install -y -qq --no-install-recommends git make passwd util-linux && groupadd -f docker",
            timeout=240,
        )
        (directory / "linux-setup.log").write_text(setup.stdout + setup.stderr)
        tools = {
            "/usr/local/go/bin/go": 'printf "go1.2.3\\n"',
            "/opt/uv/uv": 'printf "uv 0.1.2\\n"',
            "/opt/uv/uvx": "exit 0",
            "/opt/node/bin/node": 'printf "v22.0.0\\n"',
            "/opt/node/bin/npm": "exit 0",
            "/usr/local/bin/docker": "exit 0",
        }
        toolscript = "from pathlib import Path\n"
        for path, body in tools.items():
            toolscript += f"p=Path({path!r});p.parent.mkdir(parents=True,exist_ok=True);p.write_text({'#!/bin/sh\n' + body + '\n'!r});p.chmod(0o755)\n"
        transport.run("python3 -c " + shlex.quote(toolscript), timeout=30)
        inspect = """import json,hashlib,shutil,subprocess
from pathlib import Path
names='go uv uvx node npm python3 git make bash docker'.split()
commands={}
for name in names:
 p=shutil.which(name);target=Path(p).resolve();commands[name]={'path':p,'target':str(target),'sha256':hashlib.sha256(target.read_bytes()).hexdigest()}
print(json.dumps({'commands':commands,'dpkg':subprocess.check_output(['dpkg-query','-W','-f=${Package}=${Version}\\n'],text=True).strip()}))
"""
        manifest = json.loads(
            transport.run(
                "env PATH="
                + executor.HOST_PATH
                + " python3 -c "
                + shlex.quote(inspect),
                timeout=30,
            ).stdout
        )
        manifest["observed"] = fixture.observed
        config = {
            "ledger": "/retained/ledger.tsv",
            "manifest": manifest,
            "owner": "fixture",
        }
        command = 'test "$(id -u)" = 1000 && test -r /opt/vm-gate/source.json && test -r /opt/vm-gate/expected-host.json && test -w "$AWEB_GATE_LEDGER" && test -w /var/log/vm-gate && git fetch origin && printf "UID1000 launch reached\\n"; exit 7'
        provider = types.SimpleNamespace(
            read=lambda *a: {
                "labels": {PREFIX + "run": name},
                "public_net": {"ipv4": {"ip": "192.0.2.1"}},
            }
        )
        remote = cls(config, directory, source, command, provider)
        remote.preflight()
        with patch("vm_gate.executor.Transport", DockerTransport):
            # The old module resolves its globals independently.
            with patch.object(
                sys.modules[cls.__module__], "Transport", DockerTransport
            ):
                remote.prepare({"id": 1, "run_id": name}, timeout=300)
                status = remote.execute({"id": 1, "run_id": name}, timeout=60)
                if status != 7:
                    raise AssertionError("planted command exit7 not preserved")
                evidence = remote.collect({"id": 1, "run_id": name}, timeout=60)
        identity = (directory / "evidence/var/log/vm-gate/identity.txt").read_text()
        if "uid=1000" not in identity:
            raise AssertionError("launch did not use UID1000")
        if not all(
            r["root_upload_stat"].startswith("0 0 600")
            for r in DockerTransport.copies
            if r["path"].endswith(("source.json", "expected-host.json", "launch.sh"))
        ):
            raise AssertionError("fixture did not begin with root-owned0600 inputs")
        return {
            "status": "PASS",
            "exit": status,
            "identity": identity.strip(),
            "uploads": DockerTransport.copies,
            "evidence": evidence,
        }
    except Exception as exc:
        details = "\n".join(
            p.read_text(errors="replace") for p in directory.glob("*.stderr")
        )
        return {
            "status": "FAILED",
            "error": str(exc),
            "stderr": details,
            "uploads": DockerTransport.copies,
        }
    finally:
        subprocess.run(
            ["docker", "rm", "-f", cid], check=True, capture_output=True, timeout=30
        )


def main():
    if os.environ.get("VM_GATE_LINUX_LAUNCH_TEST") != "1":
        raise SystemExit("focused Linux slot and VM_GATE_LINUX_LAUNCH_TEST=1 required")
    os.umask(0o077)
    output = Path(sys.argv[1]).resolve()
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    fixture = Fixture()
    fixture.setUp()
    try:
        old = git(
            BASE.parents[1],
            "show",
            "ae79d4e92084363af708c79f66248dbbedd3bc3c:scripts/vm-gate/vm_gate/executor.py",
        ).stdout
        module = types.ModuleType("vm_gate._before_permissions")
        module.__package__ = "vm_gate"
        module.__file__ = str(BASE / "vm_gate/executor.py")
        sys.modules[module.__name__] = module
        exec(compile(old, module.__file__, "exec"), module.__dict__)
        red = run_case(fixture, module.Executor, "before")
        (output / "before.json").write_text(json.dumps(red, indent=2) + "\n")
        if (
            red["status"] != "FAILED"
            or "PermissionError" not in red.get("stderr", "")
            or "/opt/vm-gate/source.json" not in red.get("stderr", "")
        ):
            raise AssertionError(
                "old source did not reproduce the observed0600 metadata refusal"
            )
        green = run_case(fixture, executor.Executor, "after")
        (output / "after.json").write_text(json.dumps(green, indent=2) + "\n")
        if green["status"] != "PASS":
            raise AssertionError(green)
        print(
            "PASS: old source refused root0600 metadata; corrected full prepare/UID1000 launch/exit7/evidence path passed"
        )
    finally:
        fixture.doCleanups()


if __name__ == "__main__":
    main()
