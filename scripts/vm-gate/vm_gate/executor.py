"""SSH execution of unchanged source bytes on one disposable host."""

import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import tarfile
import time

from .backend import PREFIX
from .config import child_environment
from .errors import Infrastructure, Refused
from .admission import validate_command
from .evidence import collect_archive
from .transport import Transport

Q = shlex.quote
REMOTE = "/opt/vm-gate"
LOGS = "/var/log/vm-gate"
HOST_PATH = "/usr/local/go/bin:/opt/uv:/opt/node/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


class Executor:
    def __init__(self, config, directory, source, command, provider):
        self.config = config
        self.directory = Path(directory)
        self.source = source
        self.command = command
        self.provider = provider
        self.transport = None
        self.deadline = None
        self.verify_host = True

    def remaining(self):
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise Infrastructure("remote phase deadline exhausted")
        return left

    def run(self, command, name, check=True):
        result = self.transport.run(command, timeout=self.remaining(), check=False)
        (self.directory / (name + ".stdout")).write_text(result.stdout)
        (self.directory / (name + ".stderr")).write_text(result.stderr)
        if check and result.returncode:
            raise Infrastructure(f"remote {name} failed (exit {result.returncode})")
        return result

    def env(self, root=False):
        home = "/root" if root else "/home/gateuser"
        return f"env -i HOME={home} PATH={HOST_PATH} GOTOOLCHAIN=local PYTHONPATH={REMOTE}/operator "

    def host_check(self, root=False):
        return (
            self.env(root)
            + f"python3 -m vm_gate.host_contract {REMOTE}/source {REMOTE}/source.json {REMOTE}/expected-host.json"
        )

    def bootstrap_program(self, bundle_hash):
        ledger = Q(self.config["ledger"])
        parent = Q(str(Path(self.config["ledger"]).parent))
        return f"""set -euo pipefail
cd {REMOTE}
test "$(sha256sum source.bundle | cut -d' ' -f1)" = {bundle_hash}
tar -xzf operator.tar.gz -C operator
git init --bare origin
git --git-dir=origin fetch source.bundle '+refs/*:refs/*'
git --git-dir=origin update-ref refs/heads/main {self.source["frozen_main"]}
git --git-dir=origin symbolic-ref HEAD refs/heads/main
git clone origin source
git -C source checkout --detach {self.source["sha"]}
id gateuser >/dev/null 2>&1 || useradd --uid 1000 --create-home --shell /bin/bash --groups docker gateuser
usermod -aG docker gateuser
test "$(id -u gateuser)" = 1000
mkdir -p {parent}/gate-locks {parent}/gate-logs
cp ledger-before.tsv {ledger}
tar -xzf ledger-logs-before.tar.gz -C {parent}
chown gateuser:gateuser {parent} {ledger} {parent}/gate-locks
chown -R gateuser:gateuser {parent}/gate-logs
chown -R gateuser:gateuser source {LOGS}
"""

    def focused_shell(self):
        return "bash -c " + Q(self.command)

    def launch_program(self):
        return f"""#!/bin/bash
set -euo pipefail
cd {REMOTE}/source
test "$(id -u)" = 1000
{self.host_check()}
id > {LOGS}/identity.txt
date -u +%FT%TZ > {LOGS}/gate-start
set +e
{self.focused_shell()} > {LOGS}/gate-output.log 2>&1
status=$?
set -e
printf '%s\\n' "$status" > {LOGS}/gate-exit
date -u +%FT%TZ > {LOGS}/gate-end
git status --porcelain --untracked-files=all > {LOGS}/source-after
exit "$status"
"""

    def preflight(self):
        validate_command(self.bootstrap_program("0" * 64))
        script = self.launch_program()
        validate_command(script)
        (self.directory / "launch.sh").write_text(script)

    def prepare(self, server, timeout):
        self.deadline = time.monotonic() + timeout
        while True:
            info = self.provider.read("server_info", server["id"])
            if info.get("labels", {}).get(PREFIX + "run") != server["run_id"]:
                raise Infrastructure("SSH server label identity mismatch")
            address = ((info.get("public_net") or {}).get("ipv4") or {}).get("ip")
            if address:
                self.transport = Transport(self.directory, address, server["id"])
                try:
                    result = self.transport.run(
                        "true", timeout=min(10, self.remaining()), check=False
                    )
                    if result.returncode == 0:
                        break
                except Infrastructure:
                    pass  # Bounded, idempotent readiness probe; never a create retry.
            time.sleep(min(2, self.remaining()))
        self.run(f"mkdir -p {REMOTE}/operator {LOGS}", "mkdir")
        expected = self.directory / "expected-host.json"
        expected.write_text(json.dumps(self.config["manifest"], indent=2) + "\n")
        operator = self.directory / "operator.tar.gz"
        with tarfile.open(operator, "w:gz") as t:
            for path in Path(__file__).parent.rglob("*"):
                if path.suffix in {".py", ".sql"}:
                    t.add(
                        path,
                        arcname="vm_gate/"
                        + str(path.relative_to(Path(__file__).parent)),
                    )
        for path, target in [
            (Path(self.source["bundle"]), "source.bundle"),
            (self.directory / "source.json", "source.json"),
            (expected, "expected-host.json"),
            (operator, "operator.tar.gz"),
            (self.directory / "ledger-before.tsv", "ledger-before.tsv"),
            (self.directory / "ledger-logs-before.tar.gz", "ledger-logs-before.tar.gz"),
        ]:
            self.transport.copy(path, REMOTE + "/" + target, timeout=self.remaining())
        bundle_hash = hashlib.sha256(
            Path(self.source["bundle"]).read_bytes()
        ).hexdigest()
        self.run("bash -c " + Q(self.bootstrap_program(bundle_hash)), "source-prepare")
        negative = self.run(self.host_check(root=True), "uid0-negative", check=False)
        if negative.returncode != 78 or "UID 0 refused" not in negative.stderr:
            raise Infrastructure("UID 0 admission negative control failed")
        if self.verify_host:
            result = self.run(
                f"cd {REMOTE}/source && runuser -u gateuser -- " + self.host_check(),
                "host-contract",
                check=False,
            )
            if result.returncode == 78:
                raise Refused(result.stderr.strip())
            if result.returncode:
                raise Infrastructure("remote host contract failed")
        launch = self.directory / "launch.sh"
        self.transport.copy(launch, REMOTE + "/launch.sh", timeout=self.remaining())

    def execute(self, server, timeout):
        self.deadline = time.monotonic() + timeout + 45
        self.run(
            f"nohup python3 {REMOTE}/operator/vm_gate/memory.py {LOGS}/memory.jsonl >{LOGS}/sampler.log 2>&1 </dev/null & echo $! >{LOGS}/sampler.pid",
            "sampler-start",
        )
        ledger = Q(self.config["ledger"])
        logs = Q(str(Path(self.config["ledger"]).parent / "gate-logs"))
        command = (
            f"cd {REMOTE}/source && timeout --signal=TERM --kill-after=30s {timeout} runuser -u gateuser -- "
            + self.env()
            + f"AWEB_GATE_LEDGER={ledger} AWEB_GATE_LOG_DIR={logs} GATE_OWNER={Q(self.config['owner'])} bash {REMOTE}/launch.sh"
        )
        result = self.run(command, "execution", check=False)
        if result.returncode == 255:
            raise Infrastructure("SSH connection lost during gate")
        receipt = self.run(f"cat {LOGS}/gate-exit", "gate-exit", check=False)
        if receipt.returncode or not receipt.stdout.strip().isdigit():
            raise Infrastructure(
                "gate timed out or stopped without its completed exit receipt"
            )
        return int(receipt.stdout.strip())

    def collect(self, server, timeout):
        self.deadline = time.monotonic() + timeout
        self.run(
            f'if test -f {LOGS}/sampler.pid; then kill -TERM "$(cat {LOGS}/sampler.pid)"; fi; docker ps -a --no-trunc >{LOGS}/docker-after.txt; docker network ls >{LOGS}/networks-after.txt; docker volume ls >{LOGS}/volumes-after.txt',
            "after-state",
            check=False,
        )
        ledger = self.config["ledger"]
        pack = f"""import tarfile,glob,shutil
from pathlib import Path
ledger=Path({ledger!r})
if ledger.exists():shutil.copyfile(ledger,{LOGS + "/ledger-after.tsv"!r})
logs=ledger.parent/'gate-logs'
if logs.exists():shutil.copytree(logs,{LOGS + "/ledger-gate-logs"!r},dirs_exist_ok=True)
paths=[{LOGS!r}]+glob.glob('/tmp/aweb-candidate-gate-*')+glob.glob('/tmp/aweb-ledger-evidence.*')
with tarfile.open({REMOTE + "/evidence.tar.gz"!r},'w:gz') as t:
 for path in paths:t.add(path,arcname=path.lstrip('/'))
"""
        self.run("python3 -c " + Q(pack), "evidence-pack")
        archive = self.directory / "evidence.tar.gz"
        self.transport.copy(
            REMOTE + "/evidence.tar.gz",
            archive,
            timeout=self.remaining(),
            download=True,
        )
        expected = self.run(
            f"sha256sum {REMOTE}/evidence.tar.gz", "evidence-hash"
        ).stdout.split()[0]
        if hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
            raise Infrastructure("local evidence archive hash differs from VM")
        result = collect_archive(
            archive, self.source["sha"], self.directory / "evidence"
        )
        result["archive_sha256"] = expected
        return result
