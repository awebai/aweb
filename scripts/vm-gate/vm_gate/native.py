"""A release job run directly on a host's own Docker, as antares and altair run gates.

The host is this machine or one reached by SSH. Each job gets its own
directory with an aweb checkout whose frozen origin main is the release
commit, its own copy of the canonical ledger, and the release inputs. The
deadline arrives as TERM to the job's process group, then KILL after a grace,
so the gates clean up and record what passed. Evidence and new ledger rows
come back to the controller.
"""

import shlex
import shutil
import subprocess
import time
from pathlib import Path

from .errors import Infrastructure
from .ledger import LedgerLease

Q = shlex.quote
GRACE_SECONDS = 120
# Runs on the host with its own Python: a session leader whose deadline is
# TERM to the job's group, then KILL after the grace. Exits with the job's code.
DEADLINE = r"""
import os, signal, subprocess, sys, time
seconds, grace, argv = float(sys.argv[1]), float(sys.argv[2]), sys.argv[3:]
job = subprocess.Popen(argv, start_new_session=True)
try:
    code = job.wait(timeout=seconds)
except subprocess.TimeoutExpired:
    os.killpg(job.pid, signal.SIGTERM)
    try:
        job.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        os.killpg(job.pid, signal.SIGKILL)
        job.wait()
    code = 124
sys.exit(code)
"""


class Host:
    """Commands and files on the release host: local, or over SSH."""

    def __init__(self, ssh=None):
        self.ssh = ssh

    def run(self, command, *, timeout=None, check=True):
        argv = (
            ["bash", "-c", command]
            if self.ssh is None
            else ["ssh", "-o", "BatchMode=yes", self.ssh, "bash -c " + Q(command)]
        )
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        if check and result.returncode:
            raise Infrastructure(
                f"native host command failed ({result.returncode}): {result.stderr.strip()}"
            )
        return result

    def put(self, local, remote):
        if self.ssh is None:
            shutil.copyfile(local, remote)
            return
        result = subprocess.run(
            ["scp", "-q", "-o", "BatchMode=yes", str(local), f"{self.ssh}:{remote}"],
            capture_output=True,
            text=True,
        )
        if result.returncode:
            raise Infrastructure(f"copy to {self.ssh} failed: {result.stderr.strip()}")

    def get_tree(self, remote, local):
        local = Path(local)
        local.mkdir(parents=True, exist_ok=True)
        if self.ssh is None:
            shutil.copytree(remote, local, dirs_exist_ok=True, symlinks=True)
            return
        pack = subprocess.Popen(
            [
                "ssh",
                "-o",
                "BatchMode=yes",
                self.ssh,
                "tar -C " + Q(remote) + " -cf - .",
            ],
            stdout=subprocess.PIPE,
        )
        assert pack.stdout is not None
        unpack = subprocess.run(
            ["tar", "-C", str(local), "-xf", "-"], stdin=pack.stdout
        )
        pack.stdout.close()
        if pack.wait() or unpack.returncode:
            raise Infrastructure(f"copy from {self.ssh} failed")

    def read(self, remote):
        return self.run("cat " + Q(remote)).stdout


def checkout_program(job, sha, frozen_main):
    """The aweb checkout, with a frozen origin whose main is the reviewed main."""
    return f"""set -euo pipefail
cd {Q(job)}
git init --quiet --bare origin
git --git-dir=origin fetch --quiet source.bundle '+refs/*:refs/*'
git --git-dir=origin update-ref refs/heads/main {Q(frozen_main)}
git --git-dir=origin symbolic-ref HEAD refs/heads/main
git clone --quiet origin source
git -C source checkout --quiet --detach {Q(sha)}
mkdir -p home logs gate-logs release-files
chmod 0700 .
"""


def run_release(
    *,
    host,
    root,
    run_id,
    source,
    inputs,
    script,
    owner,
    timeout,
    ledger_before,
    directory,
):
    """Run one release job on the host; return its exit, evidence and ledger."""
    job = f"{root.rstrip('/')}/{run_id}"
    host.run(f"mkdir -p {Q(job)} && chmod 0700 {Q(job)}")
    started = time.time()
    try:
        host.put(source["bundle"], job + "/source.bundle")
        host.run(checkout_program(job, source["sha"], source["frozen_main"]))
        host.put(inputs["bundle"], job + "/cloud.bundle")
        if inputs["archive"]:
            host.put(inputs["archive"], job + "/cloud-image.tar")
        for path in inputs["files"]:
            host.put(path, job + "/release-files/" + Path(path).name)
        host.put(inputs["hermes_key"], job + "/hermes-key")
        host.run(f"chmod 0600 {Q(job)}/hermes-key")
        host.put(ledger_before, job + "/ledger.tsv")
        release_script = directory / "release.sh"
        release_script.write_text(script(job))
        host.put(release_script, job + "/release.sh")
        deadline = directory / "deadline.py"
        deadline.write_text(DEADLINE)
        host.put(deadline, job + "/deadline.py")
        environment = " ".join(
            Q(f"{k}={v}")
            for k, v in {
                "AWEB_GATE_LEDGER": job + "/ledger.tsv",
                "AWEB_GATE_LOG_DIR": job + "/gate-logs",
                "GATE_OWNER": owner,
                # The release script splits the host with this checkout's vm_gate.
                "PYTHONPATH": job + "/source/scripts/vm-gate",
            }.items()
        )
        result = host.run(
            f"cd {Q(job)}/source && env {environment} python3 ../deadline.py "
            f"{timeout} {GRACE_SECONDS} bash ../release.sh > ../logs/gate-output.log 2>&1",
            check=False,
        )
    finally:
        # The test-only key never outlives the job on the host.
        host.run(f"rm -f {Q(job)}/hermes-key {Q(job)}/cloud-image.tar", check=False)
    evidence = directory / "evidence/var/log/vm-gate"
    host.get_tree(job + "/logs", evidence)
    ledger_after = host.read(job + "/ledger.tsv").encode()
    return {
        "exit": result.returncode,
        "timed_out": result.returncode == 124,
        "seconds": round(time.time() - started),
        "job": job,
        "ledger_after": ledger_after,
    }


class NativeRuntime:
    """The release job on a host's own Docker, with the canonical ledger's lease."""

    def __init__(self, *, config, directory, source, script, machine, inputs, timeout):
        self.config = config
        self.directory = Path(directory)
        self.source = source
        self.script = script
        self.machine = machine
        self.inputs = inputs
        self.timeout = timeout

    def run(self):
        with LedgerLease(self.config["ledger"], self.source["tree"]) as lease:
            before = lease.snapshot(self.directory / "ledger-before.tsv")
            outcome = run_release(
                host=Host(self.machine.get("ssh")),
                root=self.machine["root"],
                run_id=self.directory.name,
                source=self.source,
                inputs=self.inputs,
                script=self.script,
                owner=self.config["owner"],
                timeout=self.timeout,
                ledger_before=self.directory / "ledger-before.tsv",
                directory=self.directory,
            )
            rows = lease.import_rows(before, outcome["ledger_after"])
        result = {
            "exit": outcome["exit"],
            "infrastructure": None,
            "error": None,
            "ledger_rows_imported": rows,
            "job": outcome["job"],
            "seconds": outcome["seconds"],
        }
        if outcome["timed_out"]:
            result.update(
                infrastructure="infrastructure", error="release job deadline reached"
            )
        return result
