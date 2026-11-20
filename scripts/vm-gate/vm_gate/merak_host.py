"""Run on the Merak SSH host. One flock covers the whole guest lifetime."""

import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import subprocess
import sys


ROOT = Path.home() / ".local/share/aweb-gates"
LABEL = "aweb.merak.run"
RUN = re.compile(r"vm-[a-f0-9]{32}")


def docker(*args):
    return subprocess.run(
        ["docker", *args], check=True, capture_output=True, text=True, timeout=120
    ).stdout.strip()


def notify(**fields):
    print(json.dumps(fields), flush=True)


def remove_guest(job):
    if job.is_symlink() or not RUN.fullmatch(job.name) or job.parent != ROOT / "runs":
        raise ValueError("invalid guest directory")
    if job.exists() and (job / "owner").read_text().strip() != job.name:
        raise ValueError("missing run directory ownership")
    selector = f"label={LABEL}={job.name}"
    ids = docker("ps", "-aq", "--no-trunc", "--filter", selector).splitlines()
    for identifier in ids:
        docker("rm", "-fv", identifier)
    remaining = docker("ps", "-aq", "--filter", selector)
    existing = set(docker("ps", "-aq", "--no-trunc").splitlines())
    if remaining or existing.intersection(ids):
        raise RuntimeError("guest container still present")
    volumes = docker("volume", "ls", "-q", "--filter", selector)
    networks = docker("network", "ls", "-q", "--filter", selector)
    if volumes or networks:
        raise RuntimeError("run-labelled launcher volumes or networks remain")
    if job.exists():
        shutil.rmtree(job)
    return {
        "run_id": job.name,
        "container_ids": ids,
        "exact_ids_absent": not existing.intersection(ids) and not job.exists(),
        "labels_absent": not remaining,
        "host_volumes_remaining": [],
        "host_networks_remaining": [],
        "guest_disk_and_checkout_absent": not job.exists(),
        "disk_free_after": shutil.disk_usage(ROOT).free,
    }


def serve(spec):
    run = spec["run"]
    if not RUN.fullmatch(run) or not re.fullmatch("[0-9a-f]{64}", spec["base"]):
        raise ValueError("invalid Merak run or image digest")
    if not re.fullmatch("sha256:[0-9a-f]{64}", spec["launcher"]):
        raise ValueError("launcher must be pinned by image ID")
    duration = spec["duration"]
    if type(duration) is not int or not 0 < duration <= 86400:
        raise ValueError("invalid guest lifetime")
    runs = ROOT / "runs"
    runs.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (ROOT / "slot.lock").open("a") as lock:
        # Do not hold an SSH connection in the queue after its caller disconnects.
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if select.select([sys.stdin], [], [], 2)[0]:
                    return
        # The exclusive lock is inherited by no guest. A stale directory belongs
        # to a previous interrupted controller; reconcile its exact run first.
        for stale in sorted(runs.iterdir()):
            if RUN.fullmatch(stale.name):
                receipt = remove_guest(stale)
                (ROOT / (stale.name + ".closure.json")).write_text(json.dumps(receipt))
        base = ROOT / "base" / (spec["base"] + ".raw")
        if base.is_symlink() or not base.is_file() or base.stat().st_mode & 0o222:
            raise ValueError("base disk must be a read-only regular file")
        with base.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != spec["base"]:
                raise ValueError("base image digest mismatch")
        job = runs / run
        before = shutil.disk_usage(runs).free
        job.mkdir(mode=0o700)
        (job / "owner").write_text(run)
        try:
            (job / "user-data").write_text("#cloud-config\n" + json.dumps(spec["seed"]))
            (job / "meta-data").write_text(
                json.dumps({"instance-id": run, "local-hostname": run})
            )
            (job / "network-config").write_text(
                json.dumps(
                    {
                        "version": 2,
                        "ethernets": {
                            "gate": {
                                "match": {"macaddress": "52:54:00:aa:bb:01"},
                                "dhcp4": True,
                            }
                        },
                    }
                )
            )
            identifier = docker(
                "run",
                "-d",
                "--pull=never",
                "--name",
                run,
                "--label",
                f"{LABEL}={run}",
                "--device=/dev/kvm",
                "--user",
                f"{os.getuid()}:{os.getgid()}",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--read-only",
                "--tmpfs",
                "/tmp",
                "--memory",
                "50g",
                "--memory-swap",
                "50g",
                "--mount",
                f"type=bind,src={base},dst=/base/disk.raw,readonly",
                "--mount",
                f"type=bind,src={job},dst=/job",
                spec["launcher"],
            )
            notify(
                ready=True,
                run=run,
                container=identifier,
                base=spec["base"],
                disk_free_before=before,
            )
            # EOF (including lost controller) and deadline take the same cleanup path.
            if select.select([sys.stdin], [], [], duration)[0]:
                sys.stdin.readline()
        finally:
            closure = remove_guest(job)
            (ROOT / (run + ".closure.json")).write_text(json.dumps(closure))
            notify(cleanup=closure)


if __name__ == "__main__":
    os.umask(0o077)
    if len(sys.argv) == 3 and sys.argv[1] == "--reconcile":
        run = sys.argv[2]
        if not RUN.fullmatch(run):
            raise ValueError("invalid reconciliation identity")
        path = ROOT / (run + ".closure.json")
        if not path.is_file():
            with (ROOT / "slot.lock").open("a") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                if not path.is_file():
                    path.write_text(json.dumps(remove_guest(ROOT / "runs" / run)))
        print(path.read_text())
    else:
        serve(json.loads(sys.stdin.readline()))
