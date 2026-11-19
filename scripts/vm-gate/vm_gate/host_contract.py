"""Source pins plus recorded binary and package identities, checked on the VM."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from .admission import aweb_requirements, validate_remote_uid, validate_snapshot
from .errors import Refused


def verify_receipt(receipt, required, expected, sha):
    validate_remote_uid(receipt["uid"])
    if receipt["sha"] != sha:
        raise Refused(f"host checkout SHA differs from required {sha}")
    if receipt["gotoolchain"] != "local":
        raise Refused("GOTOOLCHAIN=local is required")
    validate_snapshot(required, receipt["observed"], sha)
    if receipt["commands"] != expected["commands"]:
        raise Refused(f"host binary hashes differ from snapshot at SHA {sha}")
    if receipt["dpkg"] != expected["dpkg"]:
        raise Refused(f"host package manifest differs from snapshot at SHA {sha}")
    return receipt


def verify_recording(receipt, required, expected, sha):
    validate_remote_uid(receipt["uid"])
    if receipt["sha"] != sha or receipt["gotoolchain"] != "local":
        raise Refused("snapshot recording source/toolchain differs")
    validate_snapshot(required, receipt["observed"], sha)
    allowed = {"go", "uv", "uvx", "node", "npm"}
    if set(receipt["commands"]) != set(expected["commands"]) or any(
        receipt["commands"][name] != value
        for name, value in expected["commands"].items()
        if name not in allowed
    ):
        raise Refused("snapshot changed an unrelated binary")
    if receipt["dpkg"] != expected["dpkg"]:
        raise Refused("snapshot changed the OS package manifest")
    return receipt


def get(args):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        raise Refused(f"host tool unavailable: {args[0]}") from None
    if result.returncode:
        raise Refused(f"host tool failed: {args[0]} (exit {result.returncode})")
    return result.stdout.strip()


def inspect_host(root, expected):
    validate_remote_uid(os.getuid())
    if os.environ.get("GOTOOLCHAIN") != "local":
        raise Refused("GOTOOLCHAIN=local is required")
    root = Path(root)
    sha = get(["git", "-C", str(root), "rev-parse", "HEAD"])
    if get(["git", "-C", str(root), "status", "--porcelain", "--untracked-files=all"]):
        raise Refused("VM checkout is dirty")
    required = aweb_requirements(
        (root / "cli/go/go.mod").read_text(),
        (root / "candidate-gate/Dockerfile").read_text(),
        sha,
    )
    observed = {
        "go": get(["go", "env", "GOVERSION"]).removeprefix("go"),
        "uv": get(["uv", "--version"]).split()[1],
        "node": get(["node", "--version"]).removeprefix("v").split(".")[0],
        "python": ".".join(get(["python3", "--version"]).split()[1].split(".")[:2]),
    }
    commands = {}
    for name in expected["commands"]:
        path = shutil.which(name)
        if path is None:
            raise Refused("host command missing: " + name)
        target = Path(path).resolve()
        commands[name] = {
            "path": path,
            "target": str(target),
            "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
        }
    receipt = {
        "uid": os.getuid(),
        "gid": os.getgid(),
        "groups": os.getgroups(),
        "sha": sha,
        "gotoolchain": os.environ.get("GOTOOLCHAIN"),
        "required": required,
        "observed": observed,
        "commands": commands,
        "dpkg": get(["dpkg-query", "-W", "-f=${Package}=${Version}\n"]),
    }
    return receipt


def main():
    try:
        args = sys.argv[1:]
        record = args[:1] == ["record"]
        if record:
            args = args[1:]
        root, source_path, expected_path = args
        source = json.loads(Path(source_path).read_text())
        expected = json.loads(Path(expected_path).read_text())
        receipt = inspect_host(root, expected)
        (verify_recording if record else verify_receipt)(
            receipt, source["requirements"], expected, source["sha"]
        )
        print(json.dumps(receipt, indent=2))
    except Refused as exc:
        print(str(exc), file=sys.stderr)
        return int(exc.exit_code)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
