"""Distinct stock ARM admission and retained, native-only OCI qualification."""

import hashlib
import json
from pathlib import Path
import re
import subprocess

from .errors import Refused

PROFILE = "native-arm64-oci-v1"
ARCHIVE = "/evidence/server.oci.tar"
IDENTITY = ("sha256", "bytes", "index", "source_sha", "version")


def validate_image(image, disk):
    expected = {
        "id": 161547270,
        "status": "available",
        "architecture": "arm",
        "type": "system",
        "name": "ubuntu-24.04",
        "os_flavor": "ubuntu",
        "os_version": "24.04",
    }
    if (
        any(image.get(k) != v for k, v in expected.items())
        or image.get("disk_size", disk + 1) > disk
        or image.get("deprecated")
    ):
        raise Refused(
            "native ARM profile requires the admitted stock Ubuntu 24.04 ARM image"
        )


def validate_host(observed, expected):
    fixed = {
        "uid": 1000,
        "os_id": "ubuntu",
        "os_version": "24.04",
        "machine": "aarch64",
        "dpkg_architecture": "arm64",
        "docker_os": "linux",
        "docker_group": True,
    }
    if observed.get("uid") == 0:
        raise Refused("UID 0 refused")
    if any(observed.get(k) != v for k, v in fixed.items()):
        raise Refused("native ARM OS, architecture, UID or Docker-group mismatch")
    if observed.get("docker_architecture") not in {"aarch64", "arm64"}:
        raise Refused("Docker daemon is not native ARM64")
    for key in ("docker_version", "packages", "commands"):
        if not expected.get(key) or observed.get(key) != expected[key]:
            raise Refused("native Docker identity drift: " + key)


def validate_identity(identity):
    if not isinstance(identity, dict):
        raise Refused("missing OCI archive identity")
    for key, pattern in [
        ("sha256", r"[0-9a-f]{64}"),
        ("index", r"sha256:[0-9a-f]{64}"),
        ("source_sha", r"[0-9a-f]{40}"),
        ("version", r"[A-Za-z0-9.+_-]+"),
    ]:
        if not isinstance(identity.get(key), str) or not re.fullmatch(
            pattern, identity[key]
        ):
            raise Refused("invalid archive identity: " + key)
    if type(identity.get("bytes")) is not int or identity["bytes"] <= 0:
        raise Refused("invalid archive size")


def verify_archive(path, identity):
    validate_identity(identity)
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise Refused("archive is missing or is not a regular nonsymlink file")
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if path.stat().st_size != identity["bytes"] or digest != identity["sha256"]:
        raise Refused("archive SHA256 or size mismatch")
    return {key: identity[key] for key in IDENTITY}


def inspect_archive(path, identity, helper, directory):
    """Use the candidate's existing pure OCI inspector before provider access."""
    verify_archive(path, identity)
    directory = Path(directory)
    script = directory / "oci-inspector.sh"
    script.write_text(helper)
    output = directory / "archive-inspection.json"
    result = subprocess.run(
        [
            "bash",
            str(script),
            "inspect-staged",
            "--archive",
            str(path),
            "--version",
            identity["version"],
            "--source-sha",
            identity["source_sha"],
            "--out",
            str(output),
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    (directory / "archive-inspection.stdout").write_text(result.stdout)
    (directory / "archive-inspection.stderr").write_text(result.stderr)
    if result.returncode:
        raise Refused("retained OCI archive fails source/version/platform inspection")
    inspected = json.loads(output.read_text())
    if inspected.get("index") != identity["index"]:
        raise Refused("retained OCI archive index differs from x86 receipt")
    return inspected


def validate_native_receipt(receipt, platform):
    validate_identity(receipt)
    machine = "aarch64" if platform == "linux/arm64" else "x86_64"
    if (
        receipt.get("native_platform") != platform
        or receipt.get("native_pass") is not True
        or receipt.get("exit") != 0
        or receipt.get("machine") != machine
        or receipt.get("uid") != 1001
    ):
        raise Refused("successful native platform receipt required: " + platform)


def qualify_pair(amd64, arm64):
    validate_native_receipt(amd64, "linux/amd64")
    validate_native_receipt(arm64, "linux/arm64")
    if any(amd64[key] != arm64[key] for key in IDENTITY):
        raise Refused("native receipts disagree on archive/index/source/version")
    return {
        **{key: amd64[key] for key in IDENTITY},
        "platforms": ["linux/amd64", "linux/arm64"],
    }


def parse_receipt(output, sha, platform, exit_code):
    """The archive marker precedes probes; require the later native PASS too."""
    import ast

    markers = re.findall(r"^server image archive receipt=(.*)$", output, re.M)
    passes = re.findall(
        r"^server image " + re.escape(platform) + r" PASS: (.*)$", output, re.M
    )
    if exit_code != 0 or len(markers) != 1 or len(passes) != 1:
        raise Refused(
            "native harness did not complete with one archive and native PASS"
        )
    receipt = json.loads(markers[0])
    validate_identity(receipt)
    if receipt["source_sha"] != sha or receipt.get("native_platform") != platform:
        raise Refused("native harness source/platform differs from admitted source")
    probe = ast.literal_eval(passes[0])
    machine = "aarch64" if platform == "linux/arm64" else "x86_64"
    if (
        probe.get("uid") != 1001
        or probe.get("machine") != machine
        or probe.get("version") != receipt["version"]
    ):
        raise Refused("native packaged import identity mismatch")
    return {
        **receipt,
        "native_pass": True,
        "exit": exit_code,
        "machine": machine,
        "uid": 1001,
    }
