"""Stock Ubuntu ARM preparation; no snapshot or emulation admission fallback."""

import grp
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import subprocess
import sys

from .errors import Refused
from .native_oci import PROFILE, validate_host

Q = shlex.quote
PACKAGES = {"docker-ce", "docker-ce-cli", "containerd.io"}


def validate_profile(profile):
    apt = profile.get("apt", {})
    if profile.get("profile") != PROFILE or any(
        apt.get(k) != v
        for k, v in {
            "uri": "https://download.docker.com/linux/ubuntu",
            "suite": "noble",
            "component": "stable",
            "architecture": "arm64",
            "key_primary_fingerprint": "9DC858229FC7DD38854AE2D88D81803C0EBFCD88",
        }.items()
    ):
        raise Refused("unapproved native ARM profile or Docker APT authority")
    if not re.fullmatch(r"[0-9a-f]{64}", apt.get("key_sha256", "")):
        raise Refused("Docker signing-key hash required")
    if set(apt.get("packages", {})) != PACKAGES:
        raise Refused("exact Docker package pins required")
    for name, row in apt["packages"].items():
        if (
            row.get("Package") != name
            or row.get("Architecture") != "arm64"
            or not re.fullmatch(r"[0-9a-f]{64}", row.get("SHA256", ""))
            or not re.fullmatch(r"[A-Za-z0-9.+:~_-]+", row.get("Version", ""))
            or not re.fullmatch(
                r"dists/noble/pool/stable/arm64/[A-Za-z0-9.+~_-]+\.deb",
                row.get("Filename", ""),
            )
        ):
            raise Refused("invalid pinned Docker package identity: " + name)


def preparation_program(profile):
    validate_profile(profile)
    apt = profile["apt"]
    steps = [
        """set -euo pipefail
umask 022
test "$(uname -m)" = aarch64
. /etc/os-release
test "$ID" = ubuntu && test "$VERSION_ID" = 24.04
test "$(dpkg --print-architecture)" = arm64
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl gnupg git make python3 skopeo jq
install -d -m 0755 /etc/apt/keyrings /opt/vm-gate /var/log/vm-gate
curl --fail --silent --show-error https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
"""
    ]
    steps += [
        f"printf '%s\\n' {Q(apt['key_sha256'] + '  /etc/apt/keyrings/docker.asc')} | sha256sum -c -",
        f'test "$(gpg --show-keys --with-colons /etc/apt/keyrings/docker.asc | awk -F: \'$1=="fpr" {{print $10;exit}}\')" = {Q(apt["key_primary_fingerprint"])}',
        "chmod 0644 /etc/apt/keyrings/docker.asc",
        "printf '%s\\n' 'deb [arch=arm64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu noble stable' > /etc/apt/sources.list.d/docker.list",
        "apt-get update",
        "install -d -m 0700 /opt/vm-gate/docker-payloads",
    ]
    files = []
    for name, row in sorted(apt["packages"].items()):
        path = "/opt/vm-gate/docker-payloads/" + name + ".deb"
        files.append(path)
        # apt-cache is populated only after signed APT validation. Bind the
        # pinned payload to that signed index as well as its downloaded bytes.
        steps += [
            f"apt-cache show {Q(name + '=' + row['Version'])} > {Q(path + '.index')}",
            f"grep -Fx {Q('SHA256: ' + row['SHA256'])} {Q(path + '.index')}",
            f"curl --fail --silent --show-error {Q(apt['uri'] + '/' + row['Filename'])} -o {Q(path)}",
            f"printf '%s\\n' {Q(row['SHA256'] + '  ' + path)} | sha256sum -c -",
        ]
    steps += [
        "apt-get install -y " + " ".join(map(Q, files)),
        "systemctl enable --now docker",
        """account="$(getent passwd 1000 | cut -d: -f1 || true)"
if test -z "$account"; then useradd --uid 1000 --create-home --shell /bin/bash gateuser; account=gateuser; fi
test "$(id -u "$account")" = 1000
usermod -aG docker "$account"
group="$(id -gn "$account")"
install -d -m 0755 -o root -g root /opt/vm-gate/operator
install -d -m 0750 -o "$account" -g "$group" /var/log/vm-gate
install -d -m 0700 -o "$account" -g "$group" /evidence
dpkg-query -W > /var/log/vm-gate/native-packages.txt
docker info > /var/log/vm-gate/native-docker-info.txt
uname -a > /var/log/vm-gate/native-kernel.txt
""",
    ]
    return "\n".join(steps) + "\n"


def observe():
    def output(*args):
        return subprocess.check_output(args, text=True).strip()

    release = dict(
        line.split("=", 1)
        for line in Path("/etc/os-release").read_text().splitlines()
        if "=" in line
    )
    info = json.loads(output("docker", "info", "--format", "{{json .}}"))
    commands = {}
    for tool in ["docker", "skopeo", "python3", "git", "make"]:
        path = Path(shutil.which(tool) or "/missing").resolve()
        with path.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        commands[tool] = {"path": str(path), "sha256": digest}
    return {
        "uid": os.getuid(),
        "os_id": release["ID"].strip('"'),
        "os_version": release["VERSION_ID"].strip('"'),
        "machine": platform.machine(),
        "dpkg_architecture": output("dpkg", "--print-architecture"),
        "docker_os": info["OSType"],
        "docker_architecture": info["Architecture"],
        "docker_version": info["ServerVersion"],
        "docker_group": grp.getgrnam("docker").gr_gid in os.getgroups(),
        "packages": {
            name: output("dpkg-query", "-W", "-f=${Version}", name)
            for name in sorted(PACKAGES)
        },
        "commands": commands,
    }


def main():
    try:
        if os.getuid() == 0:
            raise Refused("UID 0 refused")
        expected = json.loads(Path(sys.argv[1]).read_text())
        source = json.loads(Path(sys.argv[2]).read_text())
        root = sys.argv[3]
        actual = subprocess.check_output(
            ["git", "-C", root, "rev-parse", "HEAD"], text=True
        ).strip()
        dirty = subprocess.check_output(
            ["git", "-C", root, "status", "--porcelain", "--untracked-files=all"],
            text=True,
        )
        if actual != source["sha"] or dirty:
            raise Refused("native source SHA/cleanliness mismatch")
        observed = observe()
        validate_host(observed, expected)
        print(json.dumps(observed, sort_keys=True))
        return 0
    except Refused as exc:
        print(str(exc), file=sys.stderr)
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
