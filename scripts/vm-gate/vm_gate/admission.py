"""Local admission runs before credentials and provider operations."""

import re
import subprocess

from .errors import Refused


def validate_bundle_heads(heads, sha, ref):
    advertised = dict(
        (parts[1], parts[0])
        for line in heads.splitlines()
        if len(parts := line.split()) == 2
    )
    if ref not in advertised:
        raise Refused(f"source bundle lacks advertised ref {ref}")
    if advertised[ref] != sha:
        raise Refused(
            f"advertised ref SHA differs: required {sha}, observed {advertised[ref]}"
        )


def aweb_requirements(go_mod, dockerfile, sha):
    def pin(name, pattern, text):
        matches = set(re.findall(pattern, text, re.MULTILINE))
        if len(matches) != 1:
            raise Refused(f"missing or ambiguous {name} pin at {sha}")
        return matches.pop()

    required = {
        "go": pin("go", r"^go (\S+)$", go_mod),
        "uv": pin("uv", r"COPY --from=ghcr.io/astral-sh/uv:([^\s]+)", dockerfile),
        "node": pin("node", r"node_(\d+)\.x", dockerfile),
        "python": pin("python", r"^FROM python:([\d.]+)-", dockerfile),
    }
    if pin("go", r"^ARG GO_VERSION=(\S+)", dockerfile) != required["go"]:
        raise Refused(f"Go source pins disagree at {sha}")
    return required


def validate_snapshot(required, observed, sha):
    for tool, version in required.items():
        actual = observed.get(tool, "missing")
        if actual != version:
            raise Refused(
                f"pin mismatch: {tool} required {version}, observed {actual}, SHA {sha}; "
                f"run vm-gate snapshot --sha {sha}"
            )


def validate_remote_uid(uid):
    if uid == 0:
        raise Refused("UID 0 refused at gate admission; UID 1000 required")
    if uid != 1000:
        raise Refused(f"UID 1000 required at gate admission, observed {uid}")


def validate_command(command):
    if not command.strip():
        raise Refused("empty focused command")
    if "\0" in command:
        raise Refused("command syntax contains a NUL byte")
    result = subprocess.run(
        ["bash", "-n"], input=command, text=True, capture_output=True
    )
    if result.returncode:
        raise Refused("command syntax refused: " + result.stderr.strip())
