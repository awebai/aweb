#!/usr/bin/env python3
"""Print the next patch version for one immutable local tag prefix."""

from __future__ import annotations

import re
import subprocess
import sys


SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


def next_version(prefix: str) -> str:
    output = subprocess.check_output(
        ["git", "tag", "--list", f"{prefix}*"], text=True
    )
    versions = []
    for tag in output.splitlines():
        value = tag.removeprefix(prefix)
        if tag.startswith(prefix) and SEMVER.fullmatch(value):
            versions.append(tuple(int(part) for part in value.split(".")))
    if not versions:
        raise RuntimeError(f"no {prefix}X.Y.Z tag exists")
    major, minor, patch = max(versions)
    return f"{major}.{minor}.{patch + 1}"


def main(argv: list[str]) -> int:
    if len(argv) != 1 or not argv[0] or any(char.isspace() for char in argv[0]):
        print("usage: next_tag_version.py TAG_PREFIX", file=sys.stderr)
        return 2
    try:
        print(next_version(argv[0]))
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"cannot derive next tag version: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
