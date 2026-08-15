#!/usr/bin/env python3
"""Print the desired version of one release artifact at HEAD."""

from __future__ import annotations

import sys
from pathlib import Path

import release


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: release_artifact_version.py ARTIFACT", file=sys.stderr)
        return 2
    matches = [artifact for artifact in release.ARTIFACTS if artifact.key == argv[0]]
    if len(matches) != 1:
        print(f"unknown release artifact: {argv[0]}", file=sys.stderr)
        return 2
    root = Path(__file__).resolve().parents[1]
    version, _moving = release.choose_version(
        root, release.git(root, "rev-parse", "HEAD"), matches[0]
    )
    print(version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
