#!/usr/bin/env python3
"""Print whether one artifact's shipped content changed since its latest tag."""

from __future__ import annotations

import sys
from pathlib import Path

import release


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: release_artifact_moved.py ARTIFACT", file=sys.stderr)
        return 2
    matches = [artifact for artifact in release.ARTIFACTS if artifact.key == argv[0]]
    if len(matches) != 1:
        print(f"unknown artifact {argv[0]!r}", file=sys.stderr)
        return 2
    root = Path.cwd()
    artifact = matches[0]
    previous = release.latest_release(root, artifact)
    moved = release.content_changed(
        root,
        release.git(root, "rev-parse", "HEAD"),
        artifact,
        previous[1] if previous else None,
    )
    print("moving" if moved else "unmoved")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
