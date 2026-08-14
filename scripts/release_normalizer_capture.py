#!/usr/bin/env python3
"""Repository-side capture for the normalizer (aben, design section 6).

The I/O half that reads repositories: anchor tag discovery with peeled
identities, content-changed over a canonical scope against the anchor
commit with the fixed-point exclusions, and manifest version reads.
Registry-side capture (listing discovery) lives beside it; both feed the
pure normalize() and are called exactly once per pass so the
double-compute determinism check compares computation, not I/O.
"""

from __future__ import annotations

import json
import re
import subprocess
import tomllib
from pathlib import Path

from release_normalizer import parse_version


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True
    ).stdout


def discover_anchor_tags(repo: Path, prefix: str) -> dict[str, str]:
    """All grammar-conforming anchor tags on origin, peeled to commits.

    Non-grammar candidates under the prefix are excluded (logged by the
    caller); the version-namespace ambiguity stop belongs to the
    reconciler, which sees the raw listing when it needs it.
    """

    lines = _git(repo, "ls-remote", "origin", f"refs/tags/{prefix}*").splitlines()
    direct: dict[str, str] = {}
    peeled: dict[str, str] = {}
    for line in lines:
        sha, ref = line.split(None, 1)
        name = ref.removeprefix("refs/tags/")
        if name.endswith("^{}"):
            peeled[name[:-3]] = sha
        else:
            direct[name] = sha
    tags: dict[str, str] = {}
    for name, sha in direct.items():
        version_text = name.removeprefix(prefix)
        if parse_version(version_text) is None:
            continue
        tags[version_text] = peeled.get(name, sha)
    return tags


def content_changed(
    repo: Path,
    anchor_sha: str,
    *,
    scope: tuple[str, ...],
    excluded: tuple[str, ...],
) -> bool:
    """Does the scope's content differ between the anchor commit and HEAD,
    ignoring the excluded version manifests and owned locks?"""

    names = _git(
        repo, "diff", "--name-only", f"{anchor_sha}..HEAD", "--", *scope
    ).splitlines()
    remaining = [name for name in names if name not in excluded]
    return bool(remaining)


def manifest_version(path: Path) -> str:
    """The committed version from a pyproject.toml or package.json."""

    if path.name == "package.json":
        return json.loads(path.read_text())["version"]
    if path.suffix == ".toml":
        return tomllib.load(path.open("rb"))["project"]["version"]
    raise ValueError(f"unsupported manifest kind: {path}")
