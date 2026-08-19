#!/usr/bin/env python3
"""Run the complete Docker candidate suite and create requested local tags."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path


SEMVER = r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
TAG_PATTERN = re.compile(
    rf"^(server-v|awid-service-v|awid-v|aw-v|channel-v|pi-v|skills-v|a2a-gw-v)({SEMVER})$"
)
MANIFESTS = {
    "server-v": "server/pyproject.toml",
    "awid-service-v": "awid/pyproject.toml",
    "awid-v": "awid/pyproject.toml",
    "channel-v": "channel/package.json",
    "pi-v": "pi-extension/package.json",
    "skills-v": "packages/claude-skills/package.json",
}


class CandidateRefusal(RuntimeError):
    pass


def run(
    root: Path,
    *argv: str,
    capture: bool = True,
    env: dict[str, str] | None = None,
    timeout: int = 7200,
) -> str:
    completed = subprocess.run(
        argv,
        cwd=root,
        text=True,
        capture_output=capture,
        env=env,
        timeout=timeout,
        check=False,
    )
    if completed.returncode:
        detail = (completed.stderr or completed.stdout or "").strip()
        raise CandidateRefusal(f"{' '.join(argv)} failed: {detail}")
    return completed.stdout.strip() if capture else ""


def manifest_version(root: Path, path: str) -> str:
    if path.endswith(".toml"):
        with (root / path).open("rb") as handle:
            value = tomllib.load(handle)["project"]["version"]
    else:
        value = json.loads((root / path).read_text(encoding="utf-8"))["version"]
    if not isinstance(value, str) or not re.fullmatch(SEMVER, value):
        raise CandidateRefusal(f"{path} has invalid version {value!r}")
    return value


def validate_tags(root: Path, tags: list[str]) -> tuple[str, dict[str, str]]:
    if not tags:
        raise CandidateRefusal("at least one release tag is required")
    if len(tags) != len(set(tags)):
        raise CandidateRefusal("release tags contain a duplicate")
    if run(root, "git", "status", "--porcelain", "--untracked-files=all"):
        raise CandidateRefusal("the candidate checkout is dirty or has untracked files")
    source_sha = run(root, "git", "rev-parse", "HEAD")
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise CandidateRefusal("git did not return a full source SHA")
    versions: dict[str, str] = {}
    for tag in tags:
        matched = TAG_PATTERN.fullmatch(tag)
        if not matched:
            raise CandidateRefusal(f"unsupported release tag {tag!r}")
        prefix, version = matched.group(1), matched.group(2)
        if prefix in versions:
            raise CandidateRefusal(f"more than one {prefix} tag was requested")
        versions[prefix] = version
        manifest = MANIFESTS.get(prefix)
        if manifest and manifest_version(root, manifest) != version:
            raise CandidateRefusal(
                f"{tag} does not match {manifest} version {manifest_version(root, manifest)}"
            )
        if run(root, "git", "tag", "--list", tag):
            raise CandidateRefusal(f"local tag {tag} already exists; tags are never moved")
    return source_sha, versions


def create_candidate(root: Path, tags: list[str]) -> str:
    run(root, "git", "fetch", "--quiet", "origin", "main", "+refs/tags/*:refs/tags/*")
    source_sha, versions = validate_tags(root, tags)
    run(root, "git", "merge-base", "--is-ancestor", source_sha, "origin/main")
    environment = {**os.environ, "CANDIDATE_SOURCE_SHA": source_sha}
    if "aw-v" in versions:
        environment["CLI_VERSION"] = versions["aw-v"]
    if "a2a-gw-v" in versions:
        environment["A2A_GATEWAY_VERSION"] = versions["a2a-gw-v"]
    run(root, "scripts/candidate-docker-gate.sh", capture=False, env=environment)
    if run(root, "git", "rev-parse", "HEAD") != source_sha:
        raise CandidateRefusal("checkout HEAD changed while the Docker gate ran")
    if run(root, "git", "status", "--porcelain", "--untracked-files=all"):
        raise CandidateRefusal("the Docker gate left the candidate checkout dirty")
    for tag in tags:
        message = f"aweb OSS {tag}\n\nDocker candidate gate passed for {source_sha}."
        run(root, "git", "tag", "-a", tag, source_sha, "-m", message)
    print(f"candidate PASSED: {source_sha}")
    for tag in tags:
        print(f"  {tag}")
    print("publish each tag separately:")
    for tag in tags:
        print(f"  git push origin refs/tags/{tag}")
    return source_sha


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tags", nargs="+")
    arguments = parser.parse_args(argv)
    try:
        create_candidate(Path.cwd().resolve(), arguments.tags)
    except (
        CandidateRefusal,
        OSError,
        KeyError,
        TypeError,
        json.JSONDecodeError,
        subprocess.TimeoutExpired,
    ) as error:
        print(f"candidate refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
