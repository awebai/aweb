#!/usr/bin/env python3
"""Select npm publication channels and promote the existing seven aw packages."""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import urllib.request

FINAL = r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
PACKAGES = ("aw-linux-x64", "aw-linux-arm64", "aw-darwin-x64", "aw-darwin-arm64",
            "aw-windows-x64", "aw-windows-arm64", "aw")
DECLARATION = "Npm-Publish-Channel:"


def channel(version: str, *, staged_final: bool = False,
            repository: Path | None = None, tag: str | None = None) -> str:
    if not re.fullmatch(FINAL + r"(?:-rc\.[1-9][0-9]*)?", version):
        raise ValueError("npm version must be X.Y.Z or X.Y.Z-rc.N (N >= 1)")
    if tag:
        raw = subprocess.check_output(
            ["git", "-C", str(repository or Path.cwd()), "for-each-ref",
             "--format=%(objecttype)%00%(contents)", "refs/tags/" + tag], text=True)
        kind, _, message = raw.partition("\0")
        if kind != "tag":
            message = ""  # A lightweight tag's commit message is not a declaration.
        declarations = [line[len(DECLARATION):].strip() for line in message.splitlines()
                        if line.startswith(DECLARATION)]
        if declarations:
            if declarations != ["next"]:
                raise ValueError("tag must declare Npm-Publish-Channel: next exactly once")
            staged_final = True
    if staged_final and not re.fullmatch(FINAL, version):
        raise ValueError("staged-final publication requires a final version")
    return "next" if staged_final or "-rc." in version else "latest"


def npm_json(*args: str):
    return json.loads(subprocess.check_output(["npm", *args, "--json"], text=True))


def verify_package(name: str, version: str) -> None:
    metadata = npm_json("view", name + "@" + version)
    if not isinstance(metadata, dict) or metadata.get("name") != name or metadata.get("version") != version:
        raise ValueError(f"missing or mismatched package: {name}@{version}")
    dist = metadata.get("dist") or {}
    integrity, url = dist.get("integrity"), dist.get("tarball")
    if not isinstance(integrity, str) or not integrity.startswith("sha512-") or not isinstance(url, str):
        raise ValueError(f"missing tarball or sha512 integrity: {name}@{version}")
    expected = base64.b64decode(integrity[len("sha512-"):], validate=True)
    with urllib.request.urlopen(url, timeout=30) as response:
        raw = response.read()
    if hashlib.sha512(raw).digest() != expected:
        raise ValueError(f"tarball integrity mismatch: {name}@{version}")
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        stream = archive.extractfile("package/package.json")
        if stream is None:
            raise ValueError(f"tarball has no package.json: {name}@{version}")
        manifest = json.load(stream)
    if manifest.get("name") != name or manifest.get("version") != version:
        raise ValueError(f"tarball package identity mismatch: {name}@{version}")
    if name == "@awebai/aw":
        expected_dependencies = {"@awebai/" + package: version for package in PACKAGES[:-1]}
        if manifest.get("optionalDependencies") != expected_dependencies:
            raise ValueError("aw wrapper must pin the same six platform versions")
    print(f"VERIFIED: {name}@{version} {integrity} sha256:{hashlib.sha256(raw).hexdigest()}", flush=True)


def promote_latest(version: str) -> None:
    if not re.fullmatch(FINAL, version):
        raise ValueError("latest promotion requires a final version")
    # Check every existing tarball before the first mutation. npm versions are
    # immutable; promotion changes only their public installation pointers.
    for package in PACKAGES:
        verify_package("@awebai/" + package, version)
    for package in PACKAGES:
        name = "@awebai/" + package
        subprocess.run(["npm", "dist-tag", "add", name + "@" + version, "latest"], check=True)
        if npm_json("view", name, "dist-tags.latest") != version:
            raise ValueError(f"latest read-back mismatch: {name}@{version}")
        print(f"PROMOTED: {name}@{version} -> latest", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    select = commands.add_parser("channel")
    select.add_argument("--version", required=True)
    select.add_argument("--staged-final", action="store_true")
    select.add_argument("--tag")
    select.add_argument("--repository", type=Path)
    promote = commands.add_parser("promote-latest", help="verify published final tarballs, then move their tags; no rebuild")
    promote.add_argument("--version", required=True)
    args = parser.parse_args()
    try:
        if args.operation == "channel":
            print(channel(args.version, staged_final=args.staged_final,
                          repository=args.repository, tag=args.tag))
        else:
            promote_latest(args.version)
    except (ValueError, OSError, subprocess.CalledProcessError, tarfile.TarError) as error:
        print(f"npm publication refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
