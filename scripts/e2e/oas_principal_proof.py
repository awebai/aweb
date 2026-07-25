#!/usr/bin/env python3
"""Filesystem evidence helpers for the attached-principal retirement proof."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

SCHEMA = "aweb.oas-attached-principal-filesystem.v1"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _within_or_equal(root: Path, candidate: Path) -> bool:
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


def snapshot(root_value: str) -> dict[str, Any]:
    root = Path(root_value).resolve(strict=True)
    if not root.is_dir():
        raise ValueError(f"principal root is not a directory: {root}")

    entries: list[dict[str, Any]] = []
    paths = [root, *sorted(root.rglob("*"), key=lambda path: path.as_posix())]
    for path in paths:
        relative = "." if path == root else path.relative_to(root).as_posix()
        info = path.lstat()
        base: dict[str, Any] = {
            "path": relative,
            "mode": stat.S_IMODE(info.st_mode),
            "device": info.st_dev,
            "inode": info.st_ino,
        }
        if stat.S_ISLNK(info.st_mode):
            raise ValueError(f"principal store contains a symbolic link: {path}")
        if stat.S_ISDIR(info.st_mode):
            base["kind"] = "directory"
        elif stat.S_ISREG(info.st_mode):
            base.update(kind="file", size=info.st_size, sha256=_sha256(path))
        else:
            raise ValueError(f"principal store contains unsupported entry: {path}")
        entries.append(base)

    return {"schema": SCHEMA, "root": str(root), "entries": entries}


def write_snapshot(root: str, output: str) -> None:
    document = snapshot(root)
    Path(output).write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_snapshot(path: str) -> dict[str, Any]:
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    if document.get("schema") != SCHEMA or not isinstance(document.get("entries"), list):
        raise ValueError(f"invalid principal snapshot: {path}")
    return document


def assert_unchanged(root: str, expected_path: str) -> None:
    expected = load_snapshot(expected_path)
    actual = snapshot(root)
    if actual != expected:
        expected_lines = json.dumps(expected, indent=2, sort_keys=True).splitlines()
        actual_lines = json.dumps(actual, indent=2, sort_keys=True).splitlines()
        import difflib

        diff = "\n".join(
            difflib.unified_diff(expected_lines, actual_lines, fromfile="before", tofile="after", lineterm="")
        )
        raise AssertionError(f"principal store changed:\n{diff}")


def scan_instance(principal_snapshot_path: str, instance_value: str) -> None:
    principal = load_snapshot(principal_snapshot_path)
    principal_root = Path(principal["root"]).resolve(strict=True)
    instance_root = Path(instance_value).resolve(strict=True)
    if not instance_root.is_dir():
        raise ValueError(f"instance root is not a directory: {instance_root}")

    principal_digests = {
        entry["sha256"] for entry in principal["entries"] if entry.get("kind") == "file"
    }
    principal_inodes = {
        (entry["device"], entry["inode"])
        for entry in principal["entries"]
        if entry.get("kind") == "file"
    }

    stack = [instance_root]
    while stack:
        path = stack.pop()
        relative_parts = () if path == instance_root else path.relative_to(instance_root).parts
        if ".aw" in relative_parts:
            raise AssertionError(f"instance contains forbidden .aw path: {path}")

        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            target = Path(os.path.realpath(path))
            if _within_or_equal(principal_root, target):
                raise AssertionError(f"instance symlink resolves into principal store: {path} -> {target}")
            continue
        if stat.S_ISDIR(info.st_mode):
            stack.extend(sorted(path.iterdir(), key=lambda child: child.name, reverse=True))
            continue
        if stat.S_ISREG(info.st_mode):
            if (info.st_dev, info.st_ino) in principal_inodes:
                raise AssertionError(f"instance contains a principal hardlink: {path}")
            digest = _sha256(path)
            if digest in principal_digests:
                raise AssertionError(f"instance contains principal file content: {path} ({digest})")
            continue
        raise AssertionError(f"instance contains unsupported entry: {path}")


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    snapshot_parser = subparsers.add_parser("snapshot")
    snapshot_parser.add_argument("--root", required=True)
    snapshot_parser.add_argument("--output", required=True)

    unchanged_parser = subparsers.add_parser("assert-unchanged")
    unchanged_parser.add_argument("--root", required=True)
    unchanged_parser.add_argument("--snapshot", required=True)

    scan_parser = subparsers.add_parser("scan-instance")
    scan_parser.add_argument("--principal-snapshot", required=True)
    scan_parser.add_argument("--instance", required=True)

    args = parser.parse_args()
    if args.command == "snapshot":
        write_snapshot(args.root, args.output)
    elif args.command == "assert-unchanged":
        assert_unchanged(args.root, args.snapshot)
    elif args.command == "scan-instance":
        scan_instance(args.principal_snapshot, args.instance)
    else:  # pragma: no cover
        raise AssertionError(args.command)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"oas principal proof: {error}", file=sys.stderr)
        raise SystemExit(1)
