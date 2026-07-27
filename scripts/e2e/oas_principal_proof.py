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


def capture_structure(root_value: str) -> list[dict[str, Any]]:
    root = Path(root_value).resolve(strict=True)
    rows: list[dict[str, Any]] = []

    def visit(path: Path, relative: str) -> None:
        info = path.lstat()
        row: dict[str, Any] = {
            "path": relative,
            "mode": stat.S_IMODE(info.st_mode),
            "device": info.st_dev,
            "inode": info.st_ino,
        }
        if stat.S_ISLNK(info.st_mode):
            row.update(kind="symlink", target=os.readlink(path))
        elif stat.S_ISDIR(info.st_mode):
            row["kind"] = "directory"
        elif stat.S_ISREG(info.st_mode):
            row.update(kind="file", sha256=_sha256(path))
        else:
            row["kind"] = "other"
        rows.append(row)
        if row["kind"] == "directory":
            for child in sorted(path.iterdir(), key=lambda item: item.name):
                child_relative = child.name if relative == "." else f"{relative}/{child.name}"
                visit(child, child_relative)

    visit(root, ".")
    return rows


def write_structure_snapshot(root_value: str, output_value: str) -> None:
    rows = capture_structure(root_value)
    Path(output_value).write_text(json.dumps(rows, indent=2, sort_keys=True) + "\n", encoding="utf-8")


RUNTIME_STATE_MAX_BYTES = 1024 * 1024
INTERACTION_LOG_KEYS = {
    "ts", "kind", "message_id", "session_id", "conversation_id", "from", "to", "subject", "text"
}
RUNTIME_STATE_LEAVES = {".aw/interaction-log.jsonl", ".aw/channel-delivered-ids.json"}


def _validate_runtime_state(path: Path, relative: str, encoded: bytes) -> None:
    if len(encoded) > RUNTIME_STATE_MAX_BYTES:
        raise AssertionError(f"runtime state exceeds 1 MiB: {path}")
    try:
        text = encoded.decode("utf-8")
    except UnicodeDecodeError as error:
        raise AssertionError(f"runtime state is not UTF-8: {path}") from error
    if relative == ".aw/interaction-log.jsonl":
        for line_number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                document = json.loads(line)
            except json.JSONDecodeError as error:
                raise AssertionError(f"interaction log line {line_number} is not JSON: {path}") from error
            if not isinstance(document, dict) or not set(document) <= INTERACTION_LOG_KEYS:
                raise AssertionError(f"interaction log line {line_number} has unbounded shape: {path}")
    elif relative == ".aw/channel-delivered-ids.json":
        try:
            document = json.loads(text)
        except json.JSONDecodeError as error:
            raise AssertionError(f"delivered-id store is not JSON: {path}") from error
        if not isinstance(document, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in document.items()
        ):
            raise AssertionError(f"delivered-id store is not a string map: {path}")


def _scan_material(principal_snapshot_path: str, instance_value: str, *, allow_runtime_state: bool) -> None:
    principal = load_snapshot(principal_snapshot_path)
    principal_root = Path(principal["root"]).resolve(strict=True)
    instance_root = Path(instance_value).resolve(strict=True)
    if not instance_root.is_dir():
        raise ValueError(f"instance root is not a directory: {instance_root}")

    principal_digests = {
        entry["sha256"] for entry in principal["entries"] if entry.get("kind") == "file"
    }
    principal_contents: set[bytes] = set()
    for entry in principal["entries"]:
        if entry.get("kind") != "file":
            continue
        content = (principal_root / entry["path"]).read_bytes()
        for needle in (content, content.strip()):
            if len(needle) >= 16:
                principal_contents.add(needle)
    principal_inodes = {
        (entry["device"], entry["inode"])
        for entry in principal["entries"]
        if entry.get("kind") == "file"
    }

    stack = [instance_root]
    while stack:
        path = stack.pop()
        relative = "." if path == instance_root else path.relative_to(instance_root).as_posix()
        relative_parts = () if relative == "." else Path(relative).parts
        under_dot_aw = ".aw" in relative_parts
        if under_dot_aw:
            if not allow_runtime_state:
                raise AssertionError(f"instance contains forbidden .aw path: {path}")
            if relative != ".aw" and relative not in RUNTIME_STATE_LEAVES:
                raise AssertionError(f"instance contains unexpected .aw path: {path}")

        info = path.lstat()
        if relative == ".aw" and allow_runtime_state and not stat.S_ISDIR(info.st_mode):
            raise AssertionError(f"runtime state root must be a real directory: {path}")
        if relative in RUNTIME_STATE_LEAVES and not stat.S_ISREG(info.st_mode):
            raise AssertionError(f"runtime state must be a regular file: {path}")
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
            encoded = path.read_bytes()
            digest = hashlib.sha256(encoded).hexdigest()
            if digest in principal_digests:
                raise AssertionError(f"instance contains principal file content: {path} ({digest})")
            if any(content in encoded for content in principal_contents):
                raise AssertionError(f"runtime state embeds principal file bytes: {path} ({digest})")
            if relative in RUNTIME_STATE_LEAVES:
                _validate_runtime_state(path, relative, encoded)
            continue
        raise AssertionError(f"instance contains unsupported entry: {path}")


def scan_instance(principal_snapshot_path: str, instance_value: str) -> None:
    _scan_material(principal_snapshot_path, instance_value, allow_runtime_state=False)


def scan_sensitive_material(principal_snapshot_path: str, instance_value: str) -> None:
    """Validate bounded runtime-state leaves and reject verbatim principal-store byte sequences."""
    _scan_material(principal_snapshot_path, instance_value, allow_runtime_state=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    snapshot_parser = subparsers.add_parser("snapshot")
    snapshot_parser.add_argument("--root", required=True)
    snapshot_parser.add_argument("--output", required=True)

    unchanged_parser = subparsers.add_parser("assert-unchanged")
    unchanged_parser.add_argument("--root", required=True)
    unchanged_parser.add_argument("--snapshot", required=True)

    structure_parser = subparsers.add_parser("snapshot-structure")
    structure_parser.add_argument("--root", required=True)
    structure_parser.add_argument("--output", required=True)

    scan_parser = subparsers.add_parser("scan-instance")
    scan_parser.add_argument("--principal-snapshot", required=True)
    scan_parser.add_argument("--instance", required=True)

    sensitive_parser = subparsers.add_parser("scan-sensitive-material")
    sensitive_parser.add_argument("--principal-snapshot", required=True)
    sensitive_parser.add_argument("--instance", required=True)

    args = parser.parse_args()
    if args.command == "snapshot":
        write_snapshot(args.root, args.output)
    elif args.command == "assert-unchanged":
        assert_unchanged(args.root, args.snapshot)
    elif args.command == "snapshot-structure":
        write_structure_snapshot(args.root, args.output)
    elif args.command == "scan-instance":
        scan_instance(args.principal_snapshot, args.instance)
    elif args.command == "scan-sensitive-material":
        scan_sensitive_material(args.principal_snapshot, args.instance)
    else:  # pragma: no cover
        raise AssertionError(args.command)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"oas principal proof: {error}", file=sys.stderr)
        raise SystemExit(1)
