#!/usr/bin/env python3
"""Filesystem evidence helpers for the attached-principal retirement proof."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
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
INTERACTION_LOG_KINDS = {"user", "agent", "chat_in", "chat_out", "mail_in", "mail_out"}
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
            if not {"ts", "kind"} <= set(document):
                raise AssertionError(f"interaction log line {line_number} lacks required discriminators: {path}")
            if not all(isinstance(value, str) and value.strip() for value in document.values()):
                raise AssertionError(f"interaction log line {line_number} has non-string or empty values: {path}")
            if document["kind"] not in INTERACTION_LOG_KINDS:
                raise AssertionError(f"interaction log line {line_number} has unknown kind: {path}")
            if not document.get("text", "").strip() and not document.get("subject", "").strip():
                raise AssertionError(f"interaction log line {line_number} has no interaction content: {path}")
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


def _content_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    return "\n".join(
        block.get("text", "")
        for block in content
        if isinstance(block, dict) and block.get("type") == "text"
    )


def _json_object_from_text(text: str) -> dict[str, Any]:
    start = text.find("{")
    if start < 0:
        raise ValueError("tool result contains no JSON object")
    document, _ = json.JSONDecoder().raw_decode(text[start:])
    if not isinstance(document, dict):
        raise ValueError("tool result JSON is not an object")
    if document.get("schemaVersion") == 1 and isinstance(document.get("result"), dict):
        return document["result"]
    return document


def _resident_session_entries(session_path: str, expected_session_cwd: str) -> list[dict[str, Any]]:
    entries = [
        json.loads(line)
        for line in Path(session_path).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if not entries or entries[0].get("type") != "session":
        raise AssertionError("resident session has no session header")
    if entries[0].get("cwd") != expected_session_cwd:
        raise AssertionError(
            f"resident session cwd {entries[0].get('cwd')!r} does not match spawned home {expected_session_cwd!r}"
        )
    return entries


def _resident_session_calls(
    entries: list[dict[str, Any]], expected_provider: str, expected_model: str
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]], list[dict[str, Any]]]:
    tool_calls: list[dict[str, Any]] = []
    tool_results: dict[str, dict[str, Any]] = {}
    settled: list[dict[str, Any]] = []
    for index, entry in enumerate(entries):
        if entry.get("type") != "message" or not isinstance(entry.get("message"), dict):
            continue
        message = entry["message"]
        if message.get("role") == "assistant":
            if message.get("provider") != expected_provider or message.get("model") != expected_model:
                raise AssertionError(
                    f"resident assistant used {message.get('provider')}/{message.get('model')}, "
                    f"expected {expected_provider}/{expected_model}"
                )
            content = message.get("content") if isinstance(message.get("content"), list) else []
            calls_in_message = 0
            for block_index, block in enumerate(content):
                if not isinstance(block, dict) or block.get("type") != "toolCall" or block.get("name") != "bash":
                    continue
                arguments = block.get("arguments") if isinstance(block.get("arguments"), dict) else {}
                command = arguments.get("command")
                if isinstance(block.get("id"), str) and isinstance(command, str):
                    calls_in_message += 1
                    tool_calls.append({
                        "id": block["id"], "command": command, "index": index,
                        "block_index": block_index,
                    })
            if message.get("stopReason") == "stop" and calls_in_message == 0:
                settled.append({"index": index, "text": _content_text(content)})
        elif message.get("role") == "toolResult" and isinstance(message.get("toolCallId"), str):
            tool_results[message["toolCallId"]] = {"index": index, "message": message}
    return tool_calls, tool_results, settled


def assert_resident_readiness(
    session_path: str,
    *,
    expected_address: str,
    expected_stable_id: str,
    expected_ready_subject: str,
    expected_ready_body: str,
    expected_session_cwd: str,
    expected_provider: str,
    expected_model: str,
) -> dict[str, Any]:
    entries = _resident_session_entries(session_path, expected_session_cwd)
    tool_calls, tool_results, settled = _resident_session_calls(entries, expected_provider, expected_model)
    identity_call = next(
        (
            call for call in tool_calls
            if shlex.split(call["command"]) == ["aw", "whoami", "--json"]
        ),
        None,
    )
    if identity_call is None:
        raise AssertionError("resident session has no exact ordinary aw whoami --json tool call")
    identity_result = tool_results.get(identity_call["id"])
    if identity_result is None or identity_result["message"].get("isError") is not False:
        raise AssertionError("resident session has no successful whoami tool result")
    identity = _json_object_from_text(_content_text(identity_result["message"].get("content")))
    observed_identity = {"address": identity.get("address"), "stable_id": identity.get("stable_id")}
    expected_identity = {"address": expected_address, "stable_id": expected_stable_id}
    if observed_identity != expected_identity:
        raise AssertionError(
            f"resident whoami identity {observed_identity!r} does not match {expected_identity!r}"
        )

    ready_call = next(
        (
            call for call in tool_calls
            if re.search(r"(?:^|[;&|]\s*)aw\s+mail\s+send(?:\s|$)", call["command"], re.MULTILINE)
            and expected_ready_subject in call["command"]
            and expected_ready_body in call["command"]
            and re.search(r"--to(?:\s+|=)observer(?:\s|$)", call["command"])
        ),
        None,
    )
    if ready_call is None:
        raise AssertionError("resident session has no matching ready-mail tool call")
    ready_result = tool_results.get(ready_call["id"])
    if ready_result is None or ready_result["message"].get("isError") is not False:
        raise AssertionError("resident session has no successful ready-mail tool result")
    settled_entry = next(
        (item for item in settled if item["index"] > ready_result["index"]),
        None,
    )
    if not (
        identity_call["index"] < identity_result["index"]
        < ready_call["index"] < ready_result["index"]
        and settled_entry is not None
    ):
        raise AssertionError("resident readiness was not observed after ordered identity and ready-mail results")
    return {
        "session_file": str(Path(session_path).resolve(strict=True)),
        "session_cwd": expected_session_cwd,
        "session_id": entries[0].get("id"),
        "model": {"provider": expected_provider, "model": expected_model},
        "identity": observed_identity,
        "identity_tool_call_id": identity_call["id"],
        "ready_tool_call_id": ready_call["id"],
        "ready_settled_index": settled_entry["index"],
    }


def assert_resident_session(
    session_path: str,
    *,
    expected_address: str,
    expected_stable_id: str,
    expected_message_id: str,
    expected_wake_body: str,
    expected_reply_body: str,
    expected_ready_subject: str,
    expected_ready_body: str,
    expected_session_cwd: str,
    expected_provider: str,
    expected_model: str,
) -> dict[str, Any]:
    readiness = assert_resident_readiness(
        session_path,
        expected_address=expected_address,
        expected_stable_id=expected_stable_id,
        expected_ready_subject=expected_ready_subject,
        expected_ready_body=expected_ready_body,
        expected_session_cwd=expected_session_cwd,
        expected_provider=expected_provider,
        expected_model=expected_model,
    )
    entries = _resident_session_entries(session_path, expected_session_cwd)
    tool_calls, tool_results, _ = _resident_session_calls(entries, expected_provider, expected_model)
    wake: dict[str, Any] | None = None
    for index, entry in enumerate(entries):
        if entry.get("type") != "custom_message" or entry.get("customType") != "aweb-channel":
            continue
        details = entry.get("details") if isinstance(entry.get("details"), dict) else {}
        verified = details.get("verified") in (True, "true")
        if (
            details.get("type") == "mail"
            and details.get("message_id") == expected_message_id
            and details.get("trust_status") in ("verified", "verified_custodial")
            and verified
            and expected_wake_body in _content_text(entry.get("content"))
        ):
            wake = {"index": index, "entry": entry}
            break
    if wake is None:
        raise AssertionError("resident session has no matching verified aweb-channel wake message")
    if wake["index"] <= readiness["ready_settled_index"]:
        raise AssertionError("wake was not observed after resident readiness settled")

    reply_call = next(
        (
            call for call in tool_calls
            if re.search(r"(?:^|[;&|]\s*)aw\s+mail\s+reply(?:\s|$)", call["command"], re.MULTILINE)
            and expected_message_id in call["command"]
            and expected_reply_body in call["command"]
            and call["index"] > wake["index"]
        ),
        None,
    )
    if reply_call is None:
        raise AssertionError("resident session has no matching reply tool call")
    reply_result = tool_results.get(reply_call["id"])
    if reply_result is None or reply_result["message"].get("isError") is not False:
        raise AssertionError("resident session has no successful reply tool result")
    if reply_result["index"] <= reply_call["index"]:
        raise AssertionError("resident reply result did not follow its tool call")

    return {
        key: value for key, value in {
            **readiness,
            "ready_settled_index": None,
            "wake_message_id": expected_message_id,
            "wake_trust_status": wake["entry"]["details"]["trust_status"],
            "reply_tool_call_id": reply_call["id"],
            "reply_tool_result": _content_text(reply_result["message"].get("content")),
        }.items() if value is not None
    }


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

    readiness_parser = subparsers.add_parser("verify-resident-readiness")
    readiness_parser.add_argument("--session", required=True)
    readiness_parser.add_argument("--expected-address", required=True)
    readiness_parser.add_argument("--expected-stable-id", required=True)
    readiness_parser.add_argument("--expected-ready-subject", required=True)
    readiness_parser.add_argument("--expected-ready-body", required=True)
    readiness_parser.add_argument("--expected-session-cwd", required=True)
    readiness_parser.add_argument("--expected-provider", required=True)
    readiness_parser.add_argument("--expected-model", required=True)
    readiness_parser.add_argument("--output", required=True)

    session_parser = subparsers.add_parser("verify-resident-session")
    session_parser.add_argument("--session", required=True)
    session_parser.add_argument("--expected-address", required=True)
    session_parser.add_argument("--expected-stable-id", required=True)
    session_parser.add_argument("--expected-message-id", required=True)
    session_parser.add_argument("--expected-wake-body", required=True)
    session_parser.add_argument("--expected-reply-body", required=True)
    session_parser.add_argument("--expected-ready-subject", required=True)
    session_parser.add_argument("--expected-ready-body", required=True)
    session_parser.add_argument("--expected-session-cwd", required=True)
    session_parser.add_argument("--expected-provider", required=True)
    session_parser.add_argument("--expected-model", required=True)
    session_parser.add_argument("--output", required=True)

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
    elif args.command in ("verify-resident-readiness", "verify-resident-session"):
        common = {
            "expected_address": args.expected_address,
            "expected_stable_id": args.expected_stable_id,
            "expected_ready_subject": args.expected_ready_subject,
            "expected_ready_body": args.expected_ready_body,
            "expected_session_cwd": args.expected_session_cwd,
            "expected_provider": args.expected_provider,
            "expected_model": args.expected_model,
        }
        if args.command == "verify-resident-readiness":
            observation = assert_resident_readiness(args.session, **common)
            observation.pop("ready_settled_index", None)
        else:
            observation = assert_resident_session(
                args.session,
                expected_message_id=args.expected_message_id,
                expected_wake_body=args.expected_wake_body,
                expected_reply_body=args.expected_reply_body,
                **common,
            )
        Path(args.output).write_text(
            json.dumps(observation, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    else:  # pragma: no cover
        raise AssertionError(args.command)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"oas principal proof: {error}", file=sys.stderr)
        raise SystemExit(1)
