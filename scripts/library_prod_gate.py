#!/usr/bin/env python3
"""Run the reviewed Library production compatibility gate from an isolated home.

The script prints only sanitized metadata and harness provenance. It never prints raw
responses, auth state, headers, or harness stderr.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unicodedata
from pathlib import Path
from typing import Any

RUNTIMES = ("claude-code", "pi")
REQUIRED_PUBLIC_URL = "https://library.aweb.ai"
REQUIRED_AW_PATH = Path("/opt/homebrew/bin/aw")
REQUIRED_AW_SHA256 = "e546aa12294e61c95d02cd0a69a613b115ea72cc43f7716e193dc4ef342d6815"
REQUIRED_AW_VERSION_OUTPUT = "aw 1.34.0\n  commit: 82d7ca0\n  built:  2026-07-27T20:23:38Z\n"
REQUIRED_CLAUDE_PATH = Path("/opt/homebrew/bin/claude")
REQUIRED_PI_PATH = Path("/opt/homebrew/bin/pi")
IGNORED_AUTH_FILES = (
    "interaction-log.jsonl",
    "channel-delivered-ids.json",
    "chat-delivered-ids.json",
    "chat-delivered-ids.json.lock",
)
PROMPT = (
    "From the project instructions automatically loaded at startup, print only "
    "the first Markdown title and the profile provenance line immediately below it."
)


class GateError(RuntimeError):
    pass


def validate_relative_paths(paths: list[str]) -> None:
    for value in paths:
        parts = value.split("/")
        invalid = (
            not value
            or value.strip() != value
            or any(unicodedata.category(char) == "Cc" for char in value)
            or "\\" in value
            or value.startswith("/")
            or "://" in value
            or value.startswith("git@")
            or "//" in value
            or value.endswith("/")
            or any(part in {"", ".", ".."} for part in parts)
        )
        if invalid:
            raise GateError("materialize response contains a noncanonical or unsafe managed path")


def ref_from_payload(payload: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    if not isinstance(payload, dict):
        raise GateError("materialize response is not a JSON object")
    files = payload.get("home_files")
    if not isinstance(files, list) or not files:
        raise GateError("materialize response has no home_files")
    paths = [str(entry.get("path") or "") for entry in files]
    validate_relative_paths(paths)
    try:
        entry = next(item for item in files if item.get("path") == ".aw/profile/ref.json")
        ref = json.loads(entry["content_utf8"])
    except (StopIteration, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise GateError("materialize response has no valid ref.json") from exc
    return ref, paths


def validate_profile_pin(
    ref: dict[str, Any], *, expected_version: str, expected_digest: str
) -> None:
    if ref.get("profile_ref") != "developer":
        raise GateError("profile_ref is not developer")
    if ref.get("profile_version") != expected_version:
        raise GateError("profile_version does not match the approved gate pin")
    if ref.get("profile_digest") != expected_digest:
        raise GateError("profile_digest does not match the approved gate pin")


def validate_candidate_payload(
    payload: dict[str, Any],
    runtime: str,
    *,
    expected_version: str,
    expected_digest: str,
) -> dict[str, Any]:
    ref, paths = ref_from_payload(payload)
    managed = ref.get("managed_set")
    validate_profile_pin(ref, expected_version=expected_version, expected_digest=expected_digest)
    if ref.get("runtime_kind") != runtime:
        raise GateError(f"candidate runtime_kind does not match {runtime}")
    if not isinstance(managed, list) or not managed or not all(isinstance(p, str) for p in managed):
        raise GateError("candidate managed_set is missing")
    validate_relative_paths(managed)
    if len(paths) != len(set(paths)) or len(managed) != len(set(managed)):
        raise GateError("candidate response contains duplicate managed paths")
    if managed != paths:
        mismatch = next(
            (
                index
                for index, pair in enumerate(zip(managed, paths, strict=False))
                if pair[0] != pair[1]
            ),
            min(len(managed), len(paths)),
        )
        raise GateError(f"candidate managed_set is not positionally identical at index {mismatch}")
    return sanitized_summary("raw-candidate", runtime, ref, len(managed))


def validate_recovery_payload(
    payload: dict[str, Any],
    runtime: str,
    *,
    expected_version: str,
    expected_digest: str,
) -> dict[str, Any]:
    ref, _ = ref_from_payload(payload)
    validate_profile_pin(ref, expected_version=expected_version, expected_digest=expected_digest)
    if "runtime_kind" in ref or "managed_set" in ref:
        raise GateError("rollback fingerprint is not the known pre-fix behavior")
    return sanitized_summary("raw-recovery", runtime, ref, 0)


def validate_materialized_ref(
    path: Path,
    runtime: str,
    *,
    expected_version: str,
    expected_digest: str,
) -> dict[str, Any]:
    try:
        ref = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GateError(f"strict client did not write a valid ref.json for {runtime}") from exc
    managed = ref.get("managed_set")
    validate_profile_pin(ref, expected_version=expected_version, expected_digest=expected_digest)
    if ref.get("runtime_kind") != runtime:
        raise GateError(f"strict client ref.json mismatch for {runtime}")
    if (
        not isinstance(managed, list)
        or not managed
        or not all(isinstance(p, str) for p in managed)
        or len(managed) != len(set(managed))
    ):
        raise GateError(f"strict client managed_set invalid for {runtime}")
    validate_relative_paths(managed)
    verify_managed_paths(path.parents[2], managed, runtime)
    return sanitized_summary("released-strict-client", runtime, ref, len(managed))


def verify_managed_paths(home: Path, managed: list[str], runtime: str) -> None:
    home_resolved = home.resolve(strict=True)
    for relative in managed:
        requested = home / relative
        try:
            resolved = requested.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise GateError(
                f"strict client managed path requested at {requested} is missing or broken "
                f"for {runtime}"
            ) from exc
        try:
            resolved.relative_to(home_resolved)
        except ValueError as exc:
            raise GateError(
                f"strict client managed path requested at {requested} resolves outside "
                f"generated home {home_resolved}: {resolved}"
            ) from exc


def sanitized_summary(gate: str, runtime: str, ref: dict[str, Any], count: int) -> dict[str, Any]:
    return {
        "gate": gate,
        "runtime_kind": runtime,
        "profile_ref": ref.get("profile_ref"),
        "profile_version": ref.get("profile_version"),
        "source_blueprint_ref": ref.get("source_blueprint_ref"),
        "source_blueprint_version": ref.get("source_blueprint_version"),
        "managed_set_count": count,
    }


def verify_file_artifact(
    path: Path, *, expected_path: Path, expected_sha256: str, label: str
) -> None:
    if path != expected_path:
        raise GateError(f"{label} path must be exactly {expected_path}")
    try:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise GateError(f"failed to hash {label}") from exc
    if digest != expected_sha256:
        raise GateError(f"{label} SHA-256 does not match the reviewed artifact")


def verify_released_aw(aw_bin: Path) -> None:
    verify_file_artifact(
        aw_bin,
        expected_path=REQUIRED_AW_PATH,
        expected_sha256=REQUIRED_AW_SHA256,
        label="released aw binary",
    )
    try:
        completed = subprocess.run(
            [str(aw_bin), "version"],
            check=True,
            text=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise GateError("failed to identify the released aw binary") from exc
    if completed.stdout != REQUIRED_AW_VERSION_OUTPUT:
        raise GateError(
            "released aw version/commit/build metadata does not match the reviewed artifact"
        )


def run_checked(command: list[str], *, cwd: Path, stdout: Path, stderr: Path, label: str) -> None:
    with stdout.open("wb") as out, stderr.open("wb") as err:
        completed = subprocess.run(command, cwd=cwd, stdout=out, stderr=err, check=False)
    if completed.returncode != 0:
        raise GateError(
            f"{label} exited {completed.returncode}; stderr was captured without printing"
        )


def raw_materialize(
    aw_bin: Path, source_home: Path, public_url: str, runtime: str, root: Path
) -> dict[str, Any]:
    request = root / f"raw-{runtime}.request.json"
    response = root / f"raw-{runtime}.response.json"
    stderr = root / f"raw-{runtime}.stderr"
    request.write_text(
        json.dumps({"profile_ref": "developer", "runtime_kind": runtime, "target": "local"}) + "\n",
        encoding="utf-8",
    )
    run_checked(
        [
            str(aw_bin),
            "id",
            "request",
            "POST",
            f"{public_url}/v1/materialize",
            "--team-auth",
            "--body-file",
            str(request),
            "--raw",
        ],
        cwd=source_home,
        stdout=response,
        stderr=stderr,
        label=f"raw materialize {runtime}",
    )
    try:
        return json.loads(response.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise GateError(f"raw materialize {runtime} returned invalid JSON") from exc


def clone_auth_home(source_home: Path, destination: Path) -> None:
    source_aw = source_home / ".aw"
    if not source_aw.is_dir():
        raise GateError("source home has no .aw directory")
    shutil.copytree(source_aw, destination / ".aw")
    shutil.rmtree(destination / ".aw" / "profile", ignore_errors=True)
    for relative in IGNORED_AUTH_FILES:
        (destination / ".aw" / relative).unlink(missing_ok=True)


def strict_materialize(
    aw_bin: Path,
    home: Path,
    runtime: str,
    root: Path,
    *,
    expected_version: str,
    expected_digest: str,
) -> dict[str, Any]:
    run_checked(
        [
            str(aw_bin),
            "library",
            "materialize",
            "--profile_ref",
            "developer",
            "--runtime_kind",
            runtime,
            "--target",
            "local",
        ],
        cwd=home,
        stdout=root / f"strict-{runtime}.stdout",
        stderr=root / f"strict-{runtime}.stderr",
        label=f"released strict client {runtime}",
    )
    return validate_materialized_ref(
        home / ".aw" / "profile" / "ref.json",
        runtime,
        expected_version=expected_version,
        expected_digest=expected_digest,
    )


def require_recovery_rejection(
    aw_bin: Path, home: Path, runtime: str, root: Path
) -> dict[str, Any]:
    stdout = root / f"recovery-strict-{runtime}.stdout"
    stderr = root / f"recovery-strict-{runtime}.stderr"
    with stdout.open("wb") as out, stderr.open("wb") as err:
        completed = subprocess.run(
            [
                str(aw_bin),
                "library",
                "materialize",
                "--profile_ref",
                "developer",
                "--runtime_kind",
                runtime,
                "--target",
                "local",
            ],
            cwd=home,
            stdout=out,
            stderr=err,
            check=False,
        )
    expected_error = (
        f'library materialize response runtime_kind "{runtime}" does not match ref.json ""'
    )
    captured_error = stderr.read_text(encoding="utf-8", errors="replace")
    if completed.returncode != 1 or expected_error not in captured_error:
        raise GateError(
            f"rollback strict client did not produce the expected schema rejection for {runtime}"
        )
    return {
        "gate": "released-strict-client-recovery",
        "runtime_kind": runtime,
        "exit": completed.returncode,
    }


def expected_provenance(ref_path: Path) -> str:
    ref = json.loads(ref_path.read_text(encoding="utf-8"))
    return (
        f"> Profile {ref['profile_ref']} v{ref['profile_version']} · blueprint "
        f"{ref['source_blueprint_ref']} v{ref['source_blueprint_version']}"
    )


def run_harness(
    home: Path, runtime: str, root: Path, claude_bin: Path, pi_bin: Path
) -> dict[str, Any]:
    if runtime == "claude-code":
        command = [
            str(claude_bin),
            "--print",
            "--no-session-persistence",
            "--tools",
            "",
            "--model",
            "haiku",
            PROMPT,
        ]
    else:
        command = [
            str(pi_bin),
            "--provider",
            "openai-codex",
            "--model",
            "gpt-5.6-sol",
            "--thinking",
            "off",
            "--print",
            "--no-session",
            "--approve",
            "--no-tools",
            "--no-extensions",
            PROMPT,
        ]
    stdout = root / f"harness-{runtime}.stdout"
    stderr = root / f"harness-{runtime}.stderr"
    run_checked(command, cwd=home, stdout=stdout, stderr=stderr, label=f"{runtime} harness")
    lines = [
        line.strip() for line in stdout.read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    provenance = expected_provenance(home / ".aw" / "profile" / "ref.json")
    if "# Developer" not in lines or provenance not in lines:
        raise GateError(f"{runtime} harness did not load expected project instructions")
    return {
        "gate": "real-harness",
        "runtime_kind": runtime,
        "exit": 0,
        "title": "# Developer",
        "provenance": provenance,
    }


def run_candidate(args: argparse.Namespace, root: Path) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    homes: dict[str, Path] = {}
    for runtime in RUNTIMES:
        payload = raw_materialize(args.aw_bin, args.source_home, args.public_url, runtime, root)
        summaries.append(
            validate_candidate_payload(
                payload,
                runtime,
                expected_version=args.expected_profile_version,
                expected_digest=args.expected_profile_digest,
            )
        )
    for runtime in RUNTIMES:
        home = root / f"home-{runtime}"
        home.mkdir()
        clone_auth_home(args.source_home, home)
        summaries.append(
            strict_materialize(
                args.aw_bin,
                home,
                runtime,
                root,
                expected_version=args.expected_profile_version,
                expected_digest=args.expected_profile_digest,
            )
        )
        homes[runtime] = home
    for runtime in RUNTIMES:
        summaries.append(run_harness(homes[runtime], runtime, root, args.claude_bin, args.pi_bin))
    return summaries


def run_recovery(args: argparse.Namespace, root: Path) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for runtime in RUNTIMES:
        payload = raw_materialize(args.aw_bin, args.source_home, args.public_url, runtime, root)
        summaries.append(
            validate_recovery_payload(
                payload,
                runtime,
                expected_version=args.expected_profile_version,
                expected_digest=args.expected_profile_digest,
            )
        )
        home = root / f"home-{runtime}"
        home.mkdir()
        clone_auth_home(args.source_home, home)
        summaries.append(require_recovery_rejection(args.aw_bin, home, runtime, root))
    return summaries


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode", choices=("candidate", "legacy-aasb"))
    source_home = os.environ.get("AW_SOURCE_HOME")
    p.add_argument("--source-home", type=Path, default=Path(source_home) if source_home else None)
    p.add_argument("--public-url", default=REQUIRED_PUBLIC_URL)
    p.add_argument(
        "--expected-profile-version",
        default=os.environ.get("EXPECTED_PROFILE_VERSION", ""),
    )
    p.add_argument(
        "--expected-profile-digest",
        default=os.environ.get("EXPECTED_PROFILE_DIGEST", ""),
    )
    p.add_argument("--aw-bin", type=Path, default=REQUIRED_AW_PATH)
    p.add_argument("--claude-bin", type=Path, default=REQUIRED_CLAUDE_PATH)
    p.add_argument("--pi-bin", type=Path, default=REQUIRED_PI_PATH)
    return p


def main() -> int:
    args = parser().parse_args()
    try:
        if args.source_home is None or not args.source_home.is_absolute():
            raise GateError("AW_SOURCE_HOME/--source-home must be an absolute path")
        if args.public_url != REQUIRED_PUBLIC_URL:
            raise GateError(f"production public URL must be exactly {REQUIRED_PUBLIC_URL}")
        if not args.expected_profile_version:
            raise GateError("EXPECTED_PROFILE_VERSION/--expected-profile-version is required")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", args.expected_profile_digest):
            raise GateError(
                "EXPECTED_PROFILE_DIGEST/--expected-profile-digest must be sha256-pinned"
            )
        verify_released_aw(args.aw_bin)
        with tempfile.TemporaryDirectory(prefix="library-prod-gate-") as temporary:
            root = Path(temporary)
            summaries = (
                run_candidate(args, root) if args.mode == "candidate" else run_recovery(args, root)
            )
        for summary in summaries:
            print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
        print(f"PASS: Library production {args.mode} gate")
        return 0
    except GateError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
