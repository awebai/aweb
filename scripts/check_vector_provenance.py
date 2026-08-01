#!/usr/bin/env python3
"""Enforce one public conformance-vector authority and explicit local fixtures."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path, PurePosixPath

PUBLIC_ROOT = PurePosixPath("docs/vectors")
EXPECTED_VECTOR_ROOTS = {
    PurePosixPath("cli/go/internal/conformance/vectors"),
    PUBLIC_ROOT,
    PurePosixPath("naapp/folio/tests/vectors"),
    PurePosixPath("naapp/library/tests/vectors"),
    PurePosixPath("test-vectors"),
}
APP_EMIT_COPIES = (
    PurePosixPath("cli/go/internal/conformance/vectors/app-emit-credential-v1.json"),
    PurePosixPath("naapp/folio/tests/vectors/app-emit-credential-v1.json"),
    PurePosixPath("naapp/library/tests/vectors/app-emit-credential-v1.json"),
)
MANAGED_PUBLIC_COPIES = {
    PurePosixPath("cli/go/internal/conformance/vectors/team-auth-envelope-v2.json"): (
        PUBLIC_ROOT / "team-auth-envelope-v2.json"
    ),
}
SERVER_CONSUMER = PurePosixPath("server/tests/test_identity_conformance_vectors.py")
GO_CONSUMER = PurePosixPath("cli/go/internal/conformance/conformance_test.go")
ROOT_CONSUMERS = {
    PurePosixPath("awid/tests/test_conformance_vectors.py"): (
        '_VECTORS_DIR = _ROOT / "docs" / "vectors"',
    ),
    PurePosixPath("awid/tests/test_did.py"): (
        '_IDENTITY_VECTOR = _ROOT / "docs" / "vectors" / "identity-log-v1.json"',
    ),
    SERVER_CONSUMER: (
        '_ROOT = Path(__file__).resolve().parents[2]',
        '_VECTORS_DIR = _ROOT / "docs" / "vectors"',
    ),
    GO_CONSUMER: (
        'filepath.Join(root, "docs", "vectors", name)',
    ),
    PurePosixPath("cli/go/awid/registry_register_test.go"): (
        'filepath.Join(root, "docs", "vectors", "identity-log-v1.json")',
    ),
    PurePosixPath("channel-core/test/registry.test.ts"): (
        'join(testDir, "..", "..", "docs", "vectors", "dns-txt-v1.json")',
        'join(testDir, "..", "..", "docs", "vectors", "identity-log-v1.json")',
    ),
    PurePosixPath("channel-core/test/log_rollback.test.ts"): (
        'join(testDir, "..", "..", "docs", "vectors", "identity-log-v1.json")',
    ),
}
REFERENCE_CONSUMERS = {
    PurePosixPath("naapp-lib/src/aweb_naapp/reference.py"): (
        "cli/go/internal/conformance/",
        "vectors/team-auth-envelope-v2.json",
        "<code>cli/go/internal/conformance/vectors/team-auth-envelope-v2.json</code>",
    ),
    PurePosixPath("naapp/library/tests/golden/reference.html"): (
        "https://github.com/awebai/aweb/blob/main/cli/go/internal/conformance/"
        "vectors/team-auth-envelope-v2.json",
        "<code>cli/go/internal/conformance/vectors/team-auth-envelope-v2.json</code>",
    ),
}
TEXT_SUFFIXES = {
    ".go",
    ".html",
    ".js",
    ".json",
    ".md",
    ".mjs",
    ".py",
    ".sh",
    ".ts",
    ".tsx",
    ".txt",
    ".yaml",
    ".yml",
}


def _tracked_files(root: Path) -> tuple[PurePosixPath, ...]:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        check=True,
        stdout=subprocess.PIPE,
    )
    tracked: list[PurePosixPath] = []
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        path = PurePosixPath(raw.decode("utf-8"))
        worktree_path = root / Path(*path.parts)
        if worktree_path.exists() or worktree_path.is_symlink():
            tracked.append(path)
    return tuple(tracked)


def _vector_root(path: PurePosixPath) -> PurePosixPath | None:
    parts = path.parts
    for index, part in enumerate(parts[:-1]):
        if part == "vectors" or part == "test-vectors" or part.endswith("-vectors"):
            return PurePosixPath(*parts[: index + 1])
    return None


def _reader(
    root: Path,
    overrides: Mapping[PurePosixPath, bytes] | None = None,
) -> Callable[[PurePosixPath], bytes]:
    override_bytes = overrides or {}

    def read(path: PurePosixPath) -> bytes:
        if path in override_bytes:
            return override_bytes[path]
        return (root / Path(*path.parts)).read_bytes()

    return read


def check(
    root: Path,
    tracked: Iterable[PurePosixPath] | None = None,
    overrides: Mapping[PurePosixPath, bytes] | None = None,
) -> list[str]:
    tracked_files = tuple(tracked if tracked is not None else _tracked_files(root))
    tracked_set = set(tracked_files)
    read = _reader(root, overrides)
    failures: list[str] = []

    vector_roots = {candidate for path in tracked_files if (candidate := _vector_root(path))}
    if vector_roots != EXPECTED_VECTOR_ROOTS:
        missing = sorted(str(path) for path in EXPECTED_VECTOR_ROOTS - vector_roots)
        extra = sorted(str(path) for path in vector_roots - EXPECTED_VECTOR_ROOTS)
        if missing:
            failures.append(f"missing classified vector roots: {', '.join(missing)}")
        if extra:
            failures.append(f"unclassified vector roots: {', '.join(extra)}")

    public_vectors = {
        path.name: path
        for path in tracked_files
        if path.parent == PUBLIC_ROOT and path.suffix == ".json"
    }
    if not public_vectors:
        failures.append("docs/vectors has no tracked JSON authority")

    for path in tracked_files:
        vector_root = _vector_root(path)
        if (
            vector_root is not None
            and vector_root != PUBLIC_ROOT
            and path.suffix == ".json"
            and path.name in public_vectors
            and path not in MANAGED_PUBLIC_COPIES
        ):
            failures.append(
                f"public vector mirror is forbidden: {path} duplicates {public_vectors[path.name]}"
            )

    for _name, path in sorted(public_vectors.items()):
        try:
            json.loads(read(path))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            failures.append(f"invalid public vector {path}: {exc}")

    readme_path = PUBLIC_ROOT / "README.md"
    if readme_path not in tracked_set:
        failures.append(f"missing public vector index: {readme_path}")
    else:
        readme = read(readme_path).decode("utf-8")
        for name in sorted(public_vectors):
            if f"`{name}`" not in readme:
                failures.append(f"public vector index omits {name}")

    for copy, authority in MANAGED_PUBLIC_COPIES.items():
        if copy not in tracked_set:
            failures.append(f"missing managed public-vector package copy: {copy}")
        elif authority not in tracked_set:
            failures.append(f"missing authority for managed package copy: {authority}")
        elif read(copy) != read(authority):
            failures.append(f"managed public-vector package copy differs from authority: {copy}")

    missing_app_emit = [str(path) for path in APP_EMIT_COPIES if path not in tracked_set]
    if missing_app_emit:
        failures.append(f"missing classified app-emit snapshots: {', '.join(missing_app_emit)}")
    else:
        source = read(APP_EMIT_COPIES[0])
        for path in APP_EMIT_COPIES[1:]:
            if read(path) != source:
                failures.append(f"app-emit snapshot differs from consumer authority: {path}")

    required_files = (*ROOT_CONSUMERS, *REFERENCE_CONSUMERS)
    for path in required_files:
        if path not in tracked_set:
            failures.append(f"missing declared vector consumer: {path}")

    for consumer, markers in ROOT_CONSUMERS.items():
        if consumer not in tracked_set:
            continue
        source = read(consumer).decode("utf-8")
        for marker in markers:
            if marker not in source:
                failures.append(
                    f"{consumer} does not resolve the repository-root authority: {marker}"
                )

    if GO_CONSUMER in tracked_set:
        source = read(GO_CONSUMER).decode("utf-8")
        for name in sorted(public_vectors):
            marker = f'vectorsFS.ReadFile("vectors/{name}")'
            managed = PurePosixPath("cli/go/internal/conformance/vectors") / name
            if marker in source and managed not in MANAGED_PUBLIC_COPIES:
                failures.append(f"{GO_CONSUMER} embeds public mirror {name} instead of reading root")
        managed_marker = 'vectorsFS.ReadFile("vectors/team-auth-envelope-v2.json")'
        if managed_marker not in source:
            failures.append(f"{GO_CONSUMER} does not exercise the managed team-auth package copy")

    for consumer, markers in REFERENCE_CONSUMERS.items():
        if consumer not in tracked_set:
            continue
        source = read(consumer).decode("utf-8")
        for marker in markers:
            if marker not in source:
                failures.append(f"{consumer} does not link the managed root-checked team-auth copy")

    stale_server_reference = "server/docs/" + "vectors/"
    root_mirror_reference = "cli/go/internal/conformance/" + "vectors/"
    for path in tracked_files:
        if path.suffix not in TEXT_SUFFIXES or path == PurePosixPath("scripts/check_vector_provenance.py"):
            continue
        try:
            text = read(path).decode("utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if stale_server_reference in text:
            failures.append(f"stale server vector reference: {path}")
        for name in public_vectors:
            if root_mirror_reference + name not in text:
                continue
            managed_reference = (
                name == "team-auth-envelope-v2.json"
                and path in REFERENCE_CONSUMERS
            )
            if not managed_reference:
                failures.append(f"reference bypasses root authority for {name}: {path}")

    return sorted(set(failures))


def _expect_mutation(
    label: str,
    root: Path,
    tracked: tuple[PurePosixPath, ...],
    *,
    add: PurePosixPath | None = None,
    override: tuple[PurePosixPath, bytes] | None = None,
    expected: str,
) -> None:
    mutated = tracked + ((add,) if add is not None else ())
    overrides = {override[0]: override[1]} if override is not None else None
    failures = check(root, mutated, overrides)
    if not any(expected in failure for failure in failures):
        raise AssertionError(f"{label} mutation did not fail as expected: {failures}")
    print(f"ok: {label}")


def self_test(root: Path) -> None:
    tracked = _tracked_files(root)
    baseline = check(root, tracked)
    if baseline:
        raise AssertionError(f"baseline provenance check is not green: {baseline}")

    _expect_mutation(
        "server hand copy",
        root,
        tracked,
        add=PurePosixPath("server/docs/vectors/identity-log-v1.json"),
        expected="public vector mirror is forbidden",
    )
    _expect_mutation(
        "Go embedded root mirror",
        root,
        tracked,
        add=PurePosixPath("cli/go/internal/conformance/vectors/stable-id-v1.json"),
        expected="public vector mirror is forbidden",
    )
    managed_copy = next(iter(MANAGED_PUBLIC_COPIES))
    _expect_mutation(
        "divergent managed package copy",
        root,
        tracked,
        override=(managed_copy, read_bytes(root, managed_copy) + b"\n"),
        expected="managed public-vector package copy differs",
    )
    snapshot = APP_EMIT_COPIES[1]
    _expect_mutation(
        "divergent classified snapshot",
        root,
        tracked,
        override=(snapshot, read_bytes(root, snapshot) + b"\n"),
        expected="app-emit snapshot differs",
    )
    _expect_mutation(
        "unclassified vector root",
        root,
        tracked,
        add=PurePosixPath("other/tests/vectors/private.json"),
        expected="unclassified vector roots",
    )
    reference_consumer = next(iter(REFERENCE_CONSUMERS))
    reference = read_bytes(root, reference_consumer).replace(
        b"cli/go/internal/conformance/",
        b"server/docs/",
    )
    _expect_mutation(
        "consumer path bypass",
        root,
        tracked,
        override=(reference_consumer, reference),
        expected="does not link the managed root-checked team-auth copy",
    )


def read_bytes(root: Path, path: PurePosixPath) -> bytes:
    return (root / Path(*path.parts)).read_bytes()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]

    if args.self_test:
        self_test(root)
        print("vector provenance mutation self-test passed")
        return 0

    failures = check(root)
    if failures:
        print("vector provenance check failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print("vector provenance check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
