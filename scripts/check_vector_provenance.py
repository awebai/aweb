"""Enforce one public conformance-vector authority and explicit local fixtures."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

PUBLIC_ROOT = PurePosixPath("docs/vectors")
EXPECTED_VECTOR_ROOTS = {
    PurePosixPath("cli/go/internal/conformance/vectors"),
    PUBLIC_ROOT,
    PurePosixPath("naapp/folio/tests/vectors"),
    PurePosixPath("naapp/library/tests/vectors"),
    PurePosixPath("naapp/library/test-vectors"),
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


@dataclass(frozen=True)
class ConsumerSpec:
    vector_names: frozenset[str]
    root_markers: tuple[str, ...]


def _consumer(names: str | Iterable[str], *root_markers: str) -> ConsumerSpec:
    if isinstance(names, str):
        names = (names,)
    return ConsumerSpec(frozenset(names), root_markers)


SERVER_CONSUMER = PurePosixPath("server/tests/test_identity_conformance_vectors.py")
GO_CONSUMER = PurePosixPath("cli/go/internal/conformance/conformance_test.go")
ROOT_CONSUMERS = {
    PurePosixPath("awid/tests/test_a2a_publication_route.py"): _consumer(
        "a2a-awid-publication-v1.json",
        '_ROOT / "docs" / "vectors" / "a2a-awid-publication-v1.json"',
    ),
    PurePosixPath("awid/tests/test_atomic_claim.py"): _consumer(
        "atomic-address-claim-v1.json",
        'Path(__file__).parents[2] / "docs" / "vectors" / "atomic-address-claim-v1.json"',
    ),
    PurePosixPath("awid/tests/test_atomic_claim_route.py"): _consumer(
        "atomic-address-claim-conflict-codes-v1.json",
        '_ROOT / "docs" / "vectors" / "atomic-address-claim-conflict-codes-v1.json"',
    ),
    PurePosixPath("awid/tests/test_conformance_vectors.py"): _consumer(
        {
            "dns-txt-v1.json",
            "identity-log-v1.json",
            "message-signing-v1.json",
            "rotation-announcements-v1.json",
            "stable-id-v1.json",
        },
        '_VECTORS_DIR = _ROOT / "docs" / "vectors"',
    ),
    PurePosixPath("awid/tests/test_delegation.py"): _consumer(
        "namespace-delegation-v1.json",
        'VECTOR_PATH = Path(__file__).parents[2] / "docs" / "vectors" / "namespace-delegation-v1.json"',
    ),
    PurePosixPath("awid/tests/test_registry_migration_receipts.py"): _consumer(
        "registry-migration-receipts-v1.json",
        'VECTOR = Path(__file__).parents[2] / "docs" / "vectors" / "registry-migration-receipts-v1.json"',
    ),
    PurePosixPath("awid/tests/test_did.py"): _consumer(
        "identity-log-v1.json",
        '_IDENTITY_VECTOR = _ROOT / "docs" / "vectors" / "identity-log-v1.json"',
    ),
    PurePosixPath("awid/tests/test_federation_authority_vectors.py"): _consumer(
        {
            "federation-authority-state-v1.json",
            "federation-discovery-v1.json",
            "federation-origin-ip-v1.json",
            "identity-log-negative-v1.json",
            "identity-log-raw-wire-v1.json",
            "identity-log-v1.json",
        },
        '_VECTORS = _ROOT / "docs" / "vectors"',
    ),
    PurePosixPath("awid/tests/test_external_authority.py"): _consumer(
        {
            "federation-discovery-v1.json",
            "federation-origin-ip-v1.json",
        },
        '_VECTORS = _ROOT / "docs" / "vectors"',
    ),
    PurePosixPath("awid/tests/test_external_registry.py"): _consumer(
        "identity-log-v1.json",
        '_VECTORS = _ROOT / "docs" / "vectors"',
    ),
    PurePosixPath("awid/tests/test_identity_log_verify.py"): _consumer(
        {
            "identity-log-negative-v1.json",
            "identity-log-raw-wire-v1.json",
            "identity-log-v1.json",
        },
        '_VECTORS = _ROOT / "docs" / "vectors"',
    ),
    PurePosixPath("server/tests/test_e2ee_crypto_helpers.py"): _consumer(
        "e2ee-v2-cross-language.json",
        '_CROSS_LANGUAGE_VECTOR = _ROOT / "docs" / "vectors" / "e2ee-v2-cross-language.json"',
    ),
    SERVER_CONSUMER: _consumer(
        {
            "dns-txt-v1.json",
            "identity-log-v1.json",
            "message-signing-v1.json",
            "rotation-announcements-v1.json",
            "stable-id-v1.json",
        },
        "_ROOT = Path(__file__).resolve().parents[2]",
        '_VECTORS_DIR = _ROOT / "docs" / "vectors"',
    ),
    PurePosixPath("server/tests/test_federation_authority_core.py"): _consumer(
        "federation-authority-state-v1.json",
        '_ROOT / "docs" / "vectors" / "federation-authority-state-v1.json"',
    ),
    PurePosixPath("server/tests/test_federation_authority_schema.py"): _consumer(
        "federation-authority-state-v1.json",
        '_ROOT / "docs" / "vectors" / "federation-authority-state-v1.json"',
    ),
    PurePosixPath("server/tests/test_federation_preactivation_harness.py"): _consumer(
        {
            "e2ee-v2-cross-language.json",
            "federation-authority-state-v1.json",
            "federation-discovery-v1.json",
            "federation-origin-ip-v1.json",
            "identity-log-v1.json",
            "message-signing-v1.json",
        },
        '_ROOT / item["path"]',
    ),
    PurePosixPath("scripts/check_federation_harness.py"): _consumer(
        {
            "e2ee-v2-cross-language.json",
            "federation-authority-state-v1.json",
            "federation-discovery-v1.json",
            "federation-origin-ip-v1.json",
            "identity-log-v1.json",
            "message-signing-v1.json",
        },
        "body = _read(root, path, overrides)",
    ),
    PurePosixPath("server/tests/test_team_auth_envelope.py"): _consumer(
        "team-auth-envelope-v2.json",
        'root / "docs" / "vectors" / "team-auth-envelope-v2.json"',
    ),
    PurePosixPath("naapp/folio/tests/test_auth_v2_envelope.py"): _consumer(
        "team-auth-envelope-v2.json",
        'aweb_path("docs", "vectors", "team-auth-envelope-v2.json")',
    ),
    PurePosixPath("cli/go/a2a/card_test.go"): _consumer(
        "a2a-v1.json",
        'filepath.Join(root, "docs", "vectors", "a2a-v1.json")',
    ),
    PurePosixPath("cli/go/a2agw/envelope_vector_test.go"): _consumer(
        "a2a-bridge-envelope-v0.json",
        'filepath.Join(root, "docs", "vectors", "a2a-bridge-envelope-v0.json")',
    ),
    PurePosixPath("cli/go/a2agw/gateway_rpc_test.go"): _consumer(
        "a2a-v1.json",
        'os.ReadFile("../../../docs/vectors/a2a-v1.json")',
    ),
    PurePosixPath("cli/go/awid/a2a_publication_test.go"): _consumer(
        "a2a-awid-publication-v1.json",
        'readDocsVector(t, "a2a-awid-publication-v1.json")',
    ),
    PurePosixPath("cli/go/awid/atomic_address_claim_test.go"): _consumer(
        {
            "atomic-address-claim-conflict-codes-v1.json",
            "atomic-address-claim-v1.json",
        },
        'filepath.Join("..", "..", "..", "docs", "vectors", name)',
    ),
    PurePosixPath("cli/go/awid/delegation_test.go"): _consumer(
        "namespace-delegation-v1.json",
        'os.ReadFile("../../../docs/vectors/namespace-delegation-v1.json")',
    ),
    PurePosixPath("cli/go/awid/e2ee_cross_language_test.go"): _consumer(
        "e2ee-v2-cross-language.json",
        'filepath.Join("..", "..", "..", "docs", "vectors", "e2ee-v2-cross-language.json")',
    ),
    PurePosixPath("cli/go/awid/registry_register_test.go"): _consumer(
        "identity-log-v1.json",
        'filepath.Join(root, "docs", "vectors", "identity-log-v1.json")',
    ),
    PurePosixPath("cli/go/awid/federation_authority_test.go"): _consumer(
        {
            "federation-authority-state-v1.json",
            "federation-discovery-v1.json",
            "federation-origin-ip-v1.json",
            "identity-log-v1.json",
        },
        'filepath.Join("..", "..", "..", "docs", "vectors", name)',
    ),
    PurePosixPath("cli/go/awid/federation_external_registry_test.go"): _consumer(
        "identity-log-v1.json",
        'loadFederationVector(t, "identity-log-v1.json"',
    ),
    GO_CONSUMER: _consumer(
        {
            "a2a-awid-publication-v1.json",
            "a2a-v1.json",
            "identity-log-v1.json",
            "message-signing-v1.json",
            "rotation-announcements-v1.json",
            "stable-id-v1.json",
            "team-auth-envelope-v2.json",
        },
        'filepath.Join(root, "docs", "vectors", name)',
    ),
    PurePosixPath(
        "cli/go/internal/conformance/federation_authority_vectors_test.go"
    ): _consumer(
        {
            "federation-authority-state-v1.json",
            "federation-discovery-v1.json",
            "federation-origin-ip-v1.json",
            "identity-log-negative-v1.json",
            "identity-log-raw-wire-v1.json",
            "identity-log-v1.json",
        },
        "data := readRootVector(t, name)",
    ),
    PurePosixPath(
        "cli/go/internal/conformance/identity_log_negative_test.go"
    ): _consumer(
        "identity-log-negative-v1.json",
        'readRootVector(t, "identity-log-negative-v1.json")',
    ),
    PurePosixPath(
        "cli/go/internal/conformance/identity_log_raw_wire_test.go"
    ): _consumer(
        "identity-log-raw-wire-v1.json",
        'readRootVector(t, "identity-log-raw-wire-v1.json")',
    ),
    PurePosixPath("cli/go/internal/conformance/pin_store_raw_wire_test.go"): _consumer(
        "pin-store-raw-wire-v1.json",
        'readRootVector(t, "pin-store-raw-wire-v1.json")',
    ),
    PurePosixPath("channel-core/test/log_rollback.test.ts"): _consumer(
        "identity-log-v1.json",
        'join(testDir, "..", "..", "docs", "vectors", "identity-log-v1.json")',
    ),
    PurePosixPath("channel-core/test/pin_store_raw_wire.test.ts"): _consumer(
        "pin-store-raw-wire-v1.json",
        'join(testDir, "..", "..", "docs", "vectors", "pin-store-raw-wire-v1.json")',
    ),
    PurePosixPath("channel-core/test/registry.test.ts"): _consumer(
        {
            "dns-txt-v1.json",
            "identity-log-negative-v1.json",
            "identity-log-raw-wire-v1.json",
            "identity-log-v1.json",
        },
        'join(testDir, "..", "..", "docs", "vectors", "dns-txt-v1.json")',
        'join(testDir, "..", "..", "docs", "vectors", "identity-log-v1.json")',
        'join(testDir, "..", "..", "docs", "vectors", "identity-log-raw-wire-v1.json")',
        'join(testDir, "..", "..", "docs", "vectors", "identity-log-negative-v1.json")',
    ),
    PurePosixPath("scripts/check-extension-docs.py"): _consumer(
        {
            "federation-authority-state-v1.json",
            "mutation-hook-call-sites-v1.json",
        },
        'HOOK_INVENTORY = "vectors/mutation-hook-call-sites-v1.json"',
        "inventory_path = docs / HOOK_INVENTORY",
        'vector_path = docs / "vectors/federation-authority-state-v1.json"',
    ),
    PurePosixPath("scripts/generate_federation_error_reference.py"): _consumer(
        "federation-authority-state-v1.json",
        'DEFAULT_VECTOR = ROOT / "docs/vectors/federation-authority-state-v1.json"',
    ),
    PurePosixPath("scripts/test_generate_federation_error_reference.py"): _consumer(
        "federation-authority-state-v1.json",
        'VECTOR = ROOT / "docs/vectors/federation-authority-state-v1.json"',
    ),
}
PACKAGE_GUARDS = {
    PurePosixPath("Makefile"): (
        "test-sot-source-inventories test-vector-provenance test-federation-error-reference test-federation-authority-mutations",
        "test-vector-provenance:",
        "python3 scripts/check_vector_provenance.py --self-test",
        "test-federation-error-reference:",
        "python3 scripts/generate_federation_error_reference.py --check",
    ),
    PurePosixPath("server/tests/test_package_data.py"): (
        '[uv, "build", "--out-dir", str(tmp_path)]',
        'tmp_path.glob("aweb-*.whl")',
        'tmp_path.glob("aweb-*.tar.gz")',
        'assert not any("/docs/vectors/" in name',
    ),
    PurePosixPath("naapp/folio/tests/aweb_layout.py"): (
        '_AWEB_MARKER = ("server", "pyproject.toml")',
        "candidate = root.joinpath(*parts)",
    ),
}
NON_CONSUMING_CODE_REFERENCES = {
    PurePosixPath("naapp/folio/tests/test_surfaces.py"): (
        'decoy / "docs" / "vectors" / "team-auth-envelope-v2.json"',
        "assert not is_aweb_root(decoy)",
    ),
    PurePosixPath("naapp/library/tests/test_surfaces.py"): (
        "https://github.com/awebai/aweb/blob/main/cli/go/internal/conformance/",
        'vectors/team-auth-envelope-v2.json"',
    ),
}
CODE_SUFFIXES = {".go", ".js", ".mjs", ".py", ".ts", ".tsx"}
REFERENCE_CONSUMERS = {
    PurePosixPath("naapp-lib/src/aweb_naapp/reference.py"): (
        "cli/go/internal/conformance/",
        "vectors/team-auth-envelope-v2.json",
        "<code>cli/go/internal/conformance/vectors/team-auth-envelope-v2.json</code>",
    ),
    PurePosixPath("naapp/library/tests/golden/reference.html"): (
        (
            "https://github.com/awebai/aweb/blob/main/cli/go/internal/conformance/"
            "vectors/team-auth-envelope-v2.json"
        ),
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

    vector_roots = {
        candidate for path in tracked_files if (candidate := _vector_root(path))
    }
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

    public_payloads: dict[str, object] = {}
    for name, path in sorted(public_vectors.items()):
        try:
            public_payloads[name] = json.loads(read(path))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            failures.append(f"invalid public vector {path}: {exc}")

    for path in tracked_files:
        if (
            path.parent == PUBLIC_ROOT
            or path.suffix != ".json"
            or path in MANAGED_PUBLIC_COPIES
        ):
            continue
        if path.name in public_vectors:
            failures.append(
                f"public vector mirror is forbidden: {path} duplicates {public_vectors[path.name]}"
            )
            continue
        try:
            payload = json.loads(read(path))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        for name, public_payload in public_payloads.items():
            if payload == public_payload:
                failures.append(
                    f"public vector content mirror is forbidden: {path} duplicates "
                    f"{public_vectors[name]}"
                )
                break

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
            failures.append(
                f"managed public-vector package copy differs from authority: {copy}"
            )

    missing_app_emit = [
        str(path) for path in APP_EMIT_COPIES if path not in tracked_set
    ]
    if missing_app_emit:
        failures.append(
            f"missing classified app-emit snapshots: {', '.join(missing_app_emit)}"
        )
    else:
        source = read(APP_EMIT_COPIES[0])
        for path in APP_EMIT_COPIES[1:]:
            if read(path) != source:
                failures.append(
                    f"app-emit snapshot differs from consumer authority: {path}"
                )

    required_files = (
        *ROOT_CONSUMERS,
        *REFERENCE_CONSUMERS,
        *PACKAGE_GUARDS,
        *NON_CONSUMING_CODE_REFERENCES,
    )
    for path in required_files:
        if path not in tracked_set:
            failures.append(f"missing declared vector consumer: {path}")

    for consumer, spec in ROOT_CONSUMERS.items():
        if consumer not in tracked_set:
            continue
        source = read(consumer).decode("utf-8")
        referenced_names = frozenset(name for name in public_vectors if name in source)
        missing_names = sorted(spec.vector_names - referenced_names)
        unexpected_names = sorted(referenced_names - spec.vector_names)
        if missing_names:
            failures.append(
                f"{consumer} omits inventoried public vector references: {', '.join(missing_names)}"
            )
        if unexpected_names:
            failures.append(
                f"{consumer} has unclassified public vector references: {', '.join(unexpected_names)}"
            )
        for marker in spec.root_markers:
            if marker not in source:
                failures.append(
                    f"{consumer} does not resolve the repository-root authority: {marker}"
                )

    classified_code_references = (
        set(ROOT_CONSUMERS)
        | set(REFERENCE_CONSUMERS)
        | set(NON_CONSUMING_CODE_REFERENCES)
        | {PurePosixPath("scripts/check_vector_provenance.py")}
    )
    for path in tracked_files:
        if path.suffix not in CODE_SUFFIXES or path in classified_code_references:
            continue
        try:
            source = read(path).decode("utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        referenced_names = sorted(name for name in public_vectors if name in source)
        if referenced_names:
            failures.append(
                f"unclassified public-vector code reference in {path}: "
                f"{', '.join(referenced_names)}"
            )

    for reference_guard, markers in NON_CONSUMING_CODE_REFERENCES.items():
        if reference_guard not in tracked_set:
            continue
        source = read(reference_guard).decode("utf-8")
        for marker in markers:
            if marker not in source:
                failures.append(
                    f"{reference_guard} omits classified vector reference guard: {marker}"
                )

    for package_guard, markers in PACKAGE_GUARDS.items():
        if package_guard not in tracked_set:
            continue
        source = read(package_guard).decode("utf-8")
        for marker in markers:
            if marker not in source:
                failures.append(
                    f"{package_guard} omits vector package/build guard: {marker}"
                )

    if GO_CONSUMER in tracked_set:
        source = read(GO_CONSUMER).decode("utf-8")
        for name in sorted(public_vectors):
            marker = f'vectorsFS.ReadFile("vectors/{name}")'
            managed = PurePosixPath("cli/go/internal/conformance/vectors") / name
            if marker in source and managed not in MANAGED_PUBLIC_COPIES:
                failures.append(
                    f"{GO_CONSUMER} embeds public mirror {name} instead of reading root"
                )
        managed_marker = 'vectorsFS.ReadFile("vectors/team-auth-envelope-v2.json")'
        if managed_marker not in source:
            failures.append(
                f"{GO_CONSUMER} does not exercise the managed team-auth package copy"
            )

    for consumer, markers in REFERENCE_CONSUMERS.items():
        if consumer not in tracked_set:
            continue
        source = read(consumer).decode("utf-8")
        for marker in markers:
            if marker not in source:
                failures.append(
                    f"{consumer} does not link the managed root-checked team-auth copy"
                )

    stale_server_reference = "server/docs/" + "vectors/"
    root_mirror_reference = "cli/go/internal/conformance/" + "vectors/"
    for path in tracked_files:
        if path.suffix not in TEXT_SUFFIXES or path == PurePosixPath(
            "scripts/check_vector_provenance.py"
        ):
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
                name == "team-auth-envelope-v2.json" and path in REFERENCE_CONSUMERS
            )
            if not managed_reference:
                failures.append(f"reference bypasses root authority for {name}: {path}")

    return sorted(set(failures))


def _expect_mutation(
    label: str,
    root: Path,
    tracked: tuple[PurePosixPath, ...],
    *,
    add: tuple[PurePosixPath, ...] = (),
    overrides: Mapping[PurePosixPath, bytes] | None = None,
    expected: str,
) -> None:
    mutated = tracked + add
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
        add=(PurePosixPath("server/docs/vectors/identity-log-v1.json"),),
        expected="public vector mirror is forbidden",
    )
    _expect_mutation(
        "Go embedded root mirror",
        root,
        tracked,
        add=(PurePosixPath("cli/go/internal/conformance/vectors/stable-id-v1.json"),),
        expected="public vector mirror is forbidden",
    )
    managed_copy = next(iter(MANAGED_PUBLIC_COPIES))
    _expect_mutation(
        "divergent managed package copy",
        root,
        tracked,
        overrides={managed_copy: read_bytes(root, managed_copy) + b"\n"},
        expected="managed public-vector package copy differs",
    )
    snapshot = APP_EMIT_COPIES[1]
    _expect_mutation(
        "divergent classified snapshot",
        root,
        tracked,
        overrides={snapshot: read_bytes(root, snapshot) + b"\n"},
        expected="app-emit snapshot differs",
    )
    _expect_mutation(
        "unclassified vector root",
        root,
        tracked,
        add=(PurePosixPath("other/tests/vectors/private.json"),),
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
        overrides={reference_consumer: reference},
        expected="does not link the managed root-checked team-auth copy",
    )
    arbitrary_mirror = PurePosixPath("server/tests/fixtures/identity-log-v1.json")
    _expect_mutation(
        "arbitrary-directory public mirror",
        root,
        tracked,
        add=(arbitrary_mirror,),
        overrides={
            arbitrary_mirror: read_bytes(root, PUBLIC_ROOT / arbitrary_mirror.name)
        },
        expected="public vector mirror is forbidden",
    )
    renamed_mirror = PurePosixPath("server/tests/fixtures/copied-protocol.json")
    _expect_mutation(
        "renamed public content mirror",
        root,
        tracked,
        add=(renamed_mirror,),
        overrides={
            renamed_mirror: read_bytes(root, PUBLIC_ROOT / "identity-log-v1.json")
        },
        expected="public vector content mirror is forbidden",
    )
    unclassified_consumer = PurePosixPath("other/tests/test_public_vector.py")
    _expect_mutation(
        "unclassified public-vector consumer",
        root,
        tracked,
        add=(unclassified_consumer,),
        overrides={
            unclassified_consumer: b'Path("docs/vectors/identity-log-v1.json").read_text()\n'
        },
        expected="unclassified public-vector code reference",
    )
    a2a_consumer = PurePosixPath("cli/go/a2agw/gateway_rpc_test.go")
    a2a_mirror = PurePosixPath("cli/go/a2agw/testdata/a2a-v1.json")
    redirected = read_bytes(root, a2a_consumer).replace(
        b"../../../docs/vectors/a2a-v1.json",
        b"testdata/a2a-v1.json",
    )
    _expect_mutation(
        "omitted A2A consumer reroute",
        root,
        tracked,
        add=(a2a_mirror,),
        overrides={
            a2a_consumer: redirected,
            a2a_mirror: read_bytes(root, PUBLIC_ROOT / a2a_mirror.name),
        },
        expected="does not resolve the repository-root authority",
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
