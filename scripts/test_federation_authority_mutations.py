#!/usr/bin/env python3
"""Prove the strict Go authority vectors kill reviewed security weakenings."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def copy_checkout(destination: Path) -> None:
    shutil.copytree(
        ROOT / "cli" / "go",
        destination / "cli" / "go",
        ignore=shutil.ignore_patterns(".cache", "aw"),
    )
    shutil.copytree(
        ROOT / "awid",
        destination / "awid",
        ignore=shutil.ignore_patterns(".venv", ".pytest_cache", "__pycache__"),
    )
    shutil.copytree(ROOT / "docs", destination / "docs")
    (destination / "scripts").mkdir()
    shutil.copy2(
        ROOT / "scripts" / "pytest_tracked_collection.py",
        destination / "scripts" / "pytest_tracked_collection.py",
    )
    subprocess.run(["git", "init", "-q"], cwd=destination, check=True)
    subprocess.run(
        ["git", "add", "-f", "awid/tests/test_external_authority.py"],
        cwd=destination,
        check=True,
    )


def run_test(root: Path, pattern: str) -> subprocess.CompletedProcess[str]:
    environment = {
        **os.environ,
        "GOCACHE": os.environ.get("GOCACHE", "/tmp/go-build"),
    }
    return subprocess.run(
        ["go", "test", "./awid", "-run", pattern, "-count=1"],
        cwd=root / "cli" / "go",
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def run_python_test(root: Path, pattern: str) -> subprocess.CompletedProcess[str]:
    environment = {
        **os.environ,
        "UV_CACHE_DIR": os.environ.get("UV_CACHE_DIR", "/tmp/uv-cache"),
        "PYTHONPYCACHEPREFIX": os.environ.get("PYTHONPYCACHEPREFIX", "/tmp/pycache"),
    }
    return subprocess.run(
        ["uv", "run", "--frozen", "pytest", "-q", "tests/test_external_authority.py", "-k", pattern],
        cwd=root / "awid",
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def replace_exact(path: Path, old: str, new: str) -> None:
    source = path.read_text(encoding="utf-8")
    if source.count(old) != 1:
        raise SystemExit(f"expected one mutation target in {path}, found {source.count(old)}")
    path.write_text(source.replace(old, new), encoding="utf-8")


def replace_unique_json(root: Path, old: str, new: str) -> tuple[Path, str]:
    matches = []
    for path in root.glob("*.json"):
        source = path.read_text(encoding="utf-8")
        if old in source:
            matches.append((path, source))
    if len(matches) != 1:
        raise SystemExit(f"expected one JSON mutation target, found {len(matches)}")
    path, source = matches[0]
    replace_exact(path, old, new)
    return path, source


def require_killed(result: subprocess.CompletedProcess[str], marker: str) -> None:
    if result.returncode == 0:
        raise SystemExit(f"mutation survived; expected failing case {marker}")
    if marker not in result.stdout:
        raise SystemExit(
            f"mutation failed for the wrong reason; missing {marker!r}:\n{result.stdout}"
        )


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="aweb-authority-mutations-") as temporary:
        checkout = Path(temporary)
        copy_checkout(checkout)
        baseline = run_test(
            checkout,
            "TestStrictFederationOriginAndIPVectors|TestStrictGoAuthorityLookupVectors",
        )
        if baseline.returncode != 0:
            raise SystemExit(f"authority mutation baseline failed:\n{baseline.stdout}")
        python_baseline = run_python_test(
            checkout, "pinned_transport_vectors or authority_lookup_vectors"
        )
        if python_baseline.returncode != 0:
            raise SystemExit(
                f"Python authority mutation baseline failed:\n{python_baseline.stdout}"
            )

        authority = checkout / "cli" / "go" / "awid" / "federation_authority.go"
        replace_exact(
            authority,
            '\tnetip.MustParsePrefix("100.64.0.0/10"),\n',
            "",
        )
        require_killed(
            run_test(checkout, "TestStrictFederationOriginAndIPVectors"),
            "ipv4_shared",
        )
        shutil.copy2(ROOT / "cli" / "go" / "awid" / "federation_authority.go", authority)

        registry = (
            checkout
            / "cli"
            / "go"
            / "awid"
            / "federation_external_registry.go"
        )
        replace_exact(
            registry,
            'if domainErr != nil || namespaceDomain != domain || namespace.ControllerDID == "" ||\n\t\t(authority.Selection == "dns" && namespace.ControllerDID != authority.ControllerDID) {',
            'if domainErr != nil || namespaceDomain != domain || namespace.ControllerDID == "" {',
        )
        require_killed(
            run_test(checkout, "TestStrictGoAuthorityLookupVectors/dns_controller_mismatch"),
            "dns_controller_mismatch",
        )
        shutil.copy2(
            ROOT / "cli" / "go" / "awid" / "federation_external_registry.go",
            registry,
        )

        vector, original_vector = replace_unique_json(
            checkout / "docs" / "vectors",
            '      "subsequent_answers": ["10.0.0.1"],',
            '      "subsequent_answers": ["93.184.216.34"],',
        )
        require_killed(
            run_python_test(
                checkout,
                "pinned_transport_vectors and pinned_ip_preserves_hostname_tls_and_disables_ambient_state",
            ),
            "pinned_ip_preserves_hostname_tls_and_disables_ambient_state",
        )
        require_killed(
            run_test(
                checkout,
                "TestStrictFederationOriginAndIPVectors/pinned_ip_preserves_hostname_tls_and_disables_ambient_state",
            ),
            "pinned_ip_preserves_hostname_tls_and_disables_ambient_state",
        )
        vector.write_text(original_vector, encoding="utf-8")

        vector, _ = replace_unique_json(
            checkout / "docs" / "vectors",
            '"fallback_contacted": false, "full_log_required": true}',
            '"fallback_contacted": false, "full_log_required": false}',
        )
        require_killed(
            run_python_test(
                checkout,
                "authority_lookup_vectors and degraded_key_never_authorizes",
            ),
            "degraded_key_never_authorizes",
        )
        require_killed(
            run_test(
                checkout,
                "TestStrictGoAuthorityLookupVectors/degraded_key_never_authorizes",
            ),
            "degraded_key_never_authorizes",
        )

    print(
        "authority mutation controls passed: shared IPv4, DNS-controller, "
        "rebinding-answer, and full-log weakenings were killed"
    )


if __name__ == "__main__":
    main()
