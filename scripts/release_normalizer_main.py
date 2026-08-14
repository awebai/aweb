#!/usr/bin/env python3
"""The normalizer phase entry for release-prepare (aben, design section 6).

Derives capture specs from the canonical inventory, routes each unit
target to its registry discoverer, assembles the captured world once,
and runs the orchestration: normal form proceeds, a patch stops before
tests with working-tree edits for normal review, and every other
condition stops by name. Exit codes: 0 normal form, 10 patch needed,
1 stop.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import release_normalizer as rn
import release_normalizer_capture as cap
import release_normalizer_run as run
import release_train as rt

EQUALITY_GROUPS = (
    ("awid-service", "awid-image"),
    ("aweb-server", "a2a-gateway-image"),
)


_REGISTRY_BASES = {
    "pypi": ("AWEB_NORMALIZER_PYPI_BASE", "https://pypi.org"),
    "npm": ("AWEB_NORMALIZER_NPM_BASE", "https://registry.npmjs.org"),
    "ghcr": ("AWEB_NORMALIZER_GHCR_BASE", "https://ghcr.io"),
    "github": ("AWEB_NORMALIZER_GITHUB_BASE", "https://api.github.com"),
}


def registry_bases() -> dict[str, str]:
    """Production registry endpoints, each overridable through its env
    seam (the observe_public_target --base precedent) so end-to-end
    tests drive this exact process over the real wire protocols."""

    return {
        key: os.environ.get(env_name, "").strip() or default
        for key, (env_name, default) in _REGISTRY_BASES.items()
    }


def route_discovery(
    target: str,
    *,
    timeout: float,
    ghcr_token: str,
    gh_token: str,
    bases: dict[str, str],
):
    """One listing call per unit target, by spelling. Unknown spellings
    raise: a new target kind is a reviewed decision, never a skip."""

    if target.startswith("pypi:"):
        return {
            v: None
            for v in cap.discover_pypi_versions(
                target.removeprefix("pypi:"), base=bases["pypi"], timeout=timeout
            )
        }
    if target.startswith("npm:"):
        return {
            v: None
            for v in cap.discover_npm_versions(
                target.removeprefix("npm:"), base=bases["npm"], timeout=timeout
            )
        }
    if target.startswith("ghcr.io/"):
        image = target.removeprefix("ghcr.io/")
        tags = cap.discover_ghcr_versions(
            image, base=bases["ghcr"], timeout=timeout, token=ghcr_token
        )
        occupied: dict[str, str | None] = {}
        for tag in sorted(tags):
            if rn.parse_version(tag) is None:
                # Near-matching candidates occupy identityless; the
                # reconciler stops them by name.
                occupied[tag] = None
                continue
            try:
                occupied[tag] = cap.read_oci_revision(
                    image,
                    tag,
                    base=bases["ghcr"],
                    token=ghcr_token,
                    timeout=timeout,
                )
            except cap.RevisionLabelAbsent:
                occupied[tag] = None
        return occupied
    if target.startswith("github:"):
        _, repository, _channel = target.split(":", 2)
        return {
            v: None
            for v in cap.discover_github_release_versions(
                repository, base=bases["github"], timeout=timeout, token=gh_token
            )
        }
    raise ValueError(f"no discoverer routes target {target!r}")


def _git(root: Path, *args: str) -> str:
    import subprocess

    return subprocess.run(
        ["git", *args], cwd=root, check=True, capture_output=True, text=True
    ).stdout


def worktree_stops(repo_roots: dict[str, Path]) -> list[rn.Stop]:
    """The normalizer's inputs are exact main SHAs from clean checkouts:
    a dirty tree or an origin main that moved past the checkout is a
    named stop before any capture (design section 6)."""

    stops: list[rn.Stop] = []
    for key, root in sorted(repo_roots.items()):
        if _git(root, "status", "--porcelain").strip():
            stops.append(rn.Stop("dirty-checkout", key))
            continue
        head = _git(root, "rev-parse", "HEAD").strip()
        listing = _git(root, "ls-remote", "origin", "refs/heads/main").split()
        remote_main = listing[0] if listing else ""
        if remote_main and remote_main != head:
            stops.append(rn.Stop("main-moved", key))
    return stops


def reobserve_result(result: rn.NormalizerResult, specs, discover) -> list[rn.Stop]:
    """The exit re-observation: every moving artifact's intended version
    must still be free on EVERY declared unit target - a composite
    occupied mid-run on a secondary member is the same race with the
    same name."""

    stops: list[rn.Stop] = []
    for name, artifact in sorted(result.artifacts.items()):
        if artifact.disposition != "moving" or artifact.version is None:
            continue
        spec = next(s for s in specs if s.name == name)
        for target in spec.unit_targets:
            if artifact.version in discover(target):
                stops.append(rn.Stop("version-occupied", name))
                break
    return stops


def invariant_commands(
    aweb_root: Path,
) -> tuple[tuple[str, tuple[str, ...], Path], ...]:
    """The read-only invariant pass (design section 6): the same-cycle
    lock property's check half, the canonical migration chain, and
    suite-map exactness, each by its exact selector. The env override
    exists for hermetic entry tests; the defaults here are pinned by
    test so the override can never quietly become the production path."""

    override = os.environ.get("AWEB_NORMALIZER_INVARIANT_COMMANDS", "").strip()
    if override:
        import json

        return tuple(
            (
                entry["label"],
                tuple(entry["argv"]),
                aweb_root / entry.get("cwd", "."),
            )
            for entry in json.loads(override)
        )
    return (
        ("python-locks", ("bash", "scripts/check-python-locks.sh"), aweb_root),
        (
            "migration-chain",
            (
                "uv",
                "run",
                "--frozen",
                "pytest",
                "tests/test_package_data.py::"
                "test_canonical_chain_starts_with_reset_baseline_then_forward_migrations",
                "-q",
            ),
            aweb_root / "server",
        ),
        (
            "suite-map",
            (
                sys.executable,
                "-m",
                "unittest",
                "scripts.e2e.test_release_gate_contract."
                "ThinReleaseWorkflowContractTests."
                "test_dead_hosted_gate_and_component_paths_are_deleted",
            ),
            aweb_root,
        ),
    )


def run_invariants(aweb_root: Path) -> rn.Stop | None:
    import subprocess

    env = {**os.environ, "UV_OFFLINE": "1"}
    for label, argv, cwd in invariant_commands(aweb_root):
        completed = subprocess.run(argv, cwd=cwd, env=env, capture_output=True)
        if completed.returncode != 0:
            return rn.Stop("invariant-failed", label)
    return None


def main() -> int:
    default_aweb_root = Path(__file__).resolve().parents[1]
    aweb_root = Path(
        os.environ.get("AWEB_NORMALIZER_AWEB_ROOT", "") or default_aweb_root
    ).resolve()
    ac_root = Path(
        os.environ.get("AWEB_NORMALIZER_AC_ROOT", "")
        or (default_aweb_root.parent / "ac")
    ).resolve()
    bases = registry_bases()
    timeout = float(os.environ.get("AWEB_NORMALIZER_TIMEOUT", "30"))
    ghcr_token = os.environ.get("AWEB_GHCR_READ_TOKEN", "")
    gh_token = os.environ.get("GH_TOKEN", "")
    compatibility = os.environ.get("COMPAT_BREAK", "none")

    specs = cap.derive_capture_specs(rt.ARTIFACTS)
    repo_roots = {"aweb": aweb_root, "ac": ac_root}
    manifest_paths = {
        spec.name: repo_roots[spec.repo_key] / spec.manifest_path for spec in specs
    }

    def discover(target: str):
        return route_discovery(
            target,
            timeout=timeout,
            ghcr_token=ghcr_token,
            gh_token=gh_token,
            bases=bases,
        )

    def capture() -> rn.CapturedWorld:
        return cap.assemble_captured_world(
            specs=specs,
            repo_roots=repo_roots,
            discover_target=discover,
            equality_groups=EQUALITY_GROUPS,
            compatibility=compatibility,
        )

    precondition_stops = worktree_stops(repo_roots)
    if precondition_stops:
        for stop in precondition_stops:
            print(f"STOP {stop.code} ({stop.artifact})")
        return 1

    base_shas = {
        key: _git(root, "rev-parse", "HEAD").strip()
        for key, root in sorted(repo_roots.items())
    }

    lock_paths = {
        entry.key: tuple(
            repo_roots[entry.repository] / lock.path
            for lock in entry.owned_locks
            if lock.path
        )
        for entry in rt.ARTIFACTS
        if entry.owned_locks
    }
    lock_command = tuple(
        __import__("shlex").split(
            os.environ.get("AWEB_NORMALIZER_LOCK_COMMAND", "").strip() or "uv lock"
        )
    )

    def regenerate_lock(lock: Path) -> None:
        import subprocess

        subprocess.run(
            lock_command, cwd=lock.parent, check=True, capture_output=True
        )

    outcome = run.run_normalizer(
        capture=capture,
        manifest_paths=manifest_paths,
        reobserve=lambda result: reobserve_result(result, specs, discover),
        normalize=rn.normalize,
        lock_paths=lock_paths,
        regenerate_lock=regenerate_lock,
    )
    if outcome.exit_code in (0, run.PATCH_NEEDED):
        # Read-only invariants over the (possibly patched) tree, after
        # the computation and before anything else runs.
        failed = run_invariants(aweb_root)
        if failed is not None:
            print(outcome.report)
            print(f"STOP {failed.code} ({failed.artifact})")
            return 1
    print(outcome.report)
    if outcome.exit_code == run.PATCH_NEEDED:
        # Transport contract: review of the patch needs nothing but this
        # output - the exact bases the edits apply to, and the edits.
        for key, root in sorted(repo_roots.items()):
            print(f"base {key}={base_shas[key]}")
            tree_diff = _git(root, "diff")
            if tree_diff.strip():
                print(tree_diff, end="")
    return outcome.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
