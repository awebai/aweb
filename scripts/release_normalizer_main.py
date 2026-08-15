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

import dataclasses
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


def _artifact_owning(target: str):
    """The canonical entry whose occupancy unit contains this target."""

    for entry in rt.ARTIFACTS:
        if target in (entry.occupancy_unit or ()):
            return entry
    raise ValueError(f"no canonical artifact owns target {target!r}")


def route_discovery(
    target: str,
    *,
    timeout: float,
    ghcr_token: str,
    gh_token: str,
    bases: dict[str, str],
):
    """One listing call per unit target, by spelling. Unknown spellings
    raise: a new target kind is a reviewed decision, never a skip.

    The GitHub tag prefix is DERIVED here from the canonical record,
    not passed in. It used to be a parameter defaulting to "v", and a
    caller that forgot it got silence rather than an error: continue's
    world assembly omitted it, so skills' release member was searched
    for `v0.2.12` instead of `skills-v0.2.12`, read as EMPTY, and the
    unit became conflicting-partial - refusing the release twice with
    a stop that pointed at skills rather than at the caller. Third
    derivation of one fact; the parameter is what allowed it.
    """

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
        # OCCUPANCY ONLY. Resolving each tag's source identity here is
        # a three-request walk per tag and was 94% of the phase's wall
        # time (1601 of 1672 remote calls, measured), to build a map
        # whose entries the reconciler reads at exactly one version.
        # route_identity below is called for the versions that
        # are actually compared.
        return {tag: None for tag in sorted(tags)}
    if target.startswith("github:"):
        _, repository, _channel = target.split(":", 2)
        return {
            v: None
            for v in cap.discover_github_release_versions(
                repository,
                base=bases["github"],
                timeout=timeout,
                token=gh_token,
                tag_prefix=rt.release_tag_prefix(
                    _artifact_owning(target), repository
                ),
            )
        }
    raise ValueError(f"no discoverer routes target {target!r}")


def _git(root: Path, *args: str) -> str:
    import subprocess

    return subprocess.run(
        ["git", *args], cwd=root, check=True, capture_output=True, text=True
    ).stdout


AW_CHECKOUT_DIRNAME = "aw"


def aw_root(aweb_root: Path) -> Path:
    """THE canonical location of the aw product checkout: a sibling of
    the aweb checkout, named `aw` - the same shape as the AC sibling,
    overridable by env for hermetic tests exactly like the AC one."""

    return Path(
        os.environ.get("AWEB_NORMALIZER_AW_ROOT", "")
        or (aweb_root.parent / AW_CHECKOUT_DIRNAME)
    )


def aw_checkout_stops(root: Path) -> list[rn.Stop]:
    """Each way the aw checkout can be unusable refuses BY ITS OWN
    NAME.

    The binding it answers - the external v{V} tag and the exact
    tree-equals-cli/go comparison - is now read from this checkout with
    local git. A missing or stale checkout must therefore stop the run
    rather than silently degrade the binding to "not checked": an
    unrunnable check that reports nothing is the column-b defect, where
    a row could not run where it was supposed to and nobody noticed.
    """

    if not root.exists():
        return [rn.Stop("aw-checkout-absent", "aw-cli",
                        detail=f"expected a checkout of awebai/aw at {root}")]
    if not (root / ".git").exists():
        return [rn.Stop("aw-checkout-unavailable", "aw-cli",
                        detail=f"{root} exists but is not a git repository")]
    try:
        dirty = _git(root, "status", "--porcelain").strip()
    except Exception as error:  # noqa: BLE001 - named stop, never a traceback
        return [rn.Stop("aw-checkout-unavailable", "aw-cli", detail=str(error))]
    if dirty:
        return [rn.Stop("aw-checkout-dirty", "aw-cli",
                        detail="the binding must read published trees, not local edits")]
    head = _git(root, "rev-parse", "HEAD").strip()
    listing = _git(root, "ls-remote", "origin", "refs/heads/main").split()
    remote_main = listing[0] if listing else ""
    if remote_main and remote_main != head:
        return [rn.Stop("aw-checkout-stale", "aw-cli",
                        detail=f"checkout at {head}, origin/main at {remote_main}")]
    return []


def continue_command_script_stops(repo_roots: dict) -> list[rn.Stop]:
    """Every fixed continue command's script must exist in the checkout
    prepare RESOLVED - refused here, by name, at the fail-fast phase.

    This is deliberately a RUN-TIME check rather than a test. A test
    can only ask "does this script exist in either repository", which
    is a different claim from the one a release depends on, and it
    cannot even be answered where the gate runs: the container mounts
    only the aweb checkout, so the five AC-side commands look missing.
    Prepare already resolves the AC checkout, so it is both the only
    place that can see these scripts and the place where their absence
    actually stops a release - before anything publishes rather than
    at the edge that needs them.
    """

    stops: list[rn.Stop] = []
    for env, argv in sorted(rt._CONTINUE_FIXED_COMMANDS.items()):
        for token in argv:
            if not token.endswith(".py"):
                continue
            found = [
                key for key, root in repo_roots.items() if (root / token).is_file()
            ]
            if not found:
                stops.append(
                    rn.Stop(
                        "continue-command-script-missing",
                        env,
                        detail=(
                            f"{token} is in none of the resolved checkouts "
                            f"({', '.join(f'{k}={v}' for k, v in sorted(repo_roots.items()))})"
                        ),
                    )
                )
            # Only the FIRST .py token is checked: it is the script
            # being invoked, and a later one would be an argument
            # rather than an interpreter target. True of every current
            # command; stated so the next reader does not have to
            # infer it from the loop.
            break
    return stops


def worktree_stops(
    repo_roots: dict[str, Path], expected_shas: dict[str, str] | None = None
) -> list[rn.Stop]:
    """The normalizer's inputs are exact SHAs from clean checkouts: a
    dirty tree stops; without a selected override the checkout must
    equal origin main; with one (docs/release.md's AWEB_SHA/AC_SHA,
    validated on-main upstream) the checkout must equal exactly the
    selected commit (C4)."""

    stops: list[rn.Stop] = []
    for key, root in sorted(repo_roots.items()):
        if _git(root, "status", "--porcelain").strip():
            stops.append(rn.Stop("dirty-checkout", key))
            continue
        head = _git(root, "rev-parse", "HEAD").strip()
        selected = (expected_shas or {}).get(key)
        if selected is not None:
            if head != selected:
                stops.append(rn.Stop("selected-sha-mismatch", key))
            continue
        listing = _git(root, "ls-remote", "origin", "refs/heads/main").split()
        # An empty listing here is genuine absence, not unavailability:
        # _git runs with check=True, so a FAILED ls-remote (network,
        # auth, no remote) raises before this branch is reached. That
        # keyword is what keeps "cannot ask" from reading as "nothing
        # to move" - do not relax it.
        remote_main = listing[0] if listing else ""
        if remote_main and remote_main != head:
            stops.append(rn.Stop("main-moved", key))
    return stops


def reobserve_result(
    result: rn.NormalizerResult, specs, discover, world=None
) -> list[rn.Stop]:
    """The exit re-observation over every load-bearing fact, classified
    as progress versus conflict: a moving artifact's intended version
    must still be free on EVERY declared unit target; a recovery
    candidate's occupancy may only have grown identically to what
    capture saw (a member completing with the same identity is progress;
    a changed or foreign identity is registry-conflict); and an unmoved
    or recovery row's anchor identity must not have moved under the run.
    """

    stops: list[rn.Stop] = []
    for name, artifact in sorted(result.artifacts.items()):
        if artifact.version is None:
            continue
        spec = next(s for s in specs if s.name == name)
        if artifact.disposition == "moving":
            for target in spec.unit_targets:
                if artifact.version in discover(target):
                    stops.append(rn.Stop("version-occupied", name))
                    break
            continue
        if artifact.disposition == "moving-with-recovery" and world is not None:
            # At this phase nothing has published yet, so a recovery
            # candidate's occupancy changing IN ANY WAY between capture
            # and exit means the world moved under the run - occupancy
            # appearing, disappearing, or changing identity are all the
            # same conflict; the rerun recomputes from the new world.
            captured = world.artifacts.get(name)
            captured_members = (
                {m.name: dict(m.occupied) for m in captured.members}
                if captured is not None
                else {}
            )
            for target in spec.unit_targets:
                fresh = discover(target)
                seen = captured_members.get(target, {})
                if fresh.get(artifact.version, "absent") != seen.get(
                    artifact.version, "absent"
                ):
                    stops.append(rn.Stop("registry-conflict", name))
                    break
    return stops


@dataclasses.dataclass(frozen=True)
class InvariantCommand:
    """One invariant check. `offline` marks the ones that RESOLVE:
    UV_OFFLINE proves check-python-locks.sh re-derives from cache
    rather than the live index, which is the point of that check. A
    --frozen command cannot resolve at all, so forcing it offline only
    blocks INSTALL and makes the result depend on whether the local uv
    cache happens to hold a dependency - a flake that fires mid-release
    and reads as a code problem."""

    label: str
    argv: tuple[str, ...]
    cwd: Path
    offline: bool = False


def invariant_commands(
    aweb_root: Path,
) -> tuple[InvariantCommand, ...]:
    """The read-only invariant pass (design section 6): the same-cycle
    lock property's check half, the canonical migration chain, and
    suite-map exactness, each by its exact selector. The env override
    exists for hermetic entry tests; the defaults here are pinned by
    test so the override can never quietly become the production path."""

    override = os.environ.get("AWEB_NORMALIZER_INVARIANT_COMMANDS", "").strip()
    if override:
        import json

        return tuple(
            InvariantCommand(
                label=entry["label"],
                argv=tuple(entry["argv"]),
                cwd=aweb_root / entry.get("cwd", "."),
                offline=bool(entry.get("offline", False)),
            )
            for entry in json.loads(override)
        )
    return (
        InvariantCommand(
            "python-locks",
            ("bash", "scripts/check-python-locks.sh"),
            aweb_root,
            offline=True,
        ),
        InvariantCommand(
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
        InvariantCommand(
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

    for command in invariant_commands(aweb_root):
        env = {**os.environ}
        if command.offline:
            env["UV_OFFLINE"] = "1"
        try:
            completed = subprocess.run(
                command.argv,
                cwd=command.cwd,
                env=env,
                capture_output=True,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            # A hung invariant with captured output is a silent hang at
            # the first phase; the bound turns it into a named stop.
            return rn.Stop("invariant-timeout", command.label)
        if completed.returncode != 0:
            # The refusal carries what it already knows. Returning the
            # bare label threw away output the phase had captured, and
            # recovering it meant re-running the command by hand -
            # which an operator has no reason to think is possible.
            output = (completed.stdout or b"") + (completed.stderr or b"")
            detail = output.decode(errors="replace").strip()
            tail = "\n".join(detail.splitlines()[-20:])
            return rn.Stop("invariant-failed", command.label, detail=tail)
    return None


def run_phase(
    roots: dict[str, Path] | None = None,
    expected_shas: dict[str, str] | None = None,
) -> tuple[int, str, "rn.NormalizerResult | None", dict]:
    """The whole normalizer phase, callable in-process: preconditions,
    capture, double-compute, apply, fixed point, exit re-observation,
    invariants, transport. Returns (exit code, report text, the
    projection on success, {"aweb_root", "base_shas"}) so
    release-prepare consumes the SAME in-memory result this phase
    validated (A5) and can bind the card to the exact commits it was
    computed from (C4). `roots` overrides the checkout pair (the
    selected-SHA worktrees); `expected_shas` replaces the current-main
    precondition per repo with equality against the selected commit.
    """

    default_aweb_root = Path(__file__).resolve().parents[1]
    aweb_root = Path(
        (roots or {}).get("aweb")
        or os.environ.get("AWEB_NORMALIZER_AWEB_ROOT", "")
        or default_aweb_root
    ).resolve()
    ac_root = Path(
        (roots or {}).get("ac")
        or os.environ.get("AWEB_NORMALIZER_AC_ROOT", "")
        or (default_aweb_root.parent / "ac")
    ).resolve()
    bases = registry_bases()
    timeout = float(os.environ.get("AWEB_NORMALIZER_TIMEOUT", "30"))
    ghcr_token = cap.ghcr_bearer(os.environ.get("AWEB_GHCR_READ_TOKEN", ""))
    gh_token = os.environ.get("GH_TOKEN", "")
    compatibility = os.environ.get("COMPAT_BREAK", "none")

    specs = cap.derive_capture_specs(rt.ARTIFACTS)
    repo_roots = {"aweb": aweb_root, "ac": ac_root}
    manifest_paths = {
        spec.name: repo_roots[spec.repo_key] / spec.manifest_path for spec in specs
    }
    # Files that mirror an artifact's version and must move with it,
    # from the canonical record - the guard that enforces the equality
    # and the patcher that must satisfy it now read one declaration.
    version_mirrors = {
        entry.key: tuple(
            repo_roots[entry.repository] / mirror for mirror in entry.version_mirrors
        )
        for entry in rt.ARTIFACTS
        if entry.version_mirrors
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

    # The aw checkout is a PRECONDITION of the run, not an optional
    # convenience: the external binding is read from it with local git,
    # so an absent or stale one must refuse rather than let the binding
    # quietly become unchecked.
    precondition_stops = worktree_stops(repo_roots, expected_shas)
    precondition_stops += aw_checkout_stops(aw_root(aweb_root))
    precondition_stops += continue_command_script_stops(repo_roots)
    if precondition_stops:
        report = run.render_stops(precondition_stops)
        return 1, report, None, aweb_root

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

        # The approved regeneration is offline (design section 6): the
        # patch phase must not resolve against the live index, only
        # re-derive from the cache - UV_OFFLINE on the regeneration
        # itself, not merely the later invariant check.
        subprocess.run(
            lock_command,
            cwd=lock.parent,
            check=True,
            capture_output=True,
            env={**os.environ, "UV_OFFLINE": "1"},
        )

    outcome = run.run_normalizer(
        capture=capture,
        manifest_paths=manifest_paths,
        version_mirrors=version_mirrors,
        reobserve=lambda result, world: reobserve_result(
            result, specs, discover, world
        ),
        normalize=rn.normalize,
        lock_paths=lock_paths,
        regenerate_lock=regenerate_lock,
    )
    report_lines = [outcome.report]
    if outcome.exit_code in (0, run.PATCH_NEEDED):
        # Read-only invariants over the (possibly patched) tree, after
        # the computation and before anything else runs.
        failed = run_invariants(aweb_root)
        if failed is not None:
            report_lines.append(f"STOP {failed.code} ({failed.artifact})")
            return 1, "\n".join(report_lines), None, aweb_root
    if outcome.exit_code == run.PATCH_NEEDED:
        # Transport contract: review of the patch needs nothing but this
        # output - the exact bases the edits apply to, and the edits.
        for key, root in sorted(repo_roots.items()):
            report_lines.append(f"base {key}={base_shas[key]}")
            tree_diff = _git(root, "diff")
            if tree_diff.strip():
                report_lines.append(tree_diff.rstrip("\n"))
    return (
        outcome.exit_code,
        "\n".join(report_lines),
        outcome.result if outcome.exit_code == 0 else None,
        {"aweb_root": aweb_root, "base_shas": base_shas},
    )


def main() -> int:
    exit_code, report, _result, _info = run_phase()
    print(report)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
