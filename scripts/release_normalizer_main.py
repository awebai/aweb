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


def route_discovery(target: str, *, timeout: float, ghcr_token: str, gh_token: str):
    """One listing call per unit target, by spelling. Unknown spellings
    raise: a new target kind is a reviewed decision, never a skip."""

    if target.startswith("pypi:"):
        return {
            v: None
            for v in cap.discover_pypi_versions(
                target.removeprefix("pypi:"), timeout=timeout
            )
        }
    if target.startswith("npm:"):
        return {
            v: None
            for v in cap.discover_npm_versions(
                target.removeprefix("npm:"), timeout=timeout
            )
        }
    if target.startswith("ghcr.io/"):
        image = target.removeprefix("ghcr.io/")
        return {
            v: None
            for v in cap.discover_ghcr_versions(
                image, timeout=timeout, token=ghcr_token
            )
        }
    if target.startswith("github:"):
        _, repository, _channel = target.split(":", 2)
        return {
            v: None
            for v in cap.discover_github_release_versions(
                repository, timeout=timeout, token=gh_token
            )
        }
    raise ValueError(f"no discoverer routes target {target!r}")


def main() -> int:
    aweb_root = Path(__file__).resolve().parents[1]
    ac_root = (aweb_root.parent / "ac").resolve()
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
            target, timeout=timeout, ghcr_token=ghcr_token, gh_token=gh_token
        )

    def capture() -> rn.CapturedWorld:
        return cap.assemble_captured_world(
            specs=specs,
            repo_roots=repo_roots,
            discover_target=discover,
            equality_groups=EQUALITY_GROUPS,
            compatibility=compatibility,
        )

    def reobserve(result: rn.NormalizerResult):
        # The exit re-observation: every moving artifact's intended
        # version must still be free on its primary target. World
        # movement stops under its real name.
        stops = []
        for name, artifact in sorted(result.artifacts.items()):
            if artifact.disposition != "moving" or artifact.version is None:
                continue
            spec = next(s for s in specs if s.name == name)
            occupied = discover(spec.unit_targets[0])
            if artifact.version in occupied:
                stops.append(rn.Stop("version-occupied", name))
        return stops

    outcome = run.run_normalizer(
        capture=capture,
        manifest_paths=manifest_paths,
        reobserve=reobserve,
        normalize=rn.normalize,
    )
    print(outcome.report)
    return outcome.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
