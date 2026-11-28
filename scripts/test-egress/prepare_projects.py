#!/usr/bin/env python3
"""Prepare exact-source package environments, then prove cold offline admission."""

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from enum import StrEnum
from pathlib import Path


class SetupFailure(RuntimeError):
    """A selected environment was not prepared; no product test has run."""


class PreparationMode(StrEnum):
    PREPARE = "prepare"
    VERIFY = "verify"


def selected_projects(root, names):
    root = root.resolve()
    projects = []
    for name in dict.fromkeys(names):
        project = (root / name).resolve()
        if (
            not project.is_relative_to(root)
            or not (project / "pyproject.toml").is_file()
        ):
            raise SetupFailure(f"PACKAGE_PROJECT_INVALID: {name}")
        lock = next(
            (
                p / "uv.lock"
                for p in (project, *project.parents)
                if p.is_relative_to(root) and (p / "uv.lock").is_file()
            ),
            None,
        )
        if lock is None:
            raise SetupFailure(f"PACKAGE_LOCK_MISSING: {name}")
        projects.append((project, lock))
    if not projects:
        raise SetupFailure("PACKAGE_SELECTION_EMPTY")
    return projects


def run(args, *, root, env, failure, capture=False, recovery=None):
    result = subprocess.run(
        args, cwd=root, env=env, text=True, capture_output=capture, check=False
    )
    if result.returncode:
        detail = f"{failure}: exit {result.returncode}"
        raise SetupFailure(f"{detail}. {recovery}" if recovery else detail)
    return result.stdout if capture else None


def go_build_cache(*, root: Path, mode: PreparationMode, env: dict[str, str]):
    module = root / "cli/go"
    if not (module / "go.mod").is_file():
        return None
    manifests = [module / name for name in ("go.mod", "go.sum")]
    before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in manifests}
    go_env = dict(
        env,
        GOPROXY="https://proxy.golang.org,direct"
        if mode is PreparationMode.PREPARE
        else "off",
        GOSUMDB="sum.golang.org" if mode is PreparationMode.PREPARE else "off",
        GOFLAGS="-mod=readonly",
    )
    # Use the committed build owner's GOENV, rather than warming Go's default
    # cache while make build selects a different GOMODCACHE.
    with tempfile.TemporaryDirectory(prefix="package-go-cache-") as temporary:
        recipe = Path(temporary) / "Makefile"
        recipe.write_text(
            ".PHONY: package-go-cache package-go-download\n"
            "package-go-cache:\n\t@$(GOENV) go env GOMODCACHE\n"
            "package-go-download:\n\t@$(GOENV) go mod download\n"
        )
        make = [
            "make",
            "--no-print-directory",
            "-s",
            "-C",
            str(module),
            "-f",
            "Makefile",
            "-f",
            str(recipe),
        ]
        selected = run(
            [*make, "package-go-cache"],
            root=root,
            env=go_env,
            failure="PACKAGE_GO_CACHE_SELECTION_FAILED",
            recovery="Correct the selected source's Make GOENV cache path, then prepare that frozen source again.",
            capture=True,
        ).strip()
        cache = Path(selected)
        if not selected or not cache.is_absolute() or cache == Path("/"):
            raise SetupFailure(
                "PACKAGE_GO_CACHE_PATH_INVALID: Correct Make GOENV to select an absolute module cache other than /, then prepare the frozen source again."
            )
        run(
            [*make, "package-go-download"],
            root=root,
            env=go_env,
            failure="PACKAGE_GO_PREPARATION_FAILED"
            if mode is PreparationMode.PREPARE
            else "PACKAGE_GO_OFFLINE_CACHE_MISSING",
            recovery="Prepare the selected frozen source's Make-owned Go cache with network access before running the offline phase.",
        )
    after = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in manifests}
    if before != after:
        raise SetupFailure(
            "PACKAGE_GO_LOCK_CHANGED: Restore the committed go.mod and go.sum, then prepare the frozen source again."
        )
    digest = hashlib.sha256()
    count = 0
    for path in sorted(cache.rglob("*")):
        if path.is_file():
            relative = path.relative_to(cache).as_posix()
            digest.update(
                (
                    relative
                    + "\0"
                    + hashlib.sha256(path.read_bytes()).hexdigest()
                    + "\n"
                ).encode()
            )
            count += 1
    return {
        "module": "cli/go",
        "manifests": after,
        "cache": str(cache),
        "sha256": digest.hexdigest(),
        "files": count,
    }


# Launches the project's locked Chromium through its own Playwright.
BROWSER_LAUNCH_CHECK = (
    "from playwright.sync_api import sync_playwright; "
    "p=sync_playwright().start(); b=p.chromium.launch(); b.close(); p.stop()"
)


def provision(root, sha, names, mode, receipt):
    root = root.resolve()
    if (
        subprocess.check_output(
            ["git", "-c", "safe.directory=" + str(root), "rev-parse", "HEAD"],
            cwd=root,
            text=True,
        ).strip()
        != sha
    ):
        raise SetupFailure("PACKAGE_SOURCE_MISMATCH")
    if mode == "verify" and os.getuid() != 1000:
        raise SetupFailure("PACKAGE_VERIFY_UID_INVALID: expected1000")
    projects = selected_projects(root, names)
    before = {
        str(lock.relative_to(root)): hashlib.sha256(lock.read_bytes()).hexdigest()
        for _, lock in projects
    }
    env = dict(os.environ, UV_OFFLINE="0" if mode == "prepare" else "1")
    # The checkout may belong to another UID than this process. Trust only
    # this operator-selected repository for child build backends.
    env.update(
        GIT_CONFIG_COUNT="1",
        GIT_CONFIG_KEY_0="safe.directory",
        GIT_CONFIG_VALUE_0=str(root),
    )
    for key in ("UV_NO_SYNC", "UV_PROJECT_ENVIRONMENT", "PYTHONPATH", "PYTHONHOME"):
        env.pop(key, None)
    go_cache = go_build_cache(root=root, mode=PreparationMode(mode), env=env)
    rows = []
    for project, _ in projects:
        name = str(project.relative_to(root))
        sync = ["uv", "sync", "--frozen", "--project", str(project)]
        if mode == "verify":
            # A pre-existing venv can conceal absent wheels/build backends.
            with tempfile.TemporaryDirectory(
                prefix="package-offline-check-"
            ) as temporary:
                run(
                    [*sync, "--offline"],
                    root=root,
                    env=dict(env, UV_PROJECT_ENVIRONMENT=str(Path(temporary) / "venv")),
                    failure=f"PACKAGE_OFFLINE_CACHE_MISSING[{name}]",
                )
        else:
            run(sync, root=root, env=env, failure=f"PACKAGE_SYNC_FAILED[{name}]")
        base = ["uv", "run", "--frozen", "--no-sync", "--project", str(project)]
        version = run(
            [
                *base,
                "python",
                "-c",
                (
                    "import importlib.metadata as m; "
                    "print(next((d.version for d in m.distributions() "
                    "if d.metadata['Name'].lower() == 'playwright'), ''))"
                ),
            ],
            root=root,
            env=env,
            failure=f"PACKAGE_ENVIRONMENT_INVALID[{name}]",
            capture=True,
        ).strip()
        # The image installs the locked browser and its system libraries once,
        # as root; preparation runs as UID 1000. Verification launches it
        # through each project's own Playwright.
        if version and mode == "verify":
            run(
                [
                    *base,
                    "python",
                    "-c",
                    BROWSER_LAUNCH_CHECK,
                ],
                root=root,
                env=env,
                failure=f"PACKAGE_BROWSER_UNAVAILABLE[{name}]",
            )
        rows.append({"project": name, "playwright": version or None})
    after = {
        str(lock.relative_to(root)): hashlib.sha256(lock.read_bytes()).hexdigest()
        for _, lock in projects
    }
    if after != before:
        raise SetupFailure("PACKAGE_LOCK_CHANGED")
    receipt.write_text(
        json.dumps(
            {
                "source": sha,
                "mode": mode,
                "uid": os.getuid(),
                "gid": os.getgid(),
                "locks": after,
                "projects": rows,
                "go_cache": go_cache,
                "status": "PASS",
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--project", action="append", required=True)
    parser.add_argument("--mode", choices=("prepare", "verify"), required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    try:
        provision(
            args.source_root, args.source_sha, args.project, args.mode, args.receipt
        )
    except SetupFailure as exc:
        parser.exit(78, str(exc) + "\n")
