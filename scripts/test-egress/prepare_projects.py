#!/usr/bin/env python3
"""Prepare exact-source package environments, then prove cold offline admission."""

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path


class SetupFailure(RuntimeError):
    """A selected environment was not prepared; no product test has run."""


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


def run(args, *, root, env, failure, capture=False):
    result = subprocess.run(
        args, cwd=root, env=env, text=True, capture_output=capture, check=False
    )
    if result.returncode:
        raise SetupFailure(f"{failure}: exit {result.returncode}")
    return result.stdout if capture else None


def provision(root, sha, names, mode, receipt):
    root = root.resolve()
    if (
        subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=root, text=True
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
    for key in ("UV_NO_SYNC", "UV_PROJECT_ENVIRONMENT", "PYTHONPATH", "PYTHONHOME"):
        env.pop(key, None)
    rows = []
    installed = set()
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
        if version:
            if mode == "prepare" and version not in installed:
                run(
                    [
                        *base,
                        "playwright",
                        "install",
                        "--with-deps",
                        "--only-shell",
                        "chromium",
                    ],
                    root=root,
                    env=env,
                    failure=f"PACKAGE_BROWSER_INSTALL_FAILED[{name}]",
                )
                installed.add(version)
            elif mode == "verify":
                run(
                    [
                        *base,
                        "python",
                        "-c",
                        (
                            "from playwright.sync_api import sync_playwright; "
                            "p=sync_playwright().start(); b=p.chromium.launch(); b.close(); p.stop()"
                        ),
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
                "locks": after,
                "projects": rows,
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
