"""Worker-owned Node build and read trees for parallel server tests."""

from __future__ import annotations

import os
import re
import runpy
import shutil
import subprocess
import tempfile
from pathlib import Path

# worker_services.py is loaded by path wherever it is used, never imported as
# a package module.
xdist_worker_index = runpy.run_path(
    str(Path(__file__).with_name("worker_services.py"))
)["xdist_worker_index"]

PACKAGES = ("channel-core", "channel", "pi-extension")
FILES = (
    "scripts/check-node-build-provenance.mjs",
    "server/tests/activity_emitter_host.mjs",
    "cli/go/internal/wake/channel_core_runner_bundle.mjs",
)


def runtime_repo(source: Path) -> Path:
    worker = os.environ.get("PYTEST_XDIST_WORKER")
    if worker is None:
        return source
    uid = os.environ.get("PYTEST_XDIST_TESTRUNUID", "")
    count = os.environ.get("PYTEST_XDIST_WORKER_COUNT", "")
    refusal = RuntimeError("parallel runtime tree requires the owned xdist identity")
    # One tree per worker of the run's plan, whatever its size.
    if (
        re.fullmatch(r"[1-9][0-9]*", count) is None
        or re.fullmatch(r"[0-9a-f]{32}", uid) is None
    ):
        raise refusal
    try:
        xdist_worker_index(worker, int(count))
    except ValueError:
        raise refusal from None
    return Path(tempfile.gettempdir()) / f"aweb-server-runtime-{uid}-{worker}"


def remove_runtime_tree(root: Path) -> None:
    # Only the newly created owned copy: never follow dependency symlinks.
    for directory, names, _ in os.walk(root):
        Path(directory).chmod(0o700)
        for name in names:
            child = Path(directory) / name
            if not child.is_symlink():
                child.chmod(0o700)
    shutil.rmtree(root)


def prepare_runtime_tree(source: Path, root: Path) -> None:
    source = source.resolve()
    root.mkdir(mode=0o700)  # Refuse a preexisting tree; do not remove it on error.
    try:
        for package in PACKAGES:
            origin = source / package
            if not (origin / "node_modules").is_dir():
                raise RuntimeError(f"runtime dependencies were not prepared: {package}")

            # Ignore only this package's generated output, not dependencies' dist.
            def ignore(directory, names, origin=origin):
                return (
                    {"dist"} if Path(directory) == origin and "dist" in names else set()
                )

            shutil.copytree(origin, root / package, symlinks=True, ignore=ignore)
        for name in FILES:
            destination = root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source / name, destination)
        # npm's file: workspace links must resolve inside this worker too.
        # Relative links preserve the layout; rebind absolute source links.
        for link in root.rglob("*"):
            if not link.is_symlink():
                continue
            resolved = link.resolve()
            if resolved.is_relative_to(source):
                destination = root / resolved.relative_to(source)
                link.unlink()
                link.symlink_to(os.path.relpath(destination, link.parent))
            if not link.resolve().is_relative_to(root.resolve()) or not link.exists():
                raise RuntimeError(
                    f"runtime dependency link escapes the worker tree: {link}"
                )
        for directory, _, _ in os.walk(root):
            Path(directory).chmod(0o700)
        # Both prebuilds rebuild core. Complete both before any consumer starts.
        for package in ("channel", "pi-extension"):
            result = subprocess.run(
                ["npm", "run", "build"],
                cwd=root / package,
                capture_output=True,
                text=True,
            )
            if result.returncode:
                raise RuntimeError(
                    f"owned {package} build failed: {result.stdout}\n{result.stderr}"
                )
    except BaseException:
        remove_runtime_tree(root)
        raise
