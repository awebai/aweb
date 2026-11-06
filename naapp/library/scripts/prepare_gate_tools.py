#!/usr/bin/env python3
"""Prepare reviewed Linux release clients in an operator-owned private directory."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import stat
import subprocess
import tarfile
from pathlib import Path
from urllib.request import Request, urlopen

MANIFEST = Path(__file__).resolve().parents[1] / "ops/release-client-artifacts.json"


class SetupError(RuntimeError):
    pass


def require_tool_root(root: Path) -> Path:
    if not root.is_absolute() or root.is_symlink():
        raise SetupError("LIBRARY_GATE_TOOL_ROOT must be an absolute private directory")
    info = root.stat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_IMODE(info.st_mode) != 0o700
        or info.st_uid != os.getuid()
    ):
        raise SetupError("tool directory must be operator-owned with mode 0700")
    return root


def extract_verified(archive: Path, destination: Path, expected_sha: str) -> None:
    with archive.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if digest != expected_sha:
        raise SetupError("download SHA-256 does not match the reviewed release archive")
    with tarfile.open(archive) as source:
        source.extractall(destination, filter="data")


def tree_digest(root: Path) -> str:
    rows = [
        (path.relative_to(root).as_posix(), hashlib.sha256(path.read_bytes()).hexdigest())
        for path in root.rglob("*")
        if path.is_file()
    ]
    return hashlib.sha256(json.dumps(sorted(rows), separators=(",", ":")).encode()).hexdigest()


def verify_tools(root: Path) -> dict[str, Path]:
    require_tool_root(root)
    manifest = json.loads(MANIFEST.read_text())
    paths = {}
    for name, pin in manifest["artifacts"].items():
        artifact = root / name / pin["member"]
        with artifact.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if digest != pin["sha256"]:
            raise SetupError(f"{name} executable SHA-256 does not match the reviewed artifact")
        if name == "pi" and tree_digest(root / name / "package") != pin["tree_sha256"]:
            raise SetupError("Pi package content does not match the reviewed archive")
        paths[name] = artifact
    return paths


def prepare(root: Path) -> dict[str, Path]:
    require_tool_root(root)
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
        raise SetupError("reviewed clients require Linux x86_64")
    if any(root.iterdir()):
        raise SetupError("prepare requires an empty private tool directory; use a fresh directory")
    manifest = json.loads(MANIFEST.read_text())
    for name, pin in manifest["artifacts"].items():
        archive = root / f"{name}.archive"
        with (
            urlopen(
                Request(pin["url"], headers={"User-Agent": "aweb-library-deploy-gate/1.0"}),
                timeout=180,
            ) as response,
            archive.open("xb") as output,
        ):
            while block := response.read(1024 * 1024):
                output.write(block)
        extract_verified(archive, root / name, pin["archive_sha256"])
    paths = verify_tools(root)
    for name in ("aw", "claude", "node"):
        paths[name].chmod(0o700)
    environment = {key: os.environ[key] for key in ("HOME", "LANG", "TMPDIR") if key in os.environ}
    environment["PATH"] = f"{paths['node'].parent}:/usr/bin:/bin"
    for command in (
        [str(paths["aw"]), "version"],
        [str(paths["claude"]), "--version"],
        [str(paths["node"]), "--version"],
        [str(paths["node"]), str(paths["pi"]), "--version"],
    ):
        subprocess.run(command, check=True, env=environment)
    return paths


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tools-root", type=Path, default=os.environ.get("LIBRARY_GATE_TOOL_ROOT"))
    args = parser.parse_args()
    try:
        if args.tools_root is None:
            raise SetupError("LIBRARY_GATE_TOOL_ROOT is required")
        prepare(args.tools_root)
        print("PASS: reviewed Library Linux release clients prepared")
        return 0
    except (SetupError, OSError, tarfile.TarError, subprocess.CalledProcessError) as exc:
        print(f"ERROR: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
