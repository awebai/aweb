#!/usr/bin/env python3
"""Run the reviewed, disposable exact-name Channel wake cell.

This harness is inert unless invoked with every exact reviewed input. It never
installs a plugin, edits a marketplace, or reads ambient Claude configuration.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile

FINAL_MCP_NAME = "aweb-channel"
FINAL_SOURCE = "plugin:aweb-channel:aweb-channel"
LIVE_TEST_NAME = "fresh isolated Claude session wakes through the exact distinct MCP name beside an aweb fixture"
REJECTED_ENV_PREFIXES = ("ANTHROPIC", "CLAUDE", "MCP_", "PLUGIN_")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_exact_file(path: str, expected_sha256: str, label: str) -> Path:
    candidate = Path(path).expanduser().resolve(strict=True)
    if not candidate.is_file():
        raise ValueError(f"{label} must be an existing regular file: {candidate}")
    actual = sha256(candidate)
    if actual != expected_sha256:
        raise ValueError(f"{label} sha256 {actual} does not equal reviewed {expected_sha256}")
    return candidate


def reject_ambient_configuration(credential_env: str, environ: dict[str, str]) -> None:
    unsafe = sorted(
        name for name in environ
        if name != credential_env and name.startswith(REJECTED_ENV_PREFIXES)
    )
    if unsafe:
        raise ValueError(f"refusing inherited Claude/plugin/auth configuration: {', '.join(unsafe)}")
    if not environ.get(credential_env):
        raise ValueError(f"dedicated disposable credential {credential_env} is missing")


def safe_extract_tgz(tgz: Path, destination: Path) -> Path:
    destination_resolved = destination.resolve()
    with tarfile.open(tgz, "r:gz") as archive:
        members = archive.getmembers()
        for member in members:
            target = (destination / member.name).resolve()
            if destination_resolved not in target.parents and target != destination_resolved:
                raise ValueError(f"tgz path escapes extraction root: {member.name}")
            if member.issym() or member.islnk() or member.isdev():
                raise ValueError(f"tgz contains unsupported link/device: {member.name}")
        archive.extractall(destination, members=members, filter="data")
    package_root = destination / "package"
    if not package_root.is_dir():
        raise ValueError("tgz lacks package/ root")
    return package_root.resolve()


def validate_package_identity(package_root: Path) -> None:
    package = json.loads((package_root / "package.json").read_text())
    if package.get("name") != "@awebai/claude-channel" or package.get("version") != "1.7.3":
        raise ValueError("tgz is not @awebai/claude-channel@1.7.3")
    declaration = json.loads((package_root / ".mcp.json").read_text())
    servers = declaration.get("mcpServers")
    if not isinstance(servers, dict) or set(servers) != {FINAL_MCP_NAME}:
        raise ValueError(f"tgz must declare exactly MCP server {FINAL_MCP_NAME}")
    if not (package_root / "dist" / "index.js").is_file():
        raise ValueError("tgz lacks dist/index.js")


def exact_version(binary: Path) -> str:
    result = subprocess.run(
        [str(binary), "--version"], check=True, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        env={"HOME": tempfile.gettempdir(), "PATH": os.defpath},
    )
    return result.stdout.strip()


def build_allowlisted_env(
    root: Path,
    credential_env: str,
    credential: str,
    path_dirs: list[Path],
    live_config: Path,
) -> dict[str, str]:
    locations = {
        "HOME": root / "runner-home",
        "CLAUDE_CONFIG_DIR": root / "runner-claude-config",
        "XDG_CONFIG_HOME": root / "runner-xdg-config",
        "XDG_CACHE_HOME": root / "runner-xdg-cache",
        "XDG_STATE_HOME": root / "runner-xdg-state",
        "TMPDIR": root / "runner-tmp",
    }
    for path in locations.values():
        path.mkdir(parents=True, exist_ok=True)
    return {
        **{name: str(path) for name, path in locations.items()},
        "PATH": os.pathsep.join(str(path) for path in path_dirs),
        credential_env: credential,
        "AWEB_CHANNEL_NAME_LIVE_CONFIG": str(live_config),
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--source-sha", required=True)
    result.add_argument("--tgz", required=True)
    result.add_argument("--tgz-sha256", required=True)
    result.add_argument("--claude-bin", required=True)
    result.add_argument("--claude-sha256", required=True)
    result.add_argument("--claude-version", required=True)
    result.add_argument("--credential-env", required=True)
    result.add_argument("--channel-load-spec", required=True)
    result.add_argument("--path-dir", action="append", required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    repo = Path(__file__).resolve().parents[2]
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, check=True, text=True,
        stdout=subprocess.PIPE,
    ).stdout.strip()
    if head != args.source_sha:
        raise ValueError(f"checkout HEAD {head} does not equal reviewed source {args.source_sha}")
    if subprocess.run(["git", "status", "--porcelain"], cwd=repo, check=True,
                      text=True, stdout=subprocess.PIPE).stdout:
        raise ValueError("reviewed source checkout is dirty")

    reject_ambient_configuration(args.credential_env, dict(os.environ))
    tgz = require_exact_file(args.tgz, args.tgz_sha256, "channel tgz")
    claude = require_exact_file(args.claude_bin, args.claude_sha256, "Claude binary")
    observed_version = exact_version(claude)
    if observed_version != args.claude_version:
        raise ValueError(
            f"Claude version {observed_version!r} does not equal reviewed {args.claude_version!r}"
        )
    path_dirs = [Path(path).resolve(strict=True) for path in args.path_dir]
    if any(not path.is_dir() for path in path_dirs):
        raise ValueError("every --path-dir must be an existing directory")

    root = Path(tempfile.mkdtemp(prefix="aweb-channel-name-live-"))
    evidence: dict[str, object]
    try:
        package_root = safe_extract_tgz(tgz, root / "unpacked")
        validate_package_identity(package_root)
        subprocess.run([
            "bash", str(repo / "scripts" / "npm-exact-publish.sh"),
            "inspect-tgz", "--tgz", str(tgz), "--version", "1.7.3",
            "--profile", "channel", "--source-root", str(repo),
        ], cwd=repo, check=True)

        evidence_path = root / "live-evidence.json"
        config_path = root / "live-config.json"
        config_path.write_text(json.dumps({
            "channel_load_spec": args.channel_load_spec,
            "claude_binary": str(claude),
            "claude_sha256": args.claude_sha256,
            "claude_version": observed_version,
            "collision_fixture": str(repo / "scripts" / "e2e" / "fixtures" / "aweb-name-collision-mcp.mjs"),
            "credential_env": args.credential_env,
            "evidence_path": str(evidence_path),
            "expected_source": FINAL_SOURCE,
            "plugin_root": str(package_root),
            "tgz_sha256": args.tgz_sha256,
        }, indent=2) + "\n")
        env = build_allowlisted_env(
            root, args.credential_env, os.environ[args.credential_env], path_dirs, config_path,
        )
        vitest = repo / "channel" / "node_modules" / ".bin" / "vitest"
        if not vitest.is_file():
            raise ValueError("exact channel Vitest is missing; run npm ci before the authorized cell")
        subprocess.run([
            str(vitest), "run", "test/integration.test.ts", "-t", LIVE_TEST_NAME,
        ], cwd=repo / "channel", env=env, check=True)
        evidence = json.loads(evidence_path.read_text())
        required = {
            "child_cleanup_complete": True,
            "server_cleanup_complete": True,
            "collision_initialize_observed": True,
            "plugin_initialize_observed": True,
            "channel_source": FINAL_SOURCE,
        }
        for key, expected in required.items():
            if evidence.get(key) != expected:
                raise ValueError(f"live evidence {key}={evidence.get(key)!r}, expected {expected!r}")
    finally:
        shutil.rmtree(root, ignore_errors=False)
    if root.exists():
        raise RuntimeError(f"targeted cleanup did not remove {root}")
    evidence["harness_cleanup_complete"] = True
    print(f"AWEB_CHANNEL_NAME_LIVE_GREEN {json.dumps(evidence, sort_keys=True)}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.CalledProcessError, tarfile.TarError) as error:
        print(f"REFUSE: {error}", file=sys.stderr)
        raise SystemExit(1)
