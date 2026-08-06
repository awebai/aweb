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
import signal
import subprocess
import sys
import time
import tarfile
import tempfile

FINAL_MCP_NAME = "aweb-channel"
FINAL_SOURCE = "plugin:aweb-channel:aweb-channel"
APPROVED_CREDENTIAL_ENV_NAMES = frozenset({
    "ANTHROPIC_API_KEY",
    "CLAUDE_CODE_OAUTH_TOKEN",
})
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


def require_approved_credential_env(credential_env: str) -> None:
    if credential_env not in APPROVED_CREDENTIAL_ENV_NAMES:
        approved = ", ".join(sorted(APPROVED_CREDENTIAL_ENV_NAMES))
        raise ValueError(
            f"credential selector must name an approved credential variable ({approved})"
        )


def reject_ambient_configuration(credential_env: str, environ: dict[str, str]) -> None:
    require_approved_credential_env(credential_env)
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


def start_owned_process_group(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
) -> subprocess.Popen[bytes]:
    return subprocess.Popen(command, cwd=cwd, env=env, start_new_session=True)


def process_group_exists(process_group_id: int) -> bool:
    try:
        os.killpg(process_group_id, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def list_process_group_members(process_group_id: int) -> list[dict[str, object]]:
    output = subprocess.run(
        ["/bin/ps", "-ww", "-axo", "pid=,pgid=,command="],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        env={"PATH": os.defpath},
    ).stdout
    members: list[dict[str, object]] = []
    for line in output.splitlines():
        fields = line.strip().split(maxsplit=2)
        if len(fields) != 3 or not fields[0].isdigit() or not fields[1].isdigit():
            continue
        if int(fields[1]) == process_group_id:
            members.append({"pid": int(fields[0]), "command": fields[2]})
    return members


def cleanup_owned_process_group(
    runner: subprocess.Popen[bytes],
    *,
    term_grace_seconds: float = 5.0,
) -> dict[str, object]:
    process_group_id = runner.pid
    members: list[dict[str, object]] = []
    observation_failure: BaseException | None = None
    try:
        members = list_process_group_members(process_group_id)
    except BaseException as error:
        observation_failure = error
    sigkill_required = False
    if process_group_exists(process_group_id):
        try:
            os.killpg(process_group_id, signal.SIGTERM)
        except ProcessLookupError:
            pass
        if not wait_for_process_group_exit(process_group_id, term_grace_seconds):
            sigkill_required = True
            try:
                os.killpg(process_group_id, signal.SIGKILL)
            except ProcessLookupError:
                pass
            if not wait_for_process_group_exit(process_group_id, 10.0):
                raise RuntimeError(
                    f"owned runner process group {process_group_id} survived SIGKILL: "
                    f"{list_process_group_members(process_group_id)!r}"
                )
    try:
        runner.wait(timeout=1)
    except subprocess.TimeoutExpired:
        pass
    surviving = [
        member["pid"] for member in members
        if isinstance(member["pid"], int) and pid_exists(member["pid"])
    ]
    if surviving:
        raise RuntimeError(f"owned runner PIDs survived cleanup: {surviving!r}")
    if observation_failure is not None:
        raise RuntimeError(
            "could not record owned runner process group before cleanup"
        ) from observation_failure
    return {
        "observed_pids": [member["pid"] for member in members],
        "process_group_id": process_group_id,
        "sigkill_required": sigkill_required,
        "termination_proven": True,
    }


def wait_for_process_group_exit(process_group_id: int, timeout_seconds: float) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if not process_group_exists(process_group_id):
            return True
        time.sleep(0.025)
    return not process_group_exists(process_group_id)


def pid_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def docker_project_resource_ids(
    docker: Path,
    project_name: str,
    docker_env: dict[str, str],
) -> dict[str, list[str]]:
    label = f"label=com.docker.compose.project={project_name}"
    commands = {
        "containers": [str(docker), "ps", "-aq", "--filter", label],
        "networks": [str(docker), "network", "ls", "-q", "--filter", label],
        "volumes": [str(docker), "volume", "ls", "-q", "--filter", label],
    }
    return {
        kind: subprocess.run(
            command, check=True, text=True, stdout=subprocess.PIPE, env=docker_env
        ).stdout.split()
        for kind, command in commands.items()
    }


def cleanup_compose_project(
    docker: Path,
    project_name: str,
    docker_env: dict[str, str],
) -> dict[str, object]:
    observed = docker_project_resource_ids(docker, project_name, docker_env)
    removals = (
        ("containers", [str(docker), "rm", "-f"]),
        ("networks", [str(docker), "network", "rm"]),
        ("volumes", [str(docker), "volume", "rm"]),
    )
    failures: list[BaseException] = []
    for kind, command in removals:
        if observed[kind]:
            try:
                subprocess.run([*command, *observed[kind]], check=True, env=docker_env)
            except BaseException as error:
                failures.append(error)
    remaining: dict[str, list[str]] = {}
    try:
        remaining = docker_project_resource_ids(docker, project_name, docker_env)
    except BaseException as error:
        failures.append(error)
    if failures or any(remaining.values()):
        detail = f"; removal errors: {[str(error) for error in failures]!r}" if failures else ""
        raise RuntimeError(
            f"Compose project {project_name} cleanup is ambiguous: {remaining!r}{detail}"
        ) from (failures[0] if failures else None)
    return {
        "compose_project": project_name,
        "observed_resources": observed,
        "termination_proven": True,
    }


def cleanup_supervised_resources(
    runner: subprocess.Popen[bytes] | None,
    docker: Path,
    compose_project: str,
    docker_env: dict[str, str],
    integration_root: Path,
) -> tuple[dict[str, object] | None, dict[str, object]]:
    process_proof: dict[str, object] | None = None
    compose_proof: dict[str, object] | None = None
    failures: list[BaseException] = []
    if runner is not None:
        try:
            process_proof = cleanup_owned_process_group(runner)
        except BaseException as error:
            failures.append(error)
    try:
        compose_proof = cleanup_compose_project(docker, compose_project, docker_env)
    except BaseException as error:
        failures.append(error)
    if not failures:
        try:
            shutil.rmtree(integration_root, ignore_errors=False)
        except FileNotFoundError:
            pass
        except BaseException as error:
            failures.append(error)
        if integration_root.exists():
            failures.append(
                RuntimeError(f"supervised integration root survived cleanup: {integration_root}")
            )
    if failures:
        raise RuntimeError(
            "supervisor cleanup failed: " + "; ".join(str(error) for error in failures)
        ) from failures[0]
    if compose_proof is None:
        raise RuntimeError("supervisor Compose cleanup proof is incomplete")
    return process_proof, compose_proof


def supervised_project_name(root: Path) -> str:
    suffix = hashlib.sha256(str(root).encode()).hexdigest()[:16]
    return f"aweb-channel-name-live-{suffix}"


class RunnerSignalGuard:
    handled = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)

    def __init__(self) -> None:
        self.previous: dict[signal.Signals, object] = {}

    def __enter__(self) -> "RunnerSignalGuard":
        self.previous = {signum: signal.getsignal(signum) for signum in self.handled}
        for signum in self.handled:
            signal.signal(signum, self._interrupted)
        return self

    def protect_cleanup(self) -> None:
        for signum in self.handled:
            signal.signal(signum, signal.SIG_IGN)

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        for signum, handler in self.previous.items():
            signal.signal(signum, handler)

    @staticmethod
    def _interrupted(signum: int, _frame: object) -> None:
        raise RuntimeError(f"live runner interrupted by signal {signum}")


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
    require_approved_credential_env(credential_env)
    locations = {
        "HOME": root / "runner-home",
        "CLAUDE_CONFIG_DIR": root / "runner-claude-config",
        "XDG_CONFIG_HOME": root / "runner-xdg-config",
        "XDG_CACHE_HOME": root / "runner-xdg-cache",
        "XDG_STATE_HOME": root / "runner-xdg-state",
        "TMPDIR": root / "runner-tmp",
        "DOCKER_CONFIG": root / "runner-docker-config",
    }
    for path in locations.values():
        path.mkdir(parents=True, exist_ok=True)
    return {
        **{name: str(path) for name, path in locations.items()},
        "PATH": os.pathsep.join(str(path) for path in path_dirs),
        credential_env: credential,
        "AWEB_CHANNEL_NAME_LIVE_CONFIG": str(live_config),
        "AWEB_CHANNEL_LIVE_INTEGRATION_ROOT": str(locations["TMPDIR"] / "channel-e2e-supervised"),
        "AWEB_SKEW_PROJECT_TOKEN": supervised_project_name(root),
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--source-sha", required=True)
    result.add_argument("--tgz", required=True)
    result.add_argument("--tgz-sha256", required=True)
    result.add_argument("--claude-bin", required=True)
    result.add_argument("--claude-sha256", required=True)
    result.add_argument("--claude-version", required=True)
    result.add_argument(
        "--credential-env", required=True, choices=sorted(APPROVED_CREDENTIAL_ENV_NAMES)
    )
    result.add_argument("--channel-load-spec", required=True)
    result.add_argument("--path-dir", action="append", required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if os.name != "posix":
        raise ValueError("live harness requires POSIX process-group ownership")
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
    preserve_root = False
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
        docker_name = shutil.which("docker", path=env["PATH"])
        if not docker_name:
            raise ValueError("exact allowlisted PATH lacks docker")
        docker = Path(docker_name).resolve(strict=True)
        docker_env = {
            "DOCKER_CONFIG": env["DOCKER_CONFIG"],
            "HOME": env["HOME"],
            "PATH": env["PATH"],
        }
        integration_root = Path(env["AWEB_CHANNEL_LIVE_INTEGRATION_ROOT"])
        compose_project = env["AWEB_SKEW_PROJECT_TOKEN"]
        resource_plan_path = root / "supervisor-resources.json"
        resource_plan: dict[str, object] = {
            "compose_project": compose_project,
            "integration_root": str(integration_root),
            "runner_process_group_id": None,
        }
        resource_plan_path.write_text(json.dumps(resource_plan, indent=2) + "\n")
        resource_plan_path.chmod(0o600)
        runner: subprocess.Popen[bytes] | None = None
        process_cleanup_proof: dict[str, object] | None = None
        compose_cleanup_proof: dict[str, object] | None = None
        with RunnerSignalGuard() as signal_guard:
            try:
                runner = start_owned_process_group([
                    str(vitest), "run", "test/integration.test.ts", "-t", LIVE_TEST_NAME,
                ], cwd=repo / "channel", env=env)
                resource_plan["runner_process_group_id"] = runner.pid
                resource_plan_path.write_text(json.dumps(resource_plan, indent=2) + "\n")
                resource_plan_path.chmod(0o600)
                returncode = runner.wait()
                if returncode != 0:
                    raise subprocess.CalledProcessError(returncode, runner.args)
            finally:
                signal_guard.protect_cleanup()
                try:
                    process_cleanup_proof, compose_cleanup_proof = cleanup_supervised_resources(
                        runner, docker, compose_project, docker_env, integration_root
                    )
                except BaseException:
                    preserve_root = True
                    raise

        if process_cleanup_proof is None or compose_cleanup_proof is None:
            raise RuntimeError("supervisor cleanup proof is incomplete")
        evidence = json.loads(evidence_path.read_text())
        required = {
            "child_cleanup_complete": True,
            "server_cleanup_complete": True,
            "collision_initialize_observed": True,
            "plugin_initialize_observed": True,
            "process_tree_termination_proven": True,
            "channel_source": FINAL_SOURCE,
        }
        for key, expected in required.items():
            if evidence.get(key) != expected:
                raise ValueError(f"live evidence {key}={evidence.get(key)!r}, expected {expected!r}")
        owned_pids = evidence.get("owned_process_pids")
        if (
            not isinstance(owned_pids, list)
            or len(owned_pids) < 3
            or any(not isinstance(pid, int) or pid <= 0 for pid in owned_pids)
        ):
            raise ValueError(f"live evidence lacks Claude and both MCP process PIDs: {owned_pids!r}")
        evidence["supervisor_process_group"] = process_cleanup_proof
        evidence["supervisor_compose_project"] = compose_cleanup_proof
        evidence["supervisor_integration_root_cleanup_complete"] = True
    finally:
        if preserve_root:
            print(f"REFUSE: preserving cleanup state at {root}", file=sys.stderr)
        else:
            shutil.rmtree(root, ignore_errors=False)
    if root.exists():
        raise RuntimeError(f"targeted cleanup did not remove {root}")
    evidence["harness_cleanup_complete"] = True
    print(f"AWEB_CHANNEL_NAME_LIVE_GREEN {json.dumps(evidence, sort_keys=True)}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError, tarfile.TarError) as error:
        print(f"REFUSE: {error}", file=sys.stderr)
        raise SystemExit(1)
