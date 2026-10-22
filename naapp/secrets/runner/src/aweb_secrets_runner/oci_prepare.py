"""Daemonless OCI preparation before HPKE; no process execution authority.

The worker still refuses OCI execution. This component owns only public-data
unpacking and a transient template. Its consumer must stop/reap any later job
and empty runtime state before releasing this context.
"""

import asyncio
import json
import os
import re
import secrets
import signal
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import Refused
from .filesystem import FileGuard
from .job_inputs import JobInputs
from .oci_images import ImageStore
from .oci_platform import require_memory_directory, require_runc_environment
from .oci_workspace import remove_private_tree, workspace_lock, write_marker


@dataclass(frozen=True)
class BinaryPin:
    path: Path
    sha256: str

    def check(self) -> Path:
        return FileGuard().pinned_file(self.path, self.sha256, executable=True)


@dataclass(frozen=True, repr=False)
class PreparedBundle:
    directory: Path
    state: Path
    engine: Path
    inputs: JobInputs


def _require(condition: Any) -> None:
    if not condition:
        raise Refused("runner_runtime_unavailable")


def _inside(left: Path, right: Path) -> bool:
    return left.is_relative_to(right) or right.is_relative_to(left)


def _mount_points() -> list[Path]:
    result = []
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        parts = line.split()
        _require(len(parts) >= 6)
        decoded = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), parts[4])
        result.append(Path(decoded))
    return result


def _walk_error(error: OSError) -> None:
    raise error


def _mounts(paths: list[str], workspace: Path) -> list[dict[str, Any]]:
    guard = FileGuard()
    points = _mount_points()
    mounts = []
    for path in paths:
        source = guard.entry(path)
        if _inside(source, workspace):
            raise Refused("oci_mount_invalid")
        # A plain ro recursive bind does not make existing nested mounts ro on
        # every qualified runc/kernel. Refuse that unsupported configuration.
        if any(point != source and point.is_relative_to(source) for point in points):
            raise Refused("oci_mount_invalid")
        if source.is_dir():
            for directory, dirs, files in os.walk(source, onerror=_walk_error, followlinks=False):
                for entry in [*dirs, *files]:
                    guard.entry(Path(directory) / entry)
        mounts.append(
            {
                "destination": path,
                "type": "bind",
                "source": str(source),
                "options": [
                    "rbind" if source.is_dir() else "bind",
                    "ro",
                    "rprivate",
                    "nosuid",
                    "nodev",
                ],
            }
        )
    return mounts


def _mapped(value: Any, mappings: Any) -> bool:
    _require(type(value) is int and value >= 0 and isinstance(mappings, list))
    for mapping in mappings:
        _require(isinstance(mapping, dict))
        _require(
            all(
                type(mapping.get(key)) is int and mapping[key] >= 0
                for key in ("containerID", "hostID", "size")
            )
        )
        if mapping["containerID"] <= value < mapping["containerID"] + mapping["size"]:
            return True
    return False


def _compose(
    configuration: dict[str, Any], inputs: JobInputs, mounts: list[dict[str, Any]]
) -> dict[str, Any]:
    job = inputs.definition
    _require(
        configuration.get("root", {}).get("path") == "rootfs" and not configuration.get("hooks")
    )
    linux = configuration["linux"]
    namespaces = linux["namespaces"]
    _require(isinstance(namespaces, list))
    for required in ("pid", "mount", "user"):
        _require(any(item.get("type") == required and not item.get("path") for item in namespaces))
    process = configuration["process"]
    user = process["user"]
    _require(
        _mapped(user["uid"], linux["uidMappings"]) and _mapped(user["gid"], linux["gidMappings"])
    )
    _require(all(_mapped(gid, linux["gidMappings"]) for gid in user.get("additionalGids", [])))
    process.update(
        args=list(inputs.argv),
        cwd=job["cwd"],
        terminal=False,
        env=[f"{name}={value}" for name, value in inputs.environment.items() if value is not None],
        noNewPrivileges=True,
        capabilities={
            key: [] for key in ("bounding", "effective", "inheritable", "permitted", "ambient")
        },
    )
    # umoci defaults include bind mounts of host /sys and /etc/resolv.conf.
    # No host bind may enter implicitly, even though it is read-only.
    internal = []
    for mount in configuration["mounts"]:
        options = mount.get("options", [])
        if mount.get("type") == "bind" or "bind" in options or "rbind" in options:
            continue
        _require(mount.get("type") in {"proc", "tmpfs", "devpts", "mqueue"})
        internal.append(mount)
    configuration["mounts"] = [*internal, *mounts]
    return configuration


async def _tool(executable: Path, *args: str, accept_failure: bool = False) -> int:
    creation = asyncio.create_task(
        asyncio.create_subprocess_exec(
            str(executable),
            *args,
            env={},
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
            start_new_session=True,
            umask=0o077,
        )
    )
    # Cancellation must not lose a process spawned while the OS/asyncio handoff
    # is finishing. Join that handoff before stopping and reaping its group.
    process = None
    try:
        process = await asyncio.shield(creation)
        async with asyncio.timeout(60):
            code = await process.wait()
            if code != 0 and not accept_failure:
                raise Refused("oci_prepare_failed")
            return code
    finally:
        if process is None:
            process = await creation
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        await asyncio.shield(process.wait())


@dataclass(frozen=True)
class RuncPreparation:
    engine: BinaryPin
    unpacker: BinaryPin
    images: Path
    workspace: Path
    supervisor: BinaryPin | None = None

    @asynccontextmanager
    async def prepare(self, inputs: JobInputs) -> AsyncIterator[PreparedBundle]:
        job = inputs.definition
        _require(job["kind"] == "oci")
        require_runc_environment(inputs.environment)
        engine, unpacker = self.engine.check(), self.unpacker.check()
        supervisor = self.supervisor.check() if self.supervisor else None
        with workspace_lock(self.workspace) as (workspace, parent_fd):
            mounts = _mounts(job["oci"]["read_only_paths"], workspace)
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            name = "job-" + secrets.token_hex(16)
            created = False
            yielding = False
            state = workspace / name / "state"
            try:
                os.mkdir(name, mode=0o700, dir_fd=parent_fd)
                created = True
                work = workspace / name
                work_fd = os.open(name, flags, dir_fd=parent_fd)
                try:
                    write_marker(work_fd, engine=engine, sha256=self.engine.sha256, container=None)
                    os.mkdir("state", mode=0o700, dir_fd=work_fd)
                    require_memory_directory(state)
                    staged = ImageStore(self.images).stage(job["oci"]["image"], work)
                    bundle = work / "bundle"
                    await _tool(
                        unpacker,
                        "unpack",
                        "--rootless",
                        "--image",
                        str(staged.layout) + ":verified",
                        str(bundle),
                    )
                    bundle.chmod(0o700)
                    require_memory_directory(bundle)
                    with FileGuard().open_file(bundle / "config.json") as stream:
                        raw = stream.read(16 * 1024 * 1024 + 1)
                    _require(len(raw) <= 16 * 1024 * 1024)
                    configuration = json.loads(raw)
                    configuration = _compose(configuration, inputs, mounts)
                    bundle_fd = os.open("bundle", flags, dir_fd=work_fd)
                    try:
                        fd = os.open(
                            "config.json",
                            os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW,
                            dir_fd=bundle_fd,
                        )
                        try:
                            os.fchmod(fd, 0o600)
                            with os.fdopen(fd, "wb", closefd=False) as stream:
                                stream.write(
                                    json.dumps(configuration, separators=(",", ":")).encode()
                                )
                        finally:
                            os.close(fd)
                    finally:
                        os.close(bundle_fd)
                    # Tool/filesystem work can wait; recheck pins and mount guards
                    # before this public-only preparation may precede any HPKE.
                    _require(self.engine.check() == engine and self.unpacker.check() == unpacker)
                    if self.supervisor:
                        _require(self.supervisor.check() == supervisor)
                    _require(_mounts(job["oci"]["read_only_paths"], workspace) == mounts)
                    write_marker(
                        work_fd,
                        engine=engine,
                        sha256=self.engine.sha256,
                        container=None,
                        prepared=True,
                    )
                    yielding = True
                    yield PreparedBundle(bundle, state, engine, inputs)
                finally:
                    os.close(work_fd)
            except (OSError, ValueError, KeyError, TypeError, RecursionError):
                if yielding:
                    raise
                raise Refused("oci_prepare_failed") from None
            finally:
                try:
                    if created:
                        if state.exists() and any(state.iterdir()):
                            # Later execution must stop/reap first. Preserve state
                            # for its owner rather than unlink a live container.
                            raise Refused("oci_cleanup_required")
                        remove_private_tree(parent_fd, name)
                except (OSError, RecursionError):
                    raise Refused("oci_cleanup_required") from None
