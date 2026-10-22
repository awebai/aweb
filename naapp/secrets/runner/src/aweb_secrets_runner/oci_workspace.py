"""Exclusive private workspace and public cleanup markers, never run authority."""

import fcntl
import os
import re
import secrets
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .errors import Refused
from .filesystem import FileGuard
from .oci_platform import require_memory_directory
from .protocol import canonical, parse_json

JOB_DIRECTORY = re.compile(r"job-[0-9a-f]{32}")


@contextmanager
def workspace_lock(path: Path) -> Iterator[tuple[Path, int]]:
    """Nonblocking inode lock; no extra file and no inherited descriptor."""
    workspace = require_memory_directory(path)
    try:
        fd = os.open(workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise Refused("oci_state_invalid") from None
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Refused("runner_busy") from None
        yield workspace, fd
    finally:
        os.close(fd)


def write_marker(
    work_fd: int,
    *,
    engine: Path,
    sha256: str,
    container: str | None,
    prepared: bool = False,
    stopped: bool = False,
) -> None:
    """Atomically replace only public cleanup data before any launch or opening."""
    raw = canonical(
        {
            "v": 2,
            "engine": {"path": str(engine), "sha256": sha256},
            "container": container,
            "prepared": prepared,
            "stopped": stopped,
        }
    )
    name = ".run-" + secrets.token_hex(16)
    created = False
    try:
        fd = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=work_fd,
        )
        created = True
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.rename(name, "run.json", src_dir_fd=work_fd, dst_dir_fd=work_fd)
        created = False
        os.fsync(work_fd)
    finally:
        if created:
            os.unlink(name, dir_fd=work_fd)


def read_marker(work: Path) -> dict[str, Any]:
    try:
        with FileGuard().open_file(work / "run.json") as stream:
            info = os.fstat(stream.fileno())
            if (
                info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1
            ):
                raise ValueError("marker mode")
            raw = stream.read(4097)
        if len(raw) > 4096:
            raise ValueError("marker bound")
        value = parse_json(raw)
        if (
            not isinstance(value, dict)
            or set(value) != {"v", "engine", "container", "prepared", "stopped"}
            or type(value["v"]) is not int
            or value["v"] != 2
            or type(value["prepared"]) is not bool
            or type(value["stopped"]) is not bool
        ):
            raise ValueError("marker shape")
        engine, container = value["engine"], value["container"]
        if (
            not isinstance(engine, dict)
            or set(engine) != {"path", "sha256"}
            or not isinstance(engine["path"], str)
            or not Path(engine["path"]).is_absolute()
            or ".." in Path(engine["path"]).parts
            or "\0" in engine["path"]
            or not isinstance(engine["sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", engine["sha256"])
            or container is not None
            and (not isinstance(container, str) or not JOB_DIRECTORY.fullmatch(container))
        ):
            raise ValueError("marker binding")
        return dict(value)
    except (OSError, ValueError, TypeError, RecursionError, Refused):
        raise Refused("oci_recovery_required") from None


def mark_container(work: Path, *, engine: Path, sha256: str, container: str) -> None:
    marker = read_marker(work)
    if (
        not JOB_DIRECTORY.fullmatch(container)
        or not marker["prepared"]
        or marker["container"] is not None
        or marker["engine"] != {"path": str(engine), "sha256": sha256}
    ):
        raise Refused("oci_recovery_required")
    fd = os.open(work, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        write_marker(fd, engine=engine, sha256=sha256, container=container, prepared=True)
    finally:
        os.close(fd)


def remove_private_tree(parent_fd: int, name: str) -> None:
    """Remove our stopped tree without following links, including mode-000 dirs."""
    os.chmod(name, 0o700, dir_fd=parent_fd, follow_symlinks=False)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(name, flags, dir_fd=parent_fd)
    try:
        with os.scandir(fd) as entries:
            for entry in entries:
                if entry.is_dir(follow_symlinks=False):
                    remove_private_tree(fd, entry.name)
                else:
                    os.unlink(entry.name, dir_fd=fd)
    finally:
        os.close(fd)
    os.rmdir(name, dir_fd=parent_fd)


def mark_stopped(work: Path, *, engine: Path, sha256: str, container: str) -> None:
    """Only after the exact launcher is reaped and runtime state is cleared."""
    marker = read_marker(work)
    if (
        not marker["prepared"]
        or marker["container"] != container
        or marker["engine"] != {"path": str(engine), "sha256": sha256}
    ):
        raise Refused("oci_recovery_required")
    fd = os.open(work, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        write_marker(
            fd, engine=engine, sha256=sha256, container=container, prepared=True, stopped=True
        )
    finally:
        os.close(fd)
