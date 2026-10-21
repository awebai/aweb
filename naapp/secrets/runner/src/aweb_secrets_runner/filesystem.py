"""Local user and file checks, independent of the service's approval decision."""

import hashlib
import os
import re
import stat
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO

from .errors import Refused


def require_separate_users(agent_uids: Sequence[int]) -> None:
    if (
        not agent_uids
        or any(type(uid) is not int or uid < 0 for uid in agent_uids)
        or os.geteuid() in agent_uids
        or 0 in agent_uids
    ):
        # Root agents can cross every ordinary Unix user boundary.
        raise Refused("runner_user_unsafe")


class FileGuard:
    def __init__(self) -> None:
        self.uid = os.geteuid()

    def _chain(self, path: Path) -> None:
        nodes = [*reversed(path.parents), path]
        for index, node in enumerate(nodes):
            info = node.lstat()
            if info.st_uid not in {0, self.uid}:
                raise Refused("path_permissions")
            if stat.S_ISLNK(info.st_mode):
                # The parent has already been checked; verify the resolved target below.
                continue
            sticky_parent = (
                index < len(nodes) - 1
                and info.st_uid == 0
                and stat.S_ISDIR(info.st_mode)
                and bool(info.st_mode & stat.S_ISVTX)
            )
            if info.st_mode & 0o022 and not sticky_parent:
                raise Refused("path_permissions")
            if index < len(nodes) - 1 and not stat.S_ISDIR(info.st_mode):
                raise Refused("path_permissions")

    def _resolve(self, path: Path | str, *, directory: bool = False) -> Path:
        try:
            path = Path(path)
            if not path.is_absolute() or ".." in path.parts or "\0" in str(path):
                raise Refused("path_permissions")
            self._chain(path)
            resolved = path.resolve(strict=True)
            self._chain(resolved)
            mode = resolved.stat().st_mode
            if not (stat.S_ISDIR(mode) if directory else stat.S_ISREG(mode)):
                raise Refused("path_permissions")
            return resolved
        except (OSError, ValueError, RuntimeError):
            raise Refused("path_permissions") from None

    def directory(self, path: Path | str) -> Path:
        return self._resolve(path, directory=True)

    def _open(self, path: Path, *, config: bool = False, executable: bool = False) -> int:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid not in {0, self.uid}
            or info.st_mode & 0o022
            or config
            and info.st_uid != self.uid
            or executable
            and not os.access(path, os.X_OK, effective_ids=True)
        ):
            os.close(fd)
            raise Refused("path_permissions")
        return fd

    @contextmanager
    def open_file(self, path: Path | str) -> Iterator[BinaryIO]:
        """Read one protected regular file through the checked handle."""
        try:
            resolved = self._resolve(path)
            stream = os.fdopen(self._open(resolved), "rb")
        except OSError:
            raise Refused("path_permissions") from None
        with stream:
            yield stream

    def read_config(self, path: Path | str) -> bytes:
        try:
            resolved = self._resolve(path)
            with os.fdopen(self._open(resolved, config=True), "rb") as stream:
                raw = stream.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise Refused("config_invalid")
            return raw
        except OSError:
            raise Refused("path_permissions") from None

    def pinned_file(self, path: Path | str, digest: str, *, executable: bool = False) -> Path:
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise Refused("file_pin_mismatch")
        try:
            resolved = self._resolve(path)
            hasher = hashlib.sha256()
            with os.fdopen(self._open(resolved, executable=executable), "rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    hasher.update(chunk)
            if hasher.hexdigest() != digest:
                raise Refused("file_pin_mismatch")
            return resolved
        except OSError:
            raise Refused("path_permissions") from None
