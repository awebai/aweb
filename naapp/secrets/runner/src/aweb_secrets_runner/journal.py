"""Durable acceptance before execution, shared by concurrent runner processes."""

import os
import sqlite3
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .errors import Refused


class Journal:
    def __init__(self, path: Path):
        self.path = path
        try:
            directory = path.parent.lstat()
            if (
                not stat.S_ISDIR(directory.st_mode)
                or directory.st_uid != os.geteuid()
                or directory.st_mode & 0o077
            ):
                raise Refused("state_permissions")
            fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            try:
                info = os.fstat(fd)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.geteuid()
                    or info.st_mode & 0o077
                    or info.st_nlink != 1
                ):
                    raise Refused("state_permissions")
            finally:
                os.close(fd)
            with self._connect() as connection:
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS dispatches "
                    "(dispatch_id TEXT PRIMARY KEY, expires_at REAL NOT NULL)"
                )
            # Make the newly created directory entry durable as well as SQLite's data.
            directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            raise Refused("state_permissions") from None
        except sqlite3.Error:
            raise Refused("journal_unavailable") from None

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        try:
            connection.execute("PRAGMA synchronous=FULL")
            yield connection
        finally:
            connection.close()

    def accept(self, dispatch_id: str, *, expires_at: float, now: float) -> None:
        if now >= expires_at:
            raise Refused("assignment_expired")
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute("DELETE FROM dispatches WHERE expires_at <= ?", (now,))
                try:
                    connection.execute(
                        "INSERT INTO dispatches VALUES (?, ?)", (dispatch_id, expires_at)
                    )
                except sqlite3.IntegrityError:
                    raise Refused("assignment_replayed") from None
                connection.execute("COMMIT")
        except sqlite3.Error:
            raise Refused("journal_unavailable") from None
