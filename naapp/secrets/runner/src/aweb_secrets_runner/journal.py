"""Private durable acceptance and exact-byte report retries."""

import hashlib
import os
import sqlite3
import stat
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from .errors import Refused

MAX_RESULT_BYTES = 6 * 16 * 1024 * 1024 + 1024


@dataclass(frozen=True)
class PendingResult:
    dispatch_id: str
    body: bytes = field(repr=False)


class Journal:
    def __init__(self, path: Path, *, clock: Callable[[], float] = time.time):
        self.path = path
        self.clock = clock
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
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS dispatches "
                    "(dispatch_id TEXT PRIMARY KEY, expires_at REAL NOT NULL,"
                    " result_body BLOB, result_sha256 TEXT, result_acked INTEGER NOT NULL DEFAULT 0)"
                )
                columns = {row[1] for row in connection.execute("PRAGMA table_info(dispatches)")}
                if columns != {
                    "dispatch_id",
                    "expires_at",
                    "result_body",
                    "result_sha256",
                    "result_acked",
                }:
                    raise Refused("journal_version_unsupported")
                connection.execute("COMMIT")
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

    def accept(self, dispatch_id: str, *, expires_at: float) -> None:
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                now = self.clock()
                if now >= expires_at:
                    raise Refused("assignment_expired")
                # A job can outlive assignment expiry without a saved report.
                # Only an explicitly acknowledged result is safe to prune.
                connection.execute(
                    "DELETE FROM dispatches WHERE expires_at <= ? AND result_acked=1", (now,)
                )
                try:
                    connection.execute(
                        "INSERT INTO dispatches (dispatch_id, expires_at) VALUES (?, ?)",
                        (dispatch_id, expires_at),
                    )
                except sqlite3.IntegrityError:
                    raise Refused("assignment_replayed") from None
                connection.execute("COMMIT")
        except sqlite3.Error:
            raise Refused("journal_unavailable") from None

    def save_result(self, dispatch_id: str, body: bytes) -> None:
        """Persist already-sanitized exact report bytes before their first send.

        This is private retry state, not approval or dispatch authority. It is
        valid after assignment expiry because the original job may run longer.
        """
        if not isinstance(body, bytes) or not 0 < len(body) <= MAX_RESULT_BYTES:
            raise Refused("journal_result_invalid")
        digest = hashlib.sha256(body).hexdigest()
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT result_sha256 FROM dispatches WHERE dispatch_id=?", (dispatch_id,)
                ).fetchone()
                if row is None:
                    raise Refused("journal_state_invalid")
                if row[0] is not None and row[0] != digest:
                    raise Refused("journal_result_conflict")
                if row[0] is None:
                    connection.execute(
                        "UPDATE dispatches SET result_body=?, result_sha256=? WHERE dispatch_id=?",
                        (body, digest, dispatch_id),
                    )
                connection.execute("COMMIT")
        except sqlite3.Error:
            raise Refused("journal_unavailable") from None

    def pending_results(self) -> tuple[PendingResult, ...]:
        try:
            with self._connect() as connection:
                rows = connection.execute(
                    "SELECT dispatch_id, result_body FROM dispatches"
                    " WHERE result_body IS NOT NULL AND result_acked=0 ORDER BY dispatch_id"
                ).fetchall()
            return tuple(PendingResult(row[0], row[1]) for row in rows)
        except sqlite3.Error:
            raise Refused("journal_unavailable") from None

    def ack_result(self, dispatch_id: str) -> None:
        """Clear bytes only after the service's durable 204 acknowledgment."""
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT result_sha256 FROM dispatches WHERE dispatch_id=?", (dispatch_id,)
                ).fetchone()
                if row is None or row[0] is None:
                    raise Refused("journal_state_invalid")
                connection.execute(
                    "UPDATE dispatches SET result_body=NULL, result_acked=1 WHERE dispatch_id=?",
                    (dispatch_id,),
                )
                connection.execute("COMMIT")
        except sqlite3.Error:
            raise Refused("journal_unavailable") from None
