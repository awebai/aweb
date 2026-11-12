"""Append-only VM ledger transport using the gate's existing tree lease."""

from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import re

from .errors import Infrastructure, Refused


class LedgerLease:
    def __init__(self, path, tree):
        if not re.fullmatch("[0-9a-f]{40}", tree):
            raise Refused("invalid ledger tree identity")
        self.path = Path(path)
        self.tree = tree
        self.handle = None
        self.locks = self.path.parent / "gate-locks"

    def __enter__(self):
        self.locks.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.handle = (self.locks / f"{self.tree}.lock").open("a")
        try:
            fcntl.flock(self.handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self.handle.close()
            self.handle = None
            raise Refused(f"tree {self.tree} is already being gated") from None
        return self

    def __exit__(self, *_):
        if self.handle:
            self.handle.close()
            self.handle = None

    @contextmanager
    def writer(self):
        if self.handle is None:
            raise Infrastructure("ledger transport requires a live tree lease")
        with (self.locks / "vm-gate-writer.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield

    def snapshot(self, destination):
        with self.writer():
            data = self.path.read_bytes() if self.path.exists() else b""
            if data and not data.endswith(b"\n"):
                raise Infrastructure("canonical ledger has an incomplete row")
            with Path(destination).open("xb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            return data

    def import_rows(self, before, remote):
        if not remote.startswith(before):
            raise Infrastructure("VM ledger changed the immutable snapshot prefix")
        delta = remote[len(before) :]
        if delta and not delta.endswith(b"\n"):
            raise Infrastructure("VM ledger has an incomplete row")
        rows = delta.splitlines(keepends=True)
        for row in rows:
            fields = row.rstrip(b"\n").split(b"\t")
            if (
                len(fields) != 10
                or not fields[0].startswith((self.tree + "-").encode())
                or fields[2] not in {b"passed", b"failed"}
            ):
                raise Infrastructure(
                    "VM ledger appended malformed or unrelated-tree rows"
                )
        with self.writer():
            current = self.path.read_bytes() if self.path.exists() else b""
            if not current.startswith(before) or (
                current and not current.endswith(b"\n")
            ):
                raise Infrastructure(
                    "canonical ledger lost snapshot rows or has an incomplete row"
                )
            seen = set(current.splitlines(keepends=True))
            new = []
            for row in rows:
                if row not in seen:
                    new.append(row)
                    seen.add(row)
            # Never replace the file: other trees may append through the source
            # gate. One append write retains those rows without merging snapshots.
            if new:
                fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                try:
                    data = b"".join(new)
                    if os.write(fd, data) != len(data):
                        raise Infrastructure(
                            "short canonical ledger append; inspect retained originals"
                        )
                    os.fsync(fd)
                finally:
                    os.close(fd)
            return len(new)
