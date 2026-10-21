"""Reading a key file: a secret mounted as a file, with one set of checks.

A key file must be a regular file (a symlink to one is followed, as mounted
secrets are) and must not be group- or world-writable. Read permissions are
left to the platform, because standard mounted secrets are world-readable
inside a single-user container. A file over 1 KiB is refused unread.
:func:`read_key_file` returns the raw bytes, which each caller parses.

Errors name the file, never its contents. Imports only the standard library.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

# Far more than a key file holds, so a path to some other file fails fast.
_MAX_KEY_FILE_BYTES = 1024


class KeyFileError(ValueError):
    """A key file could not be read. The message names the file, never its contents."""


def read_key_file(path: Path) -> bytes:
    """The raw contents of the key file at ``path``, after the file checks."""
    try:
        # Non-blocking, so a FIFO at the path is refused rather than waited on.
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    except OSError as exc:
        raise KeyFileError(f"cannot open key file {path}: {exc.strerror}") from None
    try:
        mode = os.fstat(fd).st_mode
        if not stat.S_ISREG(mode):
            raise KeyFileError(f"key file {path} is not a regular file")
        if mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise KeyFileError(f"key file {path} is writable by group or others")
        with os.fdopen(fd, "rb", closefd=False) as file:
            content = file.read(_MAX_KEY_FILE_BYTES + 1)
        if len(content) > _MAX_KEY_FILE_BYTES:
            raise KeyFileError(f"key file {path} is larger than {_MAX_KEY_FILE_BYTES} bytes")
    finally:
        os.close(fd)
    return content
