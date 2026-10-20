"""Reading key files, and an Ed25519 signing key from a key file or a configured value.

Every holder of a key file reads it here, so there is one set of file checks.
:func:`read_key_file` returns the raw bytes, which each caller parses; every
holder of an app or server signing key uses one format:

- the key is the 32-byte Ed25519 seed as 64 hex characters (either case), with
  one trailing newline allowed;
- a key file must be a regular file (a symlink to one is followed, as mounted
  secrets are) and must not be group- or world-writable. Read permissions are
  left to the platform, because standard mounted secrets are world-readable
  inside a single-user container. A file over 1 KiB is refused unread.

Errors name the file, never its contents. Imports only the standard library and
pynacl, so the core server can use it without the naapp runtime.
"""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path

from nacl.signing import SigningKey

_SEED_HEX = re.compile(r"[0-9a-fA-F]{64}\n?")
# Far more than a key file holds, so a path to some other file fails fast.
_MAX_KEY_FILE_BYTES = 1024


class KeyFileError(ValueError):
    """A key file could not be read. The message names the file, never its contents."""


class SigningKeyError(ValueError):
    """A signing key could not be read. The message never carries key material."""


def parse_signing_key_hex(text: str) -> SigningKey:
    """The signing key whose seed ``text`` holds as 64 hex characters."""
    if not _SEED_HEX.fullmatch(text):
        raise SigningKeyError(
            "a signing key must be 64 hex characters, optionally newline-terminated"
        )
    return SigningKey(bytes.fromhex(text.rstrip("\n")))


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


def read_signing_key_file(path: Path) -> SigningKey:
    """The signing key held in the key file at ``path``."""
    try:
        content = read_key_file(path)
    except KeyFileError as exc:
        raise SigningKeyError(str(exc)) from None
    try:
        return parse_signing_key_hex(content.decode("ascii"))
    except (UnicodeDecodeError, SigningKeyError):
        raise SigningKeyError(
            f"key file {path} must hold 64 hex characters, optionally newline-terminated"
        ) from None
