"""An Ed25519 signing key from a key file or a configured value.

Key files are read with :func:`aweb_naapp.key_file.read_key_file`, re-exported
here, so there is one set of file checks. Every holder of an app or server
signing key uses one format:

- the key is the 32-byte Ed25519 seed as 64 hex characters (either case), with
  one trailing newline allowed;
- the key file passes :mod:`aweb_naapp.key_file`'s checks.

Errors name the file, never its contents. Imports only the standard library and
pynacl, so the core server can use it without the naapp runtime.
"""

from __future__ import annotations

import re
from pathlib import Path

from nacl.signing import SigningKey

from aweb_naapp.key_file import KeyFileError, read_key_file

__all__ = [
    "KeyFileError",
    "SigningKeyError",
    "parse_signing_key_hex",
    "read_key_file",
    "read_signing_key_file",
]

_SEED_HEX = re.compile(r"[0-9a-fA-F]{64}\n?")


class SigningKeyError(ValueError):
    """A signing key could not be read. The message never carries key material."""


def parse_signing_key_hex(text: str) -> SigningKey:
    """The signing key whose seed ``text`` holds as 64 hex characters."""
    if not _SEED_HEX.fullmatch(text):
        raise SigningKeyError(
            "a signing key must be 64 hex characters, optionally newline-terminated"
        )
    return SigningKey(bytes.fromhex(text.rstrip("\n")))


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
