"""Key-encryption-key files and providers for the custody tests.

Every key here is generated at runtime; none is a real credential."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from aweb_secrets.custody import LocalKeyFileProvider


def write_key_file(path: Path, key: bytes, mode: int = 0o600) -> Path:
    path.write_text(key.hex() + "\n")
    path.chmod(mode)
    return path


@pytest.fixture
def kek_file(tmp_path: Path) -> Path:
    return write_key_file(tmp_path / "kek", os.urandom(32))


@pytest.fixture
def provider(kek_file: Path) -> LocalKeyFileProvider:
    return LocalKeyFileProvider(kek_file)


@pytest.fixture
def canary() -> bytes:
    """A random value sealed as a secret, so leak checks can search for it."""
    return os.urandom(24).hex().encode()
