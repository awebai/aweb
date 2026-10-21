"""The local key-encryption-key file is read once, at startup, and refused unless it is safe."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from aweb_secrets.custody import KeyFileError, LocalKeyFileProvider

from .conftest import write_key_file


def test_a_private_regular_key_file_loads(kek_file: Path) -> None:
    LocalKeyFileProvider(kek_file)


def test_a_missing_key_file_is_refused(tmp_path: Path) -> None:
    with pytest.raises(KeyFileError):
        LocalKeyFileProvider(tmp_path / "absent")


def test_a_directory_is_refused(tmp_path: Path) -> None:
    with pytest.raises(KeyFileError):
        LocalKeyFileProvider(tmp_path)


def test_a_fifo_is_refused_without_blocking(tmp_path: Path) -> None:
    fifo = tmp_path / "kek"
    os.mkfifo(fifo, 0o600)
    with pytest.raises(KeyFileError):
        LocalKeyFileProvider(fifo)


@pytest.mark.parametrize("mode", [0o620, 0o602, 0o666])
def test_a_key_file_writable_by_others_is_refused(tmp_path: Path, mode: int) -> None:
    path = write_key_file(tmp_path / "kek", os.urandom(32), mode)
    with pytest.raises(KeyFileError):
        LocalKeyFileProvider(path)


def test_a_world_readable_key_file_loads(tmp_path: Path) -> None:
    LocalKeyFileProvider(write_key_file(tmp_path / "kek", os.urandom(32), 0o644))


@pytest.mark.parametrize("key", [os.urandom(16), os.urandom(33)])
def test_a_key_of_the_wrong_length_is_refused(tmp_path: Path, key: bytes) -> None:
    with pytest.raises(KeyFileError):
        LocalKeyFileProvider(write_key_file(tmp_path / "kek", key))


def test_the_refusal_never_carries_the_file_contents(tmp_path: Path) -> None:
    content = os.urandom(20).hex()
    path = tmp_path / "kek"
    path.write_text(content)
    path.chmod(0o600)
    with pytest.raises(KeyFileError) as refused:
        LocalKeyFileProvider(path)
    assert content not in str(refused.value)
    assert content not in repr(refused.value)
