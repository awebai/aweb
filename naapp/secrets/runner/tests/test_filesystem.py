import hashlib
import os

import pytest

from aweb_secrets_runner.filesystem import FileGuard, require_separate_users
from aweb_secrets_runner.protocol import Refused


@pytest.fixture
def guard():
    return FileGuard()


def test_same_os_user_and_privileged_agents_are_refused():
    for uids in ([os.geteuid()], [0], [], [True]):
        with pytest.raises(Refused, match="runner_user_unsafe"):
            require_separate_users(uids)


def test_executable_and_declared_file_pins_are_rehashed_each_time(guard, tmp_path):
    path = tmp_path / "program"
    path.write_bytes(b"fixture-v1")
    path.chmod(0o700)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    assert guard.pinned_file(path, digest, executable=True) == path.resolve()
    path.write_bytes(b"fixture-v2")
    with pytest.raises(Refused, match="file_pin_mismatch"):
        guard.pinned_file(path, digest, executable=True)


@pytest.mark.parametrize("target", ["config", "file", "parent"])
def test_other_user_write_authority_is_refused(guard, tmp_path, target):
    path = tmp_path / "configuration"
    path.write_bytes(b"fixture")
    if target == "parent":
        tmp_path.chmod(0o777)
    else:
        path.chmod(0o666)
    with pytest.raises(Refused, match="path_permissions"):
        if target == "config":
            guard.read_config(path)
        else:
            guard.pinned_file(path, hashlib.sha256(b"fixture").hexdigest())


def test_config_bound_and_directory_kind(guard, tmp_path):
    path = tmp_path / "config.json"
    path.write_bytes(b"{}")
    assert guard.read_config(path) == b"{}"
    path.write_bytes(b" " * (1024 * 1024 + 1))
    with pytest.raises(Refused, match="config_invalid"):
        guard.read_config(path)
    with pytest.raises(Refused, match="path_permissions"):
        guard.directory(path)
    assert guard.directory(tmp_path) == tmp_path.resolve()


def test_trusted_symlink_target_is_hashed_and_cannot_hide_an_unsafe_target(guard, tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"fixture")
    link = tmp_path / "link"
    link.symlink_to(target)
    digest = hashlib.sha256(b"fixture").hexdigest()
    assert guard.pinned_file(link, digest) == target.resolve()
    target.chmod(0o666)
    with pytest.raises(Refused, match="path_permissions"):
        guard.pinned_file(link, digest)


def test_nonexecutable_and_special_file_refuse_without_blocking(guard, tmp_path):
    path = tmp_path / "file"
    path.write_bytes(b"fixture")
    path.chmod(0o600)
    with pytest.raises(Refused, match="path_permissions"):
        guard.pinned_file(path, hashlib.sha256(b"fixture").hexdigest(), executable=True)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo, 0o600)
    with pytest.raises(Refused, match="path_permissions"):
        guard.pinned_file(fifo, "0" * 64)


def test_relative_and_parent_traversal_paths_refuse(guard, tmp_path):
    for path in ("relative", str(tmp_path / ".." / "file")):
        with pytest.raises(Refused, match="path_permissions"):
            guard.pinned_file(path, "0" * 64)
