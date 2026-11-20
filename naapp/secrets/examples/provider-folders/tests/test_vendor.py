"""The vendored dependency pin: its closure, its lock and the assembled tree."""

import hashlib
import json
import subprocess
import zipfile
from pathlib import Path

import pytest

from deploy.vendor import (
    MODULES,
    LockError,
    assemble,
    installed_files,
    lock_entry,
    runtime_closure,
)

HERE = Path(__file__).resolve().parents[1]
UV_LOCK = HERE / "uv.lock"
VENDOR_LOCK = HERE / "deploy" / "vendor-lock.json"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def wheel(directory: Path, name: str, members: dict[str, bytes]) -> tuple[Path, str]:
    path = directory / f"{name}-1.0-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as archive:
        for member, content in members.items():
            archive.writestr(member, content)
    return path, sha256(path.read_bytes())


def lock_for(path: Path, digest: str, name: str, marker=None) -> dict:
    return {
        "v": 1,
        "uv_lock_sha256": "0" * 64,
        "wheels": [
            lock_entry(name, "1.0", marker, f"https://files.invalid/{path.name}", digest, path)
        ],
    }


def test_the_closure_is_what_uv_exports_without_dev_dependencies():
    exported = subprocess.run(
        ["uv", "export", "--frozen", "--no-dev", "--no-emit-project", "--no-header", "--no-hashes"],
        cwd=HERE,
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    ).stdout
    expected = {}
    for line in exported.splitlines():
        if line and not line.startswith(" ") and not line.startswith("#"):
            requirement, _, marker = line.partition(" ; ")
            name, version = requirement.split("==")
            expected[name] = (version, marker.strip() or None)
    closure = runtime_closure(UV_LOCK)
    assert {p.name: (p.version, p.marker) for p in closure} == expected


def test_the_committed_lock_matches_uv_lock_wheel_for_wheel():
    lock = json.loads(VENDOR_LOCK.read_bytes())
    assert lock["uv_lock_sha256"] == sha256(UV_LOCK.read_bytes())
    closure = {p.name: p for p in runtime_closure(UV_LOCK)}
    assert [entry["name"] for entry in lock["wheels"]] == sorted(closure)
    for entry in lock["wheels"]:
        package = closure[entry["name"]]
        assert (entry["version"], entry["marker"], entry["url"], entry["sha256"]) == (
            package.version,
            package.marker,
            package.url,
            package.sha256,
        )
        paths = [item["path"] for item in entry["files"]]
        assert paths == sorted(set(paths)) and paths


def test_a_markered_package_is_assembled_only_where_its_marker_holds(tmp_path):
    path, digest = wheel(tmp_path, "old", {"old/__init__.py": b""})
    lock = lock_for(path, digest, "old", "python_full_version < '3.15'")
    assemble(tmp_path / "a", lock, tmp_path, HERE, (3, 14, 2))
    assemble(tmp_path / "b", lock, tmp_path, HERE, (3, 15, 0))
    assert (tmp_path / "a" / "vendor" / "old" / "__init__.py").exists()
    assert not (tmp_path / "b" / "vendor").exists() or not any(
        (tmp_path / "b" / "vendor").iterdir()
    )


def test_the_assembled_tree_is_the_modules_and_the_locked_files_only(tmp_path):
    path, digest = wheel(
        tmp_path, "dep", {"dep/__init__.py": b"x = 1\n", "dep-1.0.dist-info/METADATA": b"m"}
    )
    root = tmp_path / "install"
    assemble(root, lock_for(path, digest, "dep"), tmp_path, HERE, (3, 13, 0))
    files = installed_files(root)
    assert sorted(files) == sorted(
        [*MODULES, "vendor/dep/__init__.py", "vendor/dep-1.0.dist-info/METADATA"]
    )
    for module in MODULES:
        assert files[module] == sha256((HERE / module).read_bytes())


@pytest.mark.parametrize(
    "members, message",
    [
        ({"/abs.py": b""}, "unsafe member"),
        ({"../up.py": b""}, "unsafe member"),
        ({"dep\\win.py": b""}, "unsafe member"),
        ({"dep-1.0.data/scripts/x": b""}, "unsafe member"),
    ],
)
def test_an_unsafe_wheel_member_refuses(tmp_path, members, message):
    path, digest = wheel(tmp_path, "dep", {"dep/__init__.py": b"", **members})
    # A lock that lists the members as they are: assembly itself must refuse.
    files = [{"path": name, "sha256": sha256(content)} for name, content in members.items()]
    entry = {
        "name": "dep",
        "version": "1.0",
        "marker": None,
        "sha256": digest,
        "files": files,
        "url": f"https://files.invalid/{path.name}",
    }
    lock = {"v": 1, "uv_lock_sha256": "0" * 64, "wheels": [entry]}
    with pytest.raises(LockError, match=message):
        assemble(tmp_path / "install", lock, tmp_path, HERE, (3, 13, 0))
    with pytest.raises(LockError, match=message):
        lock_entry("dep", "1.0", None, entry["url"], digest, path)


def test_a_changed_wheel_or_file_refuses(tmp_path):
    path, digest = wheel(tmp_path, "dep", {"dep/__init__.py": b"x = 1\n"})
    lock = lock_for(path, digest, "dep")
    lock["wheels"][0]["sha256"] = "f" * 64
    with pytest.raises(LockError, match="wheel hash"):
        assemble(tmp_path / "a", lock, tmp_path, HERE, (3, 13, 0))
    lock = lock_for(path, digest, "dep")
    lock["wheels"][0]["files"][0]["sha256"] = "f" * 64
    with pytest.raises(LockError, match="members differ"):
        assemble(tmp_path / "b", lock, tmp_path, HERE, (3, 13, 0))


def test_an_existing_install_root_refuses(tmp_path):
    path, digest = wheel(tmp_path, "dep", {"dep/__init__.py": b""})
    (tmp_path / "install").mkdir()
    with pytest.raises(FileExistsError):
        assemble(tmp_path / "install", lock_for(path, digest, "dep"), tmp_path, HERE, (3, 13, 0))
