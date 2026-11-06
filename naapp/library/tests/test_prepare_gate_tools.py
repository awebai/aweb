import hashlib
import io
import tarfile
from pathlib import Path

import pytest

from scripts import prepare_gate_tools as setup


def test_verified_archive_extraction_refuses_wrong_bytes_and_traversal(tmp_path):
    archive = tmp_path / "fixture.tgz"
    with tarfile.open(archive, "w:gz") as tar:
        member = tarfile.TarInfo("package/bin/tool")
        member.size = 4
        tar.addfile(member, io.BytesIO(b"tool"))
    with pytest.raises(setup.SetupError):
        setup.extract_verified(archive, tmp_path / "bad", "0" * 64)
    assert not (tmp_path / "bad").exists()
    setup.extract_verified(
        archive, tmp_path / "good", hashlib.sha256(archive.read_bytes()).hexdigest()
    )
    assert (tmp_path / "good/package/bin/tool").read_bytes() == b"tool"
    with tarfile.open(archive, "w:gz") as tar:
        member = tarfile.TarInfo("../../escape")
        member.size = 4
        tar.addfile(member, io.BytesIO(b"oops"))
    with pytest.raises((setup.SetupError, tarfile.FilterError)):
        setup.extract_verified(
            archive, tmp_path / "escape", hashlib.sha256(archive.read_bytes()).hexdigest()
        )
    assert not (tmp_path / "escape").is_file()


def test_gate_tool_root_is_required_absolute_and_private(tmp_path):
    with pytest.raises(setup.SetupError):
        setup.require_tool_root(Path("relative"))
    root = tmp_path / "tools"
    root.mkdir(mode=0o700)
    assert setup.require_tool_root(root) == root
    root.chmod(0o755)
    with pytest.raises(setup.SetupError):
        setup.require_tool_root(root)


def test_pi_verification_covers_runtime_files_beyond_tiny_entry(tmp_path, monkeypatch):
    import json

    root = tmp_path / "tools"
    root.mkdir(mode=0o700)
    package = root / "pi/package"
    package.mkdir(parents=True)
    entry = package / "cli.js"
    entry.write_text("import './runtime.js';")
    runtime = package / "runtime.js"
    runtime.write_text("real runtime")
    manifest = tmp_path / "pins.json"
    manifest.write_text(json.dumps({"artifacts": {"pi": {
        "member": "package/cli.js", "sha256": hashlib.sha256(entry.read_bytes()).hexdigest(),
        "tree_sha256": setup.tree_digest(package)}}}))
    monkeypatch.setattr(setup, "MANIFEST", manifest)
    assert setup.verify_tools(root)["pi"] == entry
    runtime.write_text("changed runtime")
    with pytest.raises(setup.SetupError):
        setup.verify_tools(root)
