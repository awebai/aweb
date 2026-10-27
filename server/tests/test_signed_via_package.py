"""The installed aweb package exposes exact P1 signing-agreement vectors."""
from importlib.resources import files
from pathlib import Path
import os
import shutil
import subprocess
import sys
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "docs/vectors/human-channels-signed-via-v1.json"
RESOURCE = "human-channels-signed-via-v1.json"


def test_current_awid_allows_package_import(tmp_path):
    result = subprocess.run([sys.executable, "-I", "-c", """
import aweb
from awid.signing import validate_message_via
assert validate_message_via('telegram') == 'telegram'
"""], cwd=tmp_path, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_incompatible_awid_is_rejected_before_loading_server(tmp_path):
    """Exercise a real published wheel, without changing the installed AWID.

    Release probes set AW_TEST_INCOMPATIBLE_AWID_WHEEL to the downloaded
    0.5.33rc1 (or 0.5.33 final) artifact. No substitute signing module is used.
    """
    wheel_path = os.environ.get("AW_TEST_INCOMPATIBLE_AWID_WHEEL")
    if not wheel_path:
        pytest.skip("set AW_TEST_INCOMPATIBLE_AWID_WHEEL to a published pre-P1 wheel")
    wheel = Path(wheel_path).resolve(strict=True)
    with zipfile.ZipFile(wheel) as archive:
        metadata = archive.read("awid_service-" + wheel.name.split("-")[1] + ".dist-info/METADATA")
    assert any(b"Version: " + version in metadata.splitlines()
               for version in (b"0.5.33rc1", b"0.5.33"))
    script = """
import sys
sys.path.insert(0, sys.argv[1])
import awid.signing
assert awid.signing.__file__.startswith(sys.argv[1]), awid.signing.__file__
assert not hasattr(awid.signing, 'validate_message_via')
import aweb
"""
    result = subprocess.run([sys.executable, "-I", "-c", script, str(wheel)],
                            cwd=tmp_path, capture_output=True, text=True)
    assert result.returncode != 0, "aweb imported with the incompatible released AWID"
    assert "ImportError" in result.stderr, result.stderr
    assert "awid-service>=0.5.34rc1" in result.stderr, result.stderr
    assert "validate_message_via" in result.stderr, result.stderr


def test_packaged_signing_vectors_are_exact_public_bytes():
    assert files("aweb.human_channels").joinpath(RESOURCE).read_bytes() == SOURCE.read_bytes()


def test_built_wheel_loads_vectors_without_repository_checkout(tmp_path):
    uv = shutil.which("uv")
    assert uv, "uv is required for the real wheel packaging proof"
    subprocess.run([uv, "build", "--wheel", "--out-dir", str(tmp_path)], cwd=ROOT / "server",
                   check=True, capture_output=True, text=True)
    [wheel] = tmp_path.glob("aweb-*.whl")
    installed = tmp_path / "installed"
    with zipfile.ZipFile(wheel) as archive:
        archive.extractall(installed)
    script = '''import importlib.resources, pathlib, sys
sys.path.insert(0, sys.argv[1])
import aweb.human_channels
assert pathlib.Path(aweb.human_channels.__file__).is_relative_to(pathlib.Path(sys.argv[1]))
sys.stdout.buffer.write(importlib.resources.files("aweb.human_channels").joinpath("human-channels-signed-via-v1.json").read_bytes())
'''
    result = subprocess.run([sys.executable, "-I", "-c", script, str(installed)], cwd=tmp_path,
                            check=True, capture_output=True)
    assert result.stdout == SOURCE.read_bytes()
