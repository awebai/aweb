"""The installed aweb package exposes exact P1 signing-agreement vectors."""
from importlib.resources import files
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "docs/vectors/human-channels-signed-via-v1.json"
RESOURCE = "human-channels-signed-via-v1.json"


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
