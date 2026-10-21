"""The hook catalog ships inside naapp-lib, so an installed app loads it with
no repository checkout. The package copy is the public vector's bytes; the
provenance check refuses any difference."""

from __future__ import annotations

import subprocess
import sys
import zipfile
from pathlib import Path

from aweb_naapp.hooks.catalog import load_catalog, packaged_catalog

NAAPP_LIB = Path(__file__).resolve().parents[2]
AWEB_ROOT = NAAPP_LIB.parent
VECTOR = AWEB_ROOT / "docs" / "vectors" / "hook-catalog-v1.json"


def test_the_packaged_catalog_is_the_public_vector() -> None:
    assert packaged_catalog() == load_catalog(VECTOR.read_bytes())


def test_an_installed_wheel_loads_the_catalog_without_a_checkout(tmp_path: Path) -> None:
    # Build with the locked hatchling in this environment, not an isolated one
    # that would fetch the backend: the test then runs offline on a cold cache.
    subprocess.run(
        [
            "uv",
            "build",
            "--wheel",
            "--no-build-isolation",
            "--out-dir",
            str(tmp_path / "dist"),
            str(NAAPP_LIB),
        ],
        capture_output=True,
        check=True,
    )
    (wheel,) = (tmp_path / "dist").glob("aweb_naapp-*.whl")
    installed = tmp_path / "site"
    with zipfile.ZipFile(wheel) as archive:
        archive.extractall(installed)
    # -I -S: no site-packages and no environment, so nothing can come from the
    # checkout; the only aweb_naapp on the path is the unpacked wheel.
    probe = (
        "import sys\n"
        f"sys.path.insert(0, {str(installed)!r})\n"
        "from aweb_naapp.hooks import catalog\n"
        "loaded = catalog.packaged_catalog()\n"
        "print(catalog.__file__)\n"
        "print(','.join(sorted(loaded.hooks)))\n"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-c", probe],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
    )
    module_file, hooks = result.stdout.splitlines()
    assert Path(module_file).is_relative_to(installed)
    assert hooks.split(",") == sorted(packaged_catalog().hooks)
