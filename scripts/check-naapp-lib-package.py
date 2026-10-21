#!/usr/bin/env python3
"""Build aweb-naapp's release artifacts and check them as a consumer sees them.

- The wheel ships every non-Python file of the package source.
- Its metadata names no path, file or VCS dependency, and every awid-service
  requirement has a floor the in-repo awid satisfies.
- aweb-naapp with every extra installs from the built wheel into a fresh
  environment, awid-service resolved from the in-repo awid's built wheel and
  everything else from the package index, and every module imports.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
import tomllib
import zipfile
from email import message_from_bytes
from email.message import Message
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NAAPP_LIB = ROOT / "naapp-lib"
AWID = ROOT / "awid"
PACKAGE = "aweb_naapp"
_DIRECT_REFERENCE = re.compile(r"@\s*(file:|git\+|https?:|\.|/)")


class PackageRefusal(Exception):
    pass


def _version(pyproject: Path) -> tuple[int, ...]:
    version = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]["version"]
    return tuple(int(part) for part in version.split("."))


def _build(project: Path, out_dir: Path) -> Path:
    subprocess.run(
        ["uv", "build", "--sdist", "--wheel", "--out-dir", str(out_dir), str(project)],
        check=True, capture_output=True, text=True,
    )
    wheels = sorted(out_dir.glob("*.whl"))
    if len(wheels) != 1 or len(list(out_dir.glob("*.tar.gz"))) != 1:
        raise PackageRefusal(f"expected one wheel and one sdist from {project.name}")
    return wheels[0]


def _check_contents(wheel: Path) -> None:
    source = NAAPP_LIB / "src"
    expected = {
        path.relative_to(source).as_posix()
        for path in source.rglob("*")
        if path.is_file() and path.suffix != ".py" and "__pycache__" not in path.parts
    }
    shipped = set(zipfile.ZipFile(wheel).namelist())
    missing = sorted(expected - shipped)
    if missing:
        raise PackageRefusal(f"the wheel does not ship package files: {', '.join(missing)}")


def _metadata(wheel: Path) -> Message:
    with zipfile.ZipFile(wheel) as archive:
        name = next(n for n in archive.namelist() if n.endswith(".dist-info/METADATA"))
        return message_from_bytes(archive.read(name))


def _check_requirements(metadata: Message) -> None:
    awid_version = _version(AWID / "pyproject.toml")
    for requirement in metadata.get_all("Requires-Dist") or []:
        if _DIRECT_REFERENCE.search(requirement):
            raise PackageRefusal(f"the wheel requires a direct reference: {requirement}")
        name = re.split(r"[\s<>=!~;\[(]", requirement, maxsplit=1)[0]
        if name != "awid-service":
            continue
        floor = re.search(r">=\s*([0-9]+(?:\.[0-9]+)*)", requirement)
        if floor is None:
            raise PackageRefusal(f"awid-service needs a floor: {requirement}")
        if tuple(int(part) for part in floor.group(1).split(".")) > awid_version:
            raise PackageRefusal(
                f"awid-service floor {floor.group(1)} is newer than the in-repo awid "
                f"{'.'.join(map(str, awid_version))}: {requirement}"
            )


def _modules() -> list[str]:
    source = NAAPP_LIB / "src"
    modules = []
    for path in sorted((source / PACKAGE).rglob("*.py")):
        parts = list(path.relative_to(source).with_suffix("").parts)
        if parts[-1] == "__init__":
            parts.pop()
        if parts[-1] != "__main__":
            modules.append(".".join(parts))
    return modules


def _check_install(wheel: Path, awid_dist: Path, metadata: Message) -> None:
    extras = ",".join(sorted(metadata.get_all("Provides-Extra") or []))
    probe = "import importlib\nfor name in %r:\n    importlib.import_module(name)\n" % (_modules(),)
    result = subprocess.run(
        ["uv", "run", "--isolated", "--no-project", "--find-links", str(awid_dist),
         "--with", f"{wheel}[{extras}]", "python", "-c", probe],
        capture_output=True, text=True, cwd=tempfile.gettempdir(),
    )
    if result.returncode != 0:
        raise PackageRefusal(f"aweb-naapp[{extras}] does not install and import from its wheel:\n{result.stderr}")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="naapp-lib-package-") as temporary:
        out = Path(temporary)
        try:
            wheel = _build(NAAPP_LIB, out / "naapp-lib")
            _check_contents(wheel)
            metadata = _metadata(wheel)
            _check_requirements(metadata)
            _build(AWID, out / "awid")
            _check_install(wheel, out / "awid", metadata)
        except PackageRefusal as refused:
            print(f"check-naapp-lib-package: {refused}", file=sys.stderr)
            return 1
        except subprocess.CalledProcessError as failed:
            print(f"check-naapp-lib-package: {' '.join(failed.cmd)} failed:\n{failed.stderr}", file=sys.stderr)
            return 1
    print(f"check-naapp-lib-package: {wheel.name} ships its files, pins awid-service and installs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
