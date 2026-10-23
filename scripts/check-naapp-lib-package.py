#!/usr/bin/env python3
"""Build aweb-naapp's release artifacts and check them as a consumer sees them.

The aweb-naapp-vX.Y.Z tag publishes two packages from naapp-lib/: aweb-naapp
and, at the same version, its test support aweb-naapp-testing. For each:

- The wheel ships every non-Python file of the package source.
- Its metadata names no path, file or VCS dependency, every awid-service
  requirement has a floor the in-repo awid satisfies, and aweb-naapp-testing
  requires exactly the aweb-naapp version it is released with.
- With every extra it installs from the built wheel into a fresh environment,
  awid-service and aweb-naapp resolved from their in-repo built wheels and
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
NAAPP_TESTING = NAAPP_LIB / "testing"
AWID = ROOT / "awid"
_DIRECT_REFERENCE = re.compile(r"@\s*(file:|git\+|https?:|\.|/)")


class PackageRefusal(Exception):
    pass


def _version_text(pyproject: Path) -> str:
    return tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]["version"]


def _version(pyproject: Path) -> tuple[int, ...]:
    return tuple(int(part) for part in _version_text(pyproject).split("."))


def _build(project: Path, out_dir: Path) -> Path:
    subprocess.run(
        ["uv", "build", "--sdist", "--wheel", "--out-dir", str(out_dir), str(project)],
        check=True, capture_output=True, text=True,
    )
    wheels = sorted(out_dir.glob("*.whl"))
    if len(wheels) != 1 or len(list(out_dir.glob("*.tar.gz"))) != 1:
        raise PackageRefusal(f"expected one wheel and one sdist from {project.name}")
    return wheels[0]


def _check_contents(project: Path, wheel: Path) -> None:
    source = project / "src"
    expected = {
        path.relative_to(source).as_posix()
        for path in source.rglob("*")
        if path.is_file() and path.suffix != ".py" and "__pycache__" not in path.parts
    }
    shipped = set(zipfile.ZipFile(wheel).namelist())
    missing = sorted(expected - shipped)
    if missing:
        raise PackageRefusal(f"{wheel.name} does not ship package files: {', '.join(missing)}")


def _metadata(wheel: Path) -> Message:
    with zipfile.ZipFile(wheel) as archive:
        name = next(n for n in archive.namelist() if n.endswith(".dist-info/METADATA"))
        return message_from_bytes(archive.read(name))


def _check_requirements(wheel: Path, metadata: Message, *, aweb_naapp_version: str | None) -> None:
    """``aweb_naapp_version``, when given, is the exact aweb-naapp the package must require."""
    awid_version = _version(AWID / "pyproject.toml")
    required_aweb_naapp = False
    for requirement in metadata.get_all("Requires-Dist") or []:
        if _DIRECT_REFERENCE.search(requirement):
            raise PackageRefusal(f"{wheel.name} requires a direct reference: {requirement}")
        name = re.split(r"[\s<>=!~;\[(]", requirement, maxsplit=1)[0]
        if name == "aweb-naapp" and aweb_naapp_version is not None:
            pinned = re.search(r"==\s*([0-9]+(?:\.[0-9]+)*)\s*($|;)", requirement)
            if pinned is None or pinned.group(1) != aweb_naapp_version:
                raise PackageRefusal(
                    f"{wheel.name} must require exactly aweb-naapp=={aweb_naapp_version}: {requirement}"
                )
            required_aweb_naapp = True
        if name != "awid-service":
            continue
        floor = re.search(r">=\s*([0-9]+(?:\.[0-9]+)*)", requirement)
        if floor is None:
            raise PackageRefusal(f"{wheel.name}: awid-service needs a floor: {requirement}")
        if tuple(int(part) for part in floor.group(1).split(".")) > awid_version:
            raise PackageRefusal(
                f"{wheel.name}: awid-service floor {floor.group(1)} is newer than the in-repo awid "
                f"{'.'.join(map(str, awid_version))}: {requirement}"
            )
    if aweb_naapp_version is not None and not required_aweb_naapp:
        raise PackageRefusal(f"{wheel.name} must require aweb-naapp=={aweb_naapp_version}")


def _modules(project: Path) -> list[str]:
    source = project / "src"
    modules = []
    for path in sorted(source.rglob("*.py")):
        parts = list(path.relative_to(source).with_suffix("").parts)
        if parts[-1] == "__init__":
            parts.pop()
        if parts[-1] != "__main__":
            modules.append(".".join(parts))
    return modules


def _check_install(project: Path, wheel: Path, metadata: Message, find_links: list[Path]) -> None:
    extras = ",".join(sorted(metadata.get_all("Provides-Extra") or []))
    requirement = f"{wheel}[{extras}]" if extras else str(wheel)
    probe = "import importlib\nfor name in %r:\n    importlib.import_module(name)\n" % (_modules(project),)
    links = [argument for path in find_links for argument in ("--find-links", str(path))]
    result = subprocess.run(
        ["uv", "run", "--isolated", "--no-project", *links, "--with", requirement, "python", "-c", probe],
        capture_output=True, text=True, cwd=tempfile.gettempdir(),
    )
    if result.returncode != 0:
        raise PackageRefusal(f"{wheel.name}[{extras}] does not install and import from its wheel:\n{result.stderr}")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="naapp-lib-package-") as temporary:
        out = Path(temporary)
        try:
            naapp_version = _version_text(NAAPP_LIB / "pyproject.toml")
            testing_version = _version_text(NAAPP_TESTING / "pyproject.toml")
            if testing_version != naapp_version:
                raise PackageRefusal(
                    f"aweb-naapp-testing {testing_version} must be released at aweb-naapp's version {naapp_version}"
                )
            naapp_wheel = _build(NAAPP_LIB, out / "naapp-lib")
            testing_wheel = _build(NAAPP_TESTING, out / "naapp-testing")
            _build(AWID, out / "awid")
            for project, wheel, pin in (
                (NAAPP_LIB, naapp_wheel, None),
                (NAAPP_TESTING, testing_wheel, naapp_version),
            ):
                _check_contents(project, wheel)
                metadata = _metadata(wheel)
                _check_requirements(wheel, metadata, aweb_naapp_version=pin)
                _check_install(project, wheel, metadata, [out / "awid", out / "naapp-lib"])
        except PackageRefusal as refused:
            print(f"check-naapp-lib-package: {refused}", file=sys.stderr)
            return 1
        except subprocess.CalledProcessError as failed:
            print(f"check-naapp-lib-package: {' '.join(failed.cmd)} failed:\n{failed.stderr}", file=sys.stderr)
            return 1
    print(
        f"check-naapp-lib-package: {naapp_wheel.name} and {testing_wheel.name} ship their files, "
        "pin their dependencies and install"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
