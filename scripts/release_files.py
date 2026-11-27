#!/usr/bin/env python3
"""The files an aweb release builds once, gates and publishes.

`listing DIR` prints one `sha256:<hex>  <name>` line per file, sorted by name,
after checking that DIR holds exactly one wheel and one sdist per package and
nothing else. `server-wheel DIR` prints the aweb wheel's path, sha256 and
version, one per line, for the federation journey's wheel mode.
"""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

# PyPI distribution name -> the file name prefix its wheel and sdist carry.
PACKAGES = {"aweb": "aweb", "awid-service": "awid_service"}
# PyPI distribution name -> the project directory that builds it.
SOURCE_DIRECTORIES = {"aweb": "server", "awid-service": "awid"}
# PyPI distribution name -> its release tag prefix.
RELEASE_TAGS = {"aweb": "server-v", "awid-service": "awid-service-v"}
# awid-service is published first: aweb requires the in-repo awid-service version.
PUBLICATION_ORDER = ("awid-service", "aweb")
WHEEL, SDIST = "-py3-none-any.whl", ".tar.gz"


class ReleaseFilesRefusal(RuntimeError):
    """The directory is not one release's built files."""


def sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def built_packages(directory: Path) -> dict[str, tuple[str, Path, Path]]:
    """Each package in `directory` with its version, wheel and sdist; nothing else may be there."""
    found: dict[str, tuple[str, Path, Path]] = {}
    claimed: set[Path] = set()
    for name, prefix in PACKAGES.items():
        pattern = re.compile(rf"^{prefix}-([0-9][^-]*?)({re.escape(WHEEL)}|{re.escape(SDIST)})$")
        versions: dict[str, dict[str, Path]] = {}
        for path in sorted(directory.iterdir()):
            match = pattern.match(path.name)
            if match:
                versions.setdefault(match[1], {})[match[2]] = path
        if not versions:
            continue
        if len(versions) != 1:
            raise ReleaseFilesRefusal(f"{name} has more than one version in {directory}")
        [(version, kinds)] = versions.items()
        if set(kinds) != {WHEEL, SDIST}:
            raise ReleaseFilesRefusal(f"{name} {version} needs one wheel and one sdist in {directory}")
        found[name] = (version, kinds[WHEEL], kinds[SDIST])
        claimed.update(kinds.values())
    others = sorted(path.name for path in directory.iterdir() if path not in claimed)
    if others:
        raise ReleaseFilesRefusal(f"{directory} holds files no release builds: {', '.join(others)}")
    for path in claimed:
        if path.is_symlink() or not path.is_file():
            raise ReleaseFilesRefusal(f"{path.name} is not a regular file")
    if not found:
        raise ReleaseFilesRefusal(f"{directory} holds no release files")
    return found


def digests(directory: Path) -> dict[str, str]:
    """name -> sha256:<hex> for every file of the release in `directory`."""
    return {
        path.name: sha256(path)
        for _version, wheel, sdist in built_packages(directory).values()
        for path in (wheel, sdist)
    }


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[0] not in ("listing", "server-wheel"):
        print("usage: release_files.py listing|server-wheel DIR", file=sys.stderr)
        return 2
    action, directory = argv[0], Path(argv[1])
    try:
        if action == "listing":
            for name, digest in sorted(digests(directory).items()):
                print(f"{digest}  {name}")
        else:
            packages = built_packages(directory)
            if "aweb" not in packages:
                raise ReleaseFilesRefusal(f"{directory} holds no aweb server wheel")
            version, wheel, _sdist = packages["aweb"]
            print(wheel.resolve())
            print(sha256(wheel).removeprefix("sha256:"))
            print(version)
    except (ReleaseFilesRefusal, OSError) as error:
        print(f"release files refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
