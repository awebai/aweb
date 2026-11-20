"""The publisher's pinned file set: the four package modules and a vendored tree.

The vendored tree is the runtime dependency closure in uv.lock (no dev
dependencies), each package from its one pure-Python wheel. A wheel is
used only when its bytes match uv.lock's hash; it is unpacked, never
installed, so no installer runs and nothing outside the tree is written.
vendor-lock.json pins every wheel and every file it unpacks to; assembly
refuses any difference.

    python3 -I deploy/vendor.py fetch --wheels DIR     # download, verify (network)
    python3 -I deploy/vendor.py lock --wheels DIR      # write deploy/vendor-lock.json
    python3 -I deploy/vendor.py assemble --wheels DIR --root ROOT [--python-version X.Y.Z]
"""

import argparse
import hashlib
import json
import re
import shutil
import sys
import tomllib
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

HERE = Path(__file__).resolve().parent
PACKAGE = HERE.parent
PROJECT = "aweb-provider-folders"
MODULES = ("hashes.py", "onedrive.py", "publisher.py", "replay.py")
LOCK = HERE / "vendor-lock.json"
FETCH_TIMEOUT_S = 60
# The only marker form uv.lock uses for this closure; any other refuses.
MARKER = re.compile(r"python_full_version (<|<=|>|>=|==|!=) '(\d+(?:\.\d+){0,2})'")


class LockError(Exception):
    """The lock, a wheel or a tree does not match what is pinned."""


@dataclass(frozen=True)
class Package:
    name: str
    version: str
    marker: str | None
    url: str
    sha256: str


def runtime_closure(uv_lock: Path) -> list[Package]:
    """The project's runtime dependencies, transitively, sorted by name.

    A package reached only through markered edges keeps its marker; one
    reached with no marker on any path has none. Two different markers for
    one package refuse.
    """
    packages = {p["name"]: p for p in tomllib.loads(uv_lock.read_text())["package"]}
    reached: dict[str, set[str | None]] = {}
    pending = [
        (edge["name"], edge.get("marker")) for edge in packages[PROJECT].get("dependencies", [])
    ]
    while pending:
        name, marker = pending.pop()
        seen = reached.setdefault(name, set())
        if marker in seen:
            continue
        seen.add(marker)
        for edge in packages[name].get("dependencies", []):
            inner = edge.get("marker")
            if marker is not None and inner is not None and inner != marker:
                raise LockError(f"{edge['name']} is reached under nested markers")
            pending.append((edge["name"], inner or marker))
    markers = {}
    for name, seen in reached.items():
        if None in seen:
            markers[name] = None
        elif len(seen) == 1:
            markers[name] = next(iter(seen))
        else:
            raise LockError(f"{name} is reached under two markers")
    closure = []
    for name in sorted(markers):
        wheels = [
            w for w in packages[name].get("wheels", []) if w["url"].endswith("-py3-none-any.whl")
        ]
        if len(wheels) != 1 or not wheels[0]["hash"].startswith("sha256:"):
            raise LockError(f"{name} has no single pure-Python wheel")
        if markers[name] is not None and not MARKER.fullmatch(markers[name]):
            raise LockError(f"{name} has an unsupported marker")
        version = packages[name]["version"]
        closure.append(
            Package(name, version, markers[name], wheels[0]["url"], wheels[0]["hash"][7:])
        )
    return closure


def applies(marker: str | None, python: tuple[int, ...]) -> bool:
    if marker is None:
        return True
    operator, version = MARKER.fullmatch(marker).groups()
    bound = tuple(int(part) for part in version.split("."))
    actual = python[: len(bound)]
    return {
        "<": actual < bound,
        "<=": actual <= bound,
        ">": actual > bound,
        ">=": actual >= bound,
        "==": actual == bound,
        "!=": actual != bound,
    }[operator]


def wheel_name(url: str) -> str:
    return url.rsplit("/", 1)[-1]


def lock_entry(name: str, version: str, marker, url: str, sha256: str, wheel: Path) -> dict:
    return {
        "name": name,
        "version": version,
        "marker": marker,
        "url": url,
        "sha256": sha256,
        "files": [
            {"path": path, "sha256": digest} for path, digest in sorted(_members(wheel).items())
        ],
    }


def fetch(wheels: Path) -> None:
    """Download each wheel of the closure and keep it only if its hash matches."""
    wheels.mkdir(parents=True, exist_ok=True)
    for package in runtime_closure(PACKAGE / "uv.lock"):
        target = wheels / wheel_name(package.url)
        if target.exists() and _sha256(target.read_bytes()) == package.sha256:
            continue
        with urllib.request.urlopen(package.url, timeout=FETCH_TIMEOUT_S) as response:
            data = response.read()
        if _sha256(data) != package.sha256:
            raise LockError(f"{package.name}: downloaded wheel hash differs from uv.lock")
        target.write_bytes(data)


def write_lock(wheels: Path) -> dict:
    entries = []
    for package in runtime_closure(PACKAGE / "uv.lock"):
        wheel = _verified_wheel(wheels, package.url, package.sha256, package.name)
        entries.append(
            lock_entry(
                package.name, package.version, package.marker, package.url, package.sha256, wheel
            )
        )
    lock = {
        "v": 1,
        "uv_lock_sha256": _sha256((PACKAGE / "uv.lock").read_bytes()),
        "wheels": entries,
    }
    LOCK.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n")
    return lock


def assemble(root: Path, lock: dict, wheels: Path, package: Path, python: tuple[int, ...]) -> None:
    """Lay out the pinned tree at root, which must not exist yet."""
    root.mkdir()
    for module in MODULES:
        shutil.copyfile(package / module, root / module)
    for entry in lock["wheels"]:
        if not applies(entry["marker"], python):
            continue
        wheel = _verified_wheel(wheels, entry["url"], entry["sha256"], entry["name"])
        members = _members(wheel)
        if members != {item["path"]: item["sha256"] for item in entry["files"]}:
            raise LockError(f"{entry['name']}: wheel members differ from vendor-lock.json")
        with zipfile.ZipFile(wheel) as archive:
            for path in members:
                target = root / "vendor" / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.read(path))


def installed_files(root: Path) -> dict[str, str]:
    """Every regular file under root, relative path to SHA-256; a link refuses."""
    files = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise LockError(f"{path} is not a regular file or directory")
        if path.is_file():
            files[path.relative_to(root).as_posix()] = _sha256(path.read_bytes())
    return files


def expected_files(lock: dict, package: Path, python: tuple[int, ...]) -> dict[str, str]:
    files = {module: _sha256((package / module).read_bytes()) for module in MODULES}
    for entry in lock["wheels"]:
        if applies(entry["marker"], python):
            files.update({f"vendor/{item['path']}": item["sha256"] for item in entry["files"]})
    return files


def _members(wheel: Path) -> dict[str, str]:
    members = {}
    with zipfile.ZipFile(wheel) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            name = info.filename
            parts = PurePosixPath(name).parts
            if (
                name.startswith("/")
                or "\\" in name
                or ".." in parts
                or any(part.endswith(".data") for part in parts)
            ):
                raise LockError(f"{wheel.name}: unsafe member {name!r}")
            members[name] = _sha256(archive.read(info))
    return members


def _verified_wheel(wheels: Path, url: str, sha256: str, name: str) -> Path:
    path = wheels / wheel_name(url)
    if _sha256(path.read_bytes()) != sha256:
        raise LockError(f"{name}: wheel hash differs from the pin")
    return path


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="vendor.py")
    parser.add_argument("command", choices=("fetch", "lock", "assemble"))
    parser.add_argument("--wheels", required=True, type=Path)
    parser.add_argument("--root", type=Path)
    parser.add_argument("--python-version", default=".".join(map(str, sys.version_info[:3])))
    arguments = parser.parse_args(argv)
    if arguments.command == "fetch":
        fetch(arguments.wheels)
    elif arguments.command == "lock":
        write_lock(arguments.wheels)
    else:
        if arguments.root is None:
            parser.error("assemble needs --root")
        python = tuple(int(part) for part in arguments.python_version.split("."))
        lock = json.loads(LOCK.read_bytes())
        assemble(arguments.root, lock, arguments.wheels, PACKAGE, python)
        if installed_files(arguments.root) != expected_files(lock, PACKAGE, python):
            raise LockError("the assembled tree differs from the pin")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
