"""A directory as a tar archive and back, for teamctl's backup and restore.

    python state_archive.py pack <source> <archive> <uid> <gid> [<left-out member>...]
    python state_archive.py unpack <archive> <new destination>

Numeric owners, modes and symbolic links are kept: an agent's state holds
OATS homes, whose CLAUDE.md and .claude/skills are links. Every member is
checked before anything is written, on both sides:

- its name is a path inside the archive, named once;
- it is a regular file, a directory, a symbolic link or a hard link to an
  earlier regular file;
- the archive's root, and every member another member lies under, is a
  directory: never a file, and never a link, so extracting never writes
  through a link;
- a link's target is relative and, resolved through the archive's own links,
  stays inside it.

Packing leaves sockets and FIFOs out, each reported, and refuses device files
and links it could not restore, writing no archive. Unpacking writes only to a
destination where nothing is, not even a dangling link, creates links last, and
fails, naming the destination incomplete, if any owner, mode or time cannot be set.
"""

from __future__ import annotations

import os
import stat
import sys
import tarfile
from pathlib import Path, PurePosixPath

# How many links one resolution may follow, as Linux allows.
MAX_LINKS = 40


class Refused(Exception):
    pass


def parts(name: str) -> tuple[str, ...]:
    """A member's name as path parts below the archive's root, "." being the
    root itself; refused when it is absolute or climbs out."""
    if name.startswith("/") or ".." in PurePosixPath(name).parts:
        raise Refused(f"{name}: not a path inside the archive")
    return tuple(part for part in PurePosixPath(name).parts if part != ".")


def resolve(links: dict[tuple[str, ...], str], start: tuple[str, ...], target: str, followed: list[int]) -> tuple[str, ...]:
    """Where a link's target leads from the directory start, following the
    archive's own links; climbing above the root is refused."""
    if target.startswith("/"):
        raise Refused("an absolute link")
    where = list(start)
    for part in PurePosixPath(target).parts:
        if part == ".":
            continue
        if part == "..":
            if not where:
                raise Refused("a link out of the archive")
            where.pop()
            continue
        where.append(part)
        link = links.get(tuple(where))
        if link is not None:
            followed[0] += 1
            if followed[0] > MAX_LINKS:
                raise Refused("a chain of more than 40 links")
            where = list(resolve(links, tuple(where[:-1]), link, followed))
    return tuple(where)


def check(members: list[tarfile.TarInfo]) -> None:
    """Every rule of the module's docstring, over the whole member list."""
    seen: dict[tuple[str, ...], tarfile.TarInfo] = {}
    links: dict[tuple[str, ...], str] = {}
    for member in members:
        path = parts(member.name)
        if path in seen:
            raise Refused(f"{member.name}: named twice")
        if not (member.isreg() or member.isdir() or member.issym() or member.islnk()):
            raise Refused(f"{member.name}: not a regular file, a directory or a link")
        if member.islnk():
            earlier = seen.get(parts(member.linkname))
            if earlier is None or not earlier.isreg():
                raise Refused(f"{member.name}: a hard link to no earlier file")
        if member.issym():
            if not member.linkname:
                raise Refused(f"{member.name}: an empty link")
            links[path] = member.linkname
        seen[path] = member
    root = seen.get(())
    if root is not None and not root.isdir():
        raise Refused(f"{root.name}: the archive's root is not a directory")
    for path, member in seen.items():
        for depth in range(1, len(path)):
            ancestor = "./" + "/".join(path[:depth])
            if path[:depth] in links:
                raise Refused(f"{member.name}: under the link {ancestor}")
            if path[:depth] in seen and not seen[path[:depth]].isdir():
                raise Refused(f"{member.name}: under {ancestor}, which is not a directory")
    for path, target in links.items():
        try:
            resolve(links, path[:-1], target, [0])
        except Refused as refused:
            raise Refused(f"{seen[path].name}: {refused}") from None


def pack(source: Path, archive: Path, left_out: list[str] | None = None) -> list[str]:
    """source as archive, members named "./…"; returns what was left out and
    why. On a refusal the archive is removed."""
    left_out = left_out or []
    findings: list[str] = []

    def kept(info: tarfile.TarInfo) -> tarfile.TarInfo | None:
        if any(info.name == name or info.name.startswith(name + "/") for name in left_out):
            return None
        if info.ischr() or info.isblk():
            raise Refused(f"{info.name}: a device file")
        if info.isfifo():
            findings.append(f"{info.name}: a FIFO, left out")
            return None
        return info

    try:
        with tarfile.open(archive, "w", format=tarfile.PAX_FORMAT) as tar:
            # tarfile cannot represent a socket and skips it unseen: it is
            # reported here, so that it is not left out silently.
            for directory, dirs, files in os.walk(source, followlinks=False):
                for name in (*dirs, *files):
                    path = Path(directory) / name
                    if stat.S_ISSOCK(path.lstat().st_mode):
                        relative = "./" + str(path.relative_to(source))
                        if not any(relative == out or relative.startswith(out + "/") for out in left_out):
                            findings.append(f"{relative}: a socket, left out")
            tar.add(source, arcname=".", recursive=True, filter=kept)
        with tarfile.open(archive) as tar:
            check(tar.getmembers())
    except Refused:
        archive.unlink(missing_ok=True)
        raise
    return sorted(findings)


def unpack(archive: Path, destination: Path) -> None:
    """archive into destination, which must not exist yet; nothing is
    written unless every member passes check. Links are created last."""
    if os.path.lexists(destination):
        raise Refused(f"{destination} exists; a restore writes only where nothing is")
    with tarfile.open(archive) as tar:
        members = tar.getmembers()
        check(members)
        ordered = [member for member in members if not member.issym()] + [member for member in members if member.issym()]
        os.mkdir(destination, 0o700)
        # Every member was checked above: the names, the kinds, the links and
        # the order. The trusted filter keeps the recorded modes and owners,
        # and errorlevel 2 makes a refused owner, mode or time fatal, rather
        # than a restore that reports success with other metadata.
        tar.errorlevel = 2
        try:
            tar.extractall(destination, members=ordered, numeric_owner=True, filter="fully_trusted")
        except (tarfile.TarError, OSError) as error:
            raise Refused(f"{error}; {destination} is incomplete and left for inspection") from None


def main(argv: list[str]) -> int:
    try:
        if argv[:1] == ["pack"] and len(argv) >= 5:
            source, archive, uid, gid, *left_out = argv[1:]
            for finding in pack(Path(source), Path(archive), left_out):
                print(f"teamctl: {finding}", file=sys.stderr)
            os.chown(archive, int(uid), int(gid))
            os.chmod(archive, 0o400)
            return 0
        if argv[:1] == ["unpack"] and len(argv) == 3:
            if os.geteuid() != 0:
                # Unprivileged, tarfile skips the numeric owners without a word.
                raise Refused("unpack runs as root, so that every numeric owner is restored")
            unpack(Path(argv[1]), Path(argv[2]))
            return 0
    except Refused as refused:
        print(f"teamctl: {refused}", file=sys.stderr)
        return 1
    print((__doc__ or "").split("\n\n")[1], file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
