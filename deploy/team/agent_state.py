"""One agent state (TEAM_STATE_DIR, bound at /state) as an age-encrypted
backup and back, on a host, as root, with the agent's container stopped:

    python3 -I agent_state.py capture --state DIR --container NAME \\
        --age PATH --age-sha256 HEX --recipients FILE --out NEW_DIR
    python3 -I agent_state.py restore --backup DIR --container NAME \\
        --age PATH --age-sha256 HEX --identity FILE --target NEW_DIR

Only the agent's state: no database, no Secrets or Logs, no harness login
and no provider credential, which live outside it. A restore of a team's
databases stays refused (teamctl restore).

capture refuses unless the named container is absent or stopped (the fence
on the writer). It walks the state once to an inventory, checks every member
as deploy/team/state_archive.py does, and streams the archive straight into
age, encrypted to the public recipients: no plaintext archive is written.
Sockets the declared rules name are left out, each recorded in the manifest
with its rule (aw's daemons create them again when they start); any other
socket or FIFO refuses the capture. Links come after every other member.

restore copies the ciphertext into a private directory and checks it against
the manifest's digest, decrypts it once to check every member and the count
before anything is written, then decrypts it again into a target where
nothing is, comparing each member with the checked one. It refuses unless
no container with the given name exists on this host.

Encryption does not protect the state on its source host: whoever is root
there reads it in place. The identity (age private key) belongs off the
source host and on the restore host only for the restore.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))

from state_archive import Refused, check, parts  # noqa: E402

# The endpoints aw's daemons create in the state and create again when they
# start (aw cli/go/internal/custodypath, cli/go/wake/store.go): a socket at
# exactly these places is left out and recorded; nothing else is.
DECLARED = (
    ("aw custody socket", lambda path: path[-2:] == ("run", "custody.sock")),
    ("aw wake broker control socket",
     lambda path: path[:4] == ("home", ".config", "aw", "wake") and path[-1] == "control.sock"),
)


def endpoint(path: tuple[str, ...]) -> str | None:
    for reason, matches in DECLARED:
        if matches(path):
            return reason
    return None


def inventory(root: Path) -> tuple[list[tuple[Path, str]], list[dict]]:
    """The members in stream order (the root, every directory before what it
    holds, links last) and the declared omissions; refused for an undeclared
    socket or FIFO, or a device file."""
    others: list[tuple[Path, str]] = [(root, ".")]
    links: list[tuple[Path, str]] = []
    omitted: list[dict] = []
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs.sort()
        for name in sorted((*dirs, *files)):
            path = Path(directory) / name
            relative = path.relative_to(root)
            mode = path.lstat().st_mode
            if stat.S_ISSOCK(mode) or stat.S_ISFIFO(mode):
                kind = "socket" if stat.S_ISSOCK(mode) else "FIFO"
                reason = endpoint(relative.parts) if kind == "socket" else None
                if reason is None:
                    raise Refused(f"{relative}: a {kind} no declared rule recreates")
                omitted.append({"path": str(relative), "type": kind, "reason": reason})
            elif stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
                raise Refused(f"{relative}: a device file")
            elif stat.S_ISLNK(mode):
                links.append((path, f"./{relative}"))
            else:
                others.append((path, f"./{relative}"))
    return others + links, sorted(omitted, key=lambda entry: entry["path"])


def capture(root: Path, sink: BinaryIO) -> dict:
    """root as a checked tar stream written to sink; returns the inventory
    the manifest records."""
    members, omitted = inventory(root)
    with tarfile.open(fileobj=Discard(), mode="w", format=tarfile.PAX_FORMAT) as probe:
        planned = [probe.gettarinfo(path, arcname) for path, arcname in members]
    check(planned)
    with tarfile.open(fileobj=sink, mode="w|", format=tarfile.PAX_FORMAT) as tar:
        for (path, arcname), expected in zip(members, planned):
            info = tar.gettarinfo(path, arcname)
            if (info.type, info.size, info.mtime, info.linkname) != (expected.type, expected.size, expected.mtime,
                                                                      expected.linkname):
                raise Refused(f"{arcname} changed during the capture; is the writer stopped?")
            if info.isreg():
                with open(path, "rb") as data:
                    tar.addfile(info, data)
            else:
                tar.addfile(info)
    return {"members": len(planned), "omitted": omitted}


class Discard:
    """A sink that keeps nothing: the inventory's TarFile only computes headers."""

    def write(self, data: bytes) -> int:
        return len(data)

    def tell(self) -> int:
        return 0


def signature(member: tarfile.TarInfo) -> tuple:
    return (member.name, member.type, member.linkname, member.size, member.mode, member.uid, member.gid, member.mtime)


def restore(read: Callable[[], BinaryIO], target: Path, count: int) -> int:
    """The stream read() gives, checked whole, then written into target;
    read() is called twice and must give the same stream both times."""
    if os.path.lexists(target):
        raise Refused(f"{target} exists; a restore writes only where nothing is")
    stream = read()
    with tarfile.open(fileobj=stream, mode="r|") as tar:
        checked = [member for member in tar]
    stream.close()
    if len(checked) != count:
        raise Refused(f"{len(checked)} members, not the {count} the manifest records")
    check(checked)
    seen_link = False
    for member in checked:
        if member.issym():
            seen_link = True
        elif seen_link:
            raise Refused(f"{member.name}: after a link; every link comes last")
    expected = {member.name: signature(member) for member in checked}
    written: set[str] = set()

    # tarfile calls the filter for each member, and once more for a
    # directory when it sets the directory's own attributes at the end.
    def same(member: tarfile.TarInfo, path: str) -> tarfile.TarInfo:
        if expected.get(member.name) != signature(member):
            raise Refused(f"the second read differs from the checked one at {member.name}; {target} is incomplete")
        written.add(member.name)
        return tarfile.fully_trusted_filter(member, path)

    os.mkdir(target, 0o700)
    stream = read()
    with tarfile.open(fileobj=stream, mode="r|") as tar:
        # Every member was checked above, and each is compared with its
        # checked self as it is written: the trusted filter keeps the
        # recorded owners and modes.
        tar.extractall(target, numeric_owner=True, filter=same)
    stream.close()
    if written != set(expected):
        raise Refused(f"the second read ended early; {target} is incomplete")
    return count


# --- the host commands -------------------------------------------------------


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def pinned_age(path: Path, expected: str) -> str:
    """The age binary, checked against its pinned SHA-256; its version."""
    if sha256(path) != expected:
        raise Refused(f"{path} is not the pinned age binary")
    answer = subprocess.run([str(path), "--version"], capture_output=True, text=True, timeout=30, check=False)
    if answer.returncode != 0:
        raise Refused(f"{path} --version failed")
    return answer.stdout.strip()


def container_state(name: str) -> str:
    """absent, stopped or running; a failed observation refuses."""
    try:
        answer = subprocess.run(["docker", "container", "inspect", "--format", "{{.State.Running}}", name],
                                capture_output=True, text=True, timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise Refused(f"docker container inspect {name} failed: {error}") from None
    if answer.returncode == 0:
        return {"true": "running", "false": "stopped"}.get(answer.stdout.strip()) or "unknown"
    if "no such container" in answer.stderr.lower():
        return "absent"
    raise Refused(f"docker container inspect {name} failed: {answer.stderr.strip()[-300:]}")


def new_directory(path: Path) -> None:
    if os.path.lexists(path):
        raise Refused(f"{path} exists; it must be new")
    if os.path.realpath(path.parent) != str(path.parent):
        raise Refused(f"{path.parent} is reached through a symbolic link")
    os.mkdir(path, 0o700)


def capture_command(args: argparse.Namespace) -> None:
    fence = container_state(args.container)
    if fence not in ("absent", "stopped"):
        raise Refused(f"the container {args.container} is {fence}; stop the writer before a capture")
    version = pinned_age(args.age, args.age_sha256)
    new_directory(args.out)
    partial = args.out / "state.tar.age.partial"
    age = subprocess.Popen([str(args.age), "--encrypt", "--recipients-file", str(args.recipients), "--output",
                            str(partial)], stdin=subprocess.PIPE)
    try:
        captured = capture(args.state, age.stdin)
    except BaseException:
        age.kill()
        age.wait()
        partial.unlink(missing_ok=True)
        raise
    age.stdin.close()
    if age.wait() != 0:
        partial.unlink(missing_ok=True)
        raise Refused(f"age exited {age.returncode}; no backup was written")
    final = args.out / "state.tar.age"
    partial.rename(final)
    root = args.state.lstat()
    manifest = {
        "format": 1,
        "kind": "agent-state",
        "createdAt": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "source": {"path": str(args.state), "uid": root.st_uid, "gid": root.st_gid,
                   "mode": oct(stat.S_IMODE(root.st_mode)), "container": args.container, "fence": fence},
        "members": captured["members"],
        "omitted": captured["omitted"],
        "ciphertext": {"file": final.name, "sha256": sha256(final), "bytes": final.stat().st_size},
        "age": {"version": version, "sha256": args.age_sha256,
                "recipients": [line.strip() for line in args.recipients.read_text().splitlines()
                               if line.strip() and not line.startswith("#")]},
    }
    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"captured": str(final), "members": manifest["members"], "omitted": manifest["omitted"],
                      "sha256": manifest["ciphertext"]["sha256"]}, sort_keys=True))


class Decrypted:
    """age's plaintext output, read as a stream; closing it reads what is
    left and refuses unless age exited 0, so a ciphertext that fails age's
    authentication is never taken as a whole archive."""

    def __init__(self, command: list[str]):
        self.age = subprocess.Popen(command, stdout=subprocess.PIPE)

    def read(self, size: int = -1) -> bytes:
        return self.age.stdout.read(size)

    def close(self) -> None:
        while self.age.stdout.read(1 << 20):
            pass
        self.age.stdout.close()
        if self.age.wait() != 0:
            raise Refused(f"age --decrypt exited {self.age.returncode}")


def restore_command(args: argparse.Namespace) -> None:
    if container_state(args.container) != "absent":
        raise Refused(f"a container {args.container} exists on this host; a restore starts from none")
    manifest = json.loads((args.backup / "manifest.json").read_text())
    if manifest.get("format") != 1 or manifest.get("kind") != "agent-state":
        raise Refused("the manifest is not an agent-state manifest of format 1")
    pinned_age(args.age, args.age_sha256)
    name = manifest["ciphertext"]["file"]
    if PurePosixPath(name).name != name or not parts(name):
        raise Refused(f"the manifest names {name!r}, not a file of the backup")
    private = Path(tempfile.mkdtemp(prefix="agent-state-restore-"))
    try:
        copy = private / "state.tar.age"
        shutil.copyfile(args.backup / name, copy)
        if sha256(copy) != manifest["ciphertext"]["sha256"]:
            raise Refused(f"{name} does not match the manifest's digest")

        def read() -> BinaryIO:
            return Decrypted([str(args.age), "--decrypt", "--identity", str(args.identity), str(copy)])

        restored = restore(read, args.target, manifest["members"])
    finally:
        shutil.rmtree(private)
    print(json.dumps({"restored": str(args.target), "members": restored, "omitted": manifest["omitted"]},
                     sort_keys=True))


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("capture", "restore"):
        command = commands.add_parser(name)
        command.add_argument("--container", required=True)
        command.add_argument("--age", type=Path, required=True)
        command.add_argument("--age-sha256", required=True)
    commands.choices["capture"].add_argument("--state", type=Path, required=True)
    commands.choices["capture"].add_argument("--recipients", type=Path, required=True)
    commands.choices["capture"].add_argument("--out", type=Path, required=True)
    commands.choices["restore"].add_argument("--backup", type=Path, required=True)
    commands.choices["restore"].add_argument("--identity", type=Path, required=True)
    commands.choices["restore"].add_argument("--target", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        (capture_command if args.command == "capture" else restore_command)(args)
    except Refused as refused:
        print(f"agent_state: {refused}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
