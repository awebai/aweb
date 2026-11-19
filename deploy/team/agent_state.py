"""One agent state (TEAM_STATE_DIR, bound at /state) as an age-encrypted
backup and back, on a host, as root, with the agent's writer fenced:

    python3 -I agent_state.py capture --state DIR --container NAME \\
        --age PATH --age-sha256 HEX --recipients FILE --out NEW_DIR \\
        [--wake-store REL ...] [--custody-root REL ...] [--deadline SECONDS]
    python3 -I agent_state.py restore --backup DIR --container NAME \\
        --age PATH --age-sha256 HEX --identity FILE --target NEW_DIR \\
        [--deadline SECONDS]

Only the agent's state: no database, no Secrets or Logs, no harness login
and no provider credential, which live outside it. A restore of a team's
databases stays refused (teamctl restore).

Docker is asked through the local daemon's socket alone, with no inherited
context or configuration, and its answer is an exact inventory: a failed or
mixed answer refuses. capture refuses unless the named container is absent,
or stopped with that state directory as its /state. Stopping a container does
not keep it stopped: the operator's fence (renaming the state directory, which
the agent's bind refuses to create) precedes the final capture.

capture walks the state once to an inventory, refusing any entry it cannot
read, checks every member as deploy/team/state_archive.py does, and streams
the archive straight into age, encrypted to the public recipients: no
plaintext archive is written. The only entries left out are the sockets aw
1.36.58 creates again when it starts, at the configured roots: control.sock
in each wake store (default home/.config/aw/wake, HOME being /state/home) and
run/custody.sock in each custody root (none by default: the container's seats
are local identities, not grant homes). Each is recorded in the manifest; any
other socket or FIFO refuses the capture. Links come after every other member.

restore copies the ciphertext into a private directory beside the target
(removed when it ends) and checks it against
the manifest's digest, decrypts it once to check every member and the count
before anything is written, then decrypts it again into a target where
nothing is, under a parent no one but root or this user can change, comparing
each member with the checked one. It refuses unless no container with the
given name exists on this host.

Every age process runs under a deadline, and is killed and reaped on any
failure, interruption (SIGINT), termination (SIGTERM) or timeout; a partial ciphertext is removed, and a
partial restore is named as incomplete and left for inspection.

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
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import BinaryIO

sys.path.insert(0, str(Path(__file__).resolve().parent))

from state_archive import Refused, check, parts  # noqa: E402

DOCKER_ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
              "DOCKER_HOST": "unix:///var/run/docker.sock"}
# How long one age process may run, by default.
DEADLINE = 3600


class Endpoints:
    """The sockets aw 1.36.58 creates in the state and creates again when it
    starts, at the roots this state configures (relative to the state):
    cli/go/cmd/aw/wake.go puts control.sock in the wake store, default
    $HOME/.config/aw/wake; cli/go/internal/custodypath puts custody.sock in a
    grant home's run/. Nothing else is left out."""

    def __init__(self, wake_stores: list[str], custody_roots: list[str]):
        self.rules = {parts(store) + ("control.sock",): f"aw wake broker control socket of the store {store}"
                      for store in wake_stores}
        self.rules |= {parts(root) + ("run", "custody.sock"): f"aw custody socket of the grant home {root}"
                       for root in custody_roots}

    def reason(self, path: tuple[str, ...]) -> str | None:
        return self.rules.get(path)


DEFAULT_ENDPOINTS = Endpoints(["home/.config/aw/wake"], [])


def inventory(root: Path, endpoints: Endpoints) -> tuple[list[tuple[Path, str]], list[dict]]:
    """The members in stream order (the root, every directory before what it
    holds, links last) and the declared omissions; refused for an entry that
    cannot be read, an undeclared socket or FIFO, or a device file."""

    def unreadable(error: OSError) -> None:
        raise Refused(f"{error.filename}: cannot be read ({error.strerror}); no backup is complete without it")

    others: list[tuple[Path, str]] = [(root, ".")]
    links: list[tuple[Path, str]] = []
    omitted: list[dict] = []
    for directory, dirs, files in os.walk(root, onerror=unreadable, followlinks=False):
        dirs.sort()
        for name in sorted((*dirs, *files)):
            path = Path(directory) / name
            relative = path.relative_to(root)
            mode = path.lstat().st_mode
            if stat.S_ISSOCK(mode) or stat.S_ISFIFO(mode):
                kind = "socket" if stat.S_ISSOCK(mode) else "FIFO"
                reason = endpoints.reason(relative.parts) if kind == "socket" else None
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


class Discard:
    """A sink that keeps nothing: the inventory's TarFile only computes headers."""

    def write(self, data: bytes) -> int:
        return len(data)

    def tell(self) -> int:
        return 0


def capture(root: Path, sink: BinaryIO, endpoints: Endpoints = DEFAULT_ENDPOINTS) -> dict:
    """root as a checked tar stream written to sink; returns the inventory
    the manifest records."""
    members, omitted = inventory(root, endpoints)
    with tarfile.open(fileobj=Discard(), mode="w", format=tarfile.PAX_FORMAT) as probe:  # type: ignore[call-overload]
        planned = [probe.gettarinfo(path, arcname) for path, arcname in members]
    check(planned)
    with tarfile.open(fileobj=sink, mode="w|", format=tarfile.PAX_FORMAT) as tar:
        for (path, arcname), expected in zip(members, planned, strict=True):
            info = tar.gettarinfo(path, arcname)
            if (info.type, info.size, info.mtime, info.linkname) != (expected.type, expected.size, expected.mtime,
                                                                      expected.linkname):
                raise Refused(f"{arcname} changed during the capture; is the writer fenced?")
            if info.isreg():
                with open(path, "rb") as data:
                    tar.addfile(info, data)
            else:
                tar.addfile(info)
    return {"members": len(planned), "omitted": omitted}


def signature(member: tarfile.TarInfo) -> tuple:
    return (member.name, member.type, member.linkname, member.size, member.mode, member.uid, member.gid, member.mtime)


def secure_parent(target: Path) -> None:
    """target's parent and every ancestor: reached without a symbolic link,
    owned by root or this user, and writable by no one else unless sticky."""
    if not target.is_absolute():
        raise Refused(f"{target} is not an absolute path")
    parent = target.parent
    if os.path.realpath(parent) != str(parent):
        raise Refused(f"{parent} is reached through a symbolic link")
    for ancestor in (parent, *parent.parents):
        info = ancestor.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise Refused(f"{ancestor} is not a directory")
        if info.st_uid not in (0, os.geteuid()):
            raise Refused(f"{ancestor} belongs to uid {info.st_uid}, neither root nor this user")
        if info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX:
            raise Refused(f"{ancestor} is writable by others")


def settle(stream: BinaryIO, failed: bool) -> str | None:
    """Ends a stream: on success its close must succeed; after a failure it
    is aborted, and what that says is returned to go with the first error."""
    if not failed:
        stream.close()
        return None
    abort = getattr(stream, "abort", None)
    try:
        return abort() if abort is not None else stream.close()
    except Exception as error:  # the first failure is the one reported
        return str(error)


def read_whole(read: Callable[[], BinaryIO], each: Callable[[tarfile.TarFile], object]) -> None:
    """One whole read of the stream, ended on every path, its final drain
    and close included: a failure aborts the stream (an age child is killed
    and reaped) and reports what the abort said beside the first error."""
    stream = read()
    try:
        with tarfile.open(fileobj=stream, mode="r|") as tar:
            each(tar)
        settle(stream, False)
    except (Refused, tarfile.TarError, OSError) as error:
        said = settle(stream, True)
        message = str(error)
        raise Refused(message + (f"; {said}" if said and said not in message else "")) from None
    except BaseException:
        settle(stream, True)
        raise


def restore(read: Callable[[], BinaryIO], target: Path, count: int) -> int:
    """The stream read() gives, checked whole, then written into target;
    read() is called twice and must give the same stream both times."""
    secure_parent(target)
    if os.path.lexists(target):
        raise Refused(f"{target} exists; a restore writes only where nothing is")
    checked: list[tarfile.TarInfo] = []
    read_whole(read, lambda tar: checked.extend(tar))
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
            raise Refused(f"the second read differs from the checked one at {member.name}")
        written.add(member.name)
        return tarfile.fully_trusted_filter(member, path)

    os.mkdir(target, 0o700)
    try:
        # Every member was checked above, and each is compared with its
        # checked self as it is written: the trusted filter keeps the
        # recorded owners and modes.
        read_whole(read, lambda tar: tar.extractall(target, numeric_owner=True, filter=same))
        if written != set(expected):
            raise Refused("the second read ended early")
    except Refused as refused:
        raise Refused(f"{refused}; {target} is incomplete and left for inspection") from None
    return count


# --- child processes ---------------------------------------------------------


class Terminated(BaseException):
    """SIGTERM, raised where the process is, so that every owned child is
    ended as on an interrupt."""


def terminate(signum: int, frame: object) -> None:
    raise Terminated()


class Child:
    """One process under a deadline: killed when it passes, and killed and
    reaped by abort on any failure."""

    def __init__(self, command: list[str], deadline: float, **popen):
        self.command = command
        self.expired = False
        self.process = subprocess.Popen(command, **popen)
        try:
            self.timer = threading.Timer(deadline, self.expire)
            self.timer.daemon = True
            self.timer.start()
        except BaseException:
            self.process.kill()
            self.process.wait()
            raise

    def expire(self) -> None:
        self.expired = True
        self.process.kill()

    def outcome(self) -> str:
        if self.expired:
            return f"{self.command[0]} passed its deadline and was killed"
        return f"{self.command[0]} exited {self.process.returncode}"

    def finish(self) -> None:
        """Waits for a clean exit; refuses unless it exited 0 in time."""
        self.process.wait()
        self.timer.cancel()
        if self.expired or self.process.returncode != 0:
            raise Refused(self.outcome())

    def abort(self) -> str:
        self.timer.cancel()
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait()
        if self.process.stdin is not None and not self.process.stdin.closed:
            try:
                self.process.stdin.close()
            except OSError:  # a killed reader: what was buffered for it goes nowhere
                pass
        return self.outcome()


class Decrypted(Child):
    """age's plaintext output, read as a stream; closing it reads what is
    left and refuses unless age exited 0 within its deadline, so a ciphertext
    that fails age's authentication is never taken as a whole archive."""

    def __init__(self, command: list[str], deadline: float):
        super().__init__(command, deadline, stdout=subprocess.PIPE)

    def read(self, size: int = -1) -> bytes:
        return self.process.stdout.read(size)  # type: ignore[union-attr]

    def close(self) -> None:
        while self.process.stdout.read(1 << 20):  # type: ignore[union-attr]
            pass
        self.process.stdout.close()  # type: ignore[union-attr]
        self.finish()

    def abort(self) -> str:
        said = super().abort()
        self.process.stdout.close()  # type: ignore[union-attr]
        return said


def encrypt(state: Path, partial: Path, command: list[str], deadline: float, endpoints: Endpoints) -> dict:
    """state captured into command's standard input, which writes partial;
    on any failure the child is killed and reaped and partial removed, and
    the first error is the one raised."""
    child = Child(command, deadline, stdin=subprocess.PIPE)
    try:
        captured = capture(state, child.process.stdin, endpoints)  # type: ignore[arg-type]
        child.process.stdin.close()  # type: ignore[union-attr]
        child.finish()
    except (Refused, OSError, tarfile.TarError) as error:
        said = child.abort()
        partial.unlink(missing_ok=True)
        raise Refused(f"{error}; {said}; no backup was written") from None
    except BaseException:
        child.abort()
        partial.unlink(missing_ok=True)
        raise
    return captured


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


def docker(*args: str) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(["docker", *args], env=DOCKER_ENV, capture_output=True, text=True, timeout=60,
                              check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise Refused(f"docker {args[0]} failed: {error}") from None


def listed(answer: subprocess.CompletedProcess, name: str) -> dict | None:
    """The container named exactly name in a `docker container ls --all
    --no-trunc --format {{json .}}` answer, or None when it lists none. Only a
    clean answer counts: a nonzero exit, any diagnostic or an unreadable line
    refuses, and so do two containers of that name."""
    if answer.returncode != 0 or answer.stderr.strip():
        raise Refused(f"docker container ls failed (rc={answer.returncode}): {answer.stderr.strip()[-300:]}")
    found = []
    for line in answer.stdout.splitlines():
        try:
            container = json.loads(line)
            names = container["Names"].split(",")
        except (ValueError, KeyError, AttributeError):
            raise Refused(f"docker container ls answered an unreadable line: {line[:200]!r}") from None
        if name in names:
            found.append({"id": container["ID"], "state": container.get("State", "")})
    if len(found) > 1:
        raise Refused(f"{len(found)} containers are named {name}")
    return found[0] if found else None


def writer(name: str, state: Path) -> dict:
    """The fence on the writer as this host's daemon answers it: absent, or
    stopped with state as its /state; anything else refuses."""
    daemon = docker("info", "--format", "{{.ID}}")
    if daemon.returncode != 0 or daemon.stderr.strip() or not daemon.stdout.strip():
        raise Refused(f"docker info failed (rc={daemon.returncode})")
    container = listed(docker("container", "ls", "--all", "--no-trunc", "--format", "{{json .}}"), name)
    seen = {"daemon": daemon.stdout.strip(), "container": name}
    if container is None:
        return {**seen, "state": "absent"}
    if container["state"] not in ("exited", "created"):
        raise Refused(f"the container {name} is {container['state'] or 'in an unknown state'}; fence the writer first")
    mounts = docker("container", "inspect", "--format", "{{json .Mounts}}", container["id"])
    if mounts.returncode != 0 or mounts.stderr.strip():
        raise Refused(f"docker container inspect {name} failed (rc={mounts.returncode})")
    sources = [mount.get("Source") for mount in json.loads(mounts.stdout) if mount.get("Destination") == "/state"]
    if sources != [os.path.realpath(state)]:
        raise Refused(f"the container {name} mounts /state from {sources}, not {state}")
    return {**seen, "state": container["state"], "id": container["id"]}


def new_directory(path: Path) -> None:
    secure_parent(path)
    if os.path.lexists(path):
        raise Refused(f"{path} exists; it must be new")
    os.mkdir(path, 0o700)


def capture_command(args: argparse.Namespace) -> None:
    fence = writer(args.container, args.state)
    version = pinned_age(args.age, args.age_sha256)
    new_directory(args.out)
    partial = args.out / "state.tar.age.partial"
    endpoints = Endpoints(args.wake_store or ["home/.config/aw/wake"], args.custody_root or [])
    captured = encrypt(args.state, partial,
                       [str(args.age), "--encrypt", "--recipients-file", str(args.recipients), "--output", str(partial)],
                       args.deadline, endpoints)
    final = args.out / "state.tar.age"
    partial.rename(final)
    root = args.state.lstat()
    manifest = {
        "format": 1,
        "kind": "agent-state",
        "createdAt": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
        "source": {"path": str(args.state), "uid": root.st_uid, "gid": root.st_gid,
                   "mode": oct(stat.S_IMODE(root.st_mode)), "writer": fence},
        "members": captured["members"],
        "omitted": captured["omitted"],
        "endpointRules": sorted(endpoints.rules.values()),
        "ciphertext": {"file": final.name, "sha256": sha256(final), "bytes": final.stat().st_size},
        "age": {"version": version, "sha256": args.age_sha256,
                "recipients": [line.strip() for line in args.recipients.read_text().splitlines()
                               if line.strip() and not line.startswith("#")]},
    }
    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"captured": str(final), "members": manifest["members"], "omitted": manifest["omitted"],
                      "sha256": manifest["ciphertext"]["sha256"]}, sort_keys=True))


def restore_command(args: argparse.Namespace) -> None:
    if listed(docker("container", "ls", "--all", "--no-trunc", "--format", "{{json .}}"), args.container) is not None:
        raise Refused(f"a container {args.container} exists on this host; a restore starts from none")
    manifest = json.loads((args.backup / "manifest.json").read_text())
    if manifest.get("format") != 1 or manifest.get("kind") != "agent-state":
        raise Refused("the manifest is not an agent-state manifest of format 1")
    pinned_age(args.age, args.age_sha256)
    name = manifest["ciphertext"]["file"]
    if PurePosixPath(name).name != name or not parts(name):
        raise Refused(f"the manifest names {name!r}, not a file of the backup")
    # The private copy sits beside the target, under the parent checked for it.
    secure_parent(args.target)
    private = Path(tempfile.mkdtemp(prefix=".agent-state-restore-", dir=args.target.parent))
    try:
        copy = private / "state.tar.age"
        shutil.copyfile(args.backup / name, copy)
        if sha256(copy) != manifest["ciphertext"]["sha256"]:
            raise Refused(f"{name} does not match the manifest's digest")
        command = [str(args.age), "--decrypt", "--identity", str(args.identity), str(copy)]
        restored = restore(lambda: Decrypted(command, args.deadline), args.target, manifest["members"])
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
        command.add_argument("--deadline", type=float, default=DEADLINE, help="seconds one age process may run")
    capture_parser, restore_parser = commands.choices["capture"], commands.choices["restore"]
    capture_parser.add_argument("--state", type=Path, required=True)
    capture_parser.add_argument("--recipients", type=Path, required=True)
    capture_parser.add_argument("--out", type=Path, required=True)
    capture_parser.add_argument("--wake-store", action="append", help="relative to the state; repeatable")
    capture_parser.add_argument("--custody-root", action="append", help="relative to the state; repeatable")
    restore_parser.add_argument("--backup", type=Path, required=True)
    restore_parser.add_argument("--identity", type=Path, required=True)
    restore_parser.add_argument("--target", type=Path, required=True)
    args = parser.parse_args(argv)
    signal.signal(signal.SIGTERM, terminate)
    try:
        (capture_command if args.command == "capture" else restore_command)(args)
    except (Refused, OSError) as refused:
        print(f"agent_state: {refused}", file=sys.stderr)
        return 1
    except (Terminated, KeyboardInterrupt) as stopped:
        incomplete = ""
        if args.command == "restore" and os.path.lexists(args.target):
            incomplete = f"; {args.target} is incomplete and left for inspection"
        print(f"agent_state: {'terminated' if isinstance(stopped, Terminated) else 'interrupted'}; its age child"
              f" was killed and reaped{incomplete}", file=sys.stderr)
        return 143 if isinstance(stopped, Terminated) else 130
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
