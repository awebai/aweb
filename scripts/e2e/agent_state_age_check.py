"""deploy/team/agent_state.py with the real age, on fictional state and
disposable keys (aweb-acwd.25.1). Run as root on a Linux host, in a new
directory:

    python3 -I scripts/e2e/agent_state_age_check.py --work NEW_DIR \\
        --age PATH --age-sha256 HEX --age-keygen PATH

It makes a fictional agent state owned by uid:gid 20001:20001 (an OATS home
with its links, a seat key 0600, a setgid directory, a setuid file and aw's
wake-store socket), a second fictional state holding one 512 MiB sparse file
(so that age is still writing when it is stopped), a disposable identity and
recipient, and a second identity that is not the recipient's. Then, each
through the CLI as an operator runs it, each judged on its own:

1. capture: exit 0; the manifest records the socket as the one omission;
   no plaintext archive in the backup directory;
2. restore: exit 0; every entry back with its owner, mode (setgid and setuid
   included), link target and bytes; the socket left out;
3. tampered: one ciphertext byte changed and the manifest digest made to
   match, so only age's authentication can catch it: refused, no target;
4. wrong key: refused, no target;
5. digest: the untouched ciphertext against a changed manifest digest:
   refused, no target;
6. deadline expiry: a capture whose age has a 1 ms deadline: refused as
   past its deadline, no partial ciphertext left;
7. capture terminated: once the partial ciphertext has bytes, the CLI's
   process group is stopped, so the write is caught in progress; then the
   CLI is sent SIGTERM and continued. Asserted separately: the CLI's exit
   (143, "terminated"), no partial ciphertext, and no process left in its
   group (its age child included);
8. restore terminated: the large state's backup restoring, stopped once the
   target exists (the second pass is writing), then SIGTERM: the CLI's exit
   (143), the target named incomplete and left, the private ciphertext copy
   removed, and no process left in its group.

Every CLI call runs in its own process group under one absolute deadline set
at its launch, observation included, that holds its age deadlines (60 s each,
two per restore) with a reserve; past it the group is sent SIGTERM, then
SIGKILL, and reaped, which has its own 30 s reserve. Any exit of this check
other than its verdict (SIGTERM, an interrupt, an error) ends the call in
flight the same way first and reports whether its group is gone. A disposable key on the same
host proves function only, not key custody. Prints one JSON line per case
and exits 0 only when all eight pass.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path

TOOL = Path(__file__).resolve().parents[2] / "deploy" / "team" / "agent_state.py"
UID = GID = 20001
# One age process may run this long; a CLI call holds at most two.
AGE_DEADLINE = 60
CALL_BUDGET = 2 * AGE_DEADLINE + 30
CASES = ("capture", "restore", "tampered", "wrong-key", "digest", "deadline-expiry", "capture-terminated",
         "restore-terminated")


class Terminated(BaseException):
    pass


def terminate(signum: int, frame: object) -> None:
    raise Terminated()


def fixture(root: Path) -> socket.socket:
    """The fictional state; returns the bound wake socket, held open."""
    instance = root / "deploy" / "agents" / "soul" / "instances" / "fixture"
    (instance / ".agents" / "skills" / "skill").mkdir(parents=True)
    (instance / ".claude").mkdir()
    (instance / "AGENTS.md").write_text("fictional instructions\n")
    (instance / "CLAUDE.md").symlink_to("AGENTS.md")
    (instance / ".claude" / "skills").symlink_to("../.agents/skills")
    (instance / ".agents" / "skills" / "skill" / "SKILL.md").write_text("a fictional skill\n")
    seat = root / "seats" / "fixture" / ".aw"
    seat.mkdir(parents=True)
    (seat / "signing.key").write_bytes(os.urandom(32))
    (seat / "signing.key").chmod(0o600)
    (root / "shared").mkdir()
    (root / "work.bin").write_bytes(os.urandom(1 << 20))
    (root / "tool").write_text("#!/bin/sh\n")
    wake = root / "home" / ".config" / "aw" / "wake"
    wake.mkdir(parents=True)
    for path in [root, *root.rglob("*")]:
        os.lchown(path, UID, GID)
        if path.is_dir() and not path.is_symlink():
            path.chmod(0o700)
    (root / "shared").chmod(0o2750)
    (root / "tool").chmod(0o4750)
    listener = socket.socket(socket.AF_UNIX)
    listener.bind(str(wake / "control.sock"))
    os.lchown(wake / "control.sock", UID, GID)
    return listener


def tree(root: Path) -> dict[str, tuple]:
    entries = {}
    for path in [root, *sorted(root.rglob("*"))]:
        info = path.lstat()
        relative = str(path.relative_to(root))
        kind = stat.S_IFMT(info.st_mode)
        body = os.readlink(path) if path.is_symlink() else path.read_bytes() if stat.S_ISREG(info.st_mode) else None
        entries[relative] = (kind, info.st_uid, info.st_gid, oct(stat.S_IMODE(info.st_mode)), body)
    return entries


def group_gone(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return True
    return False


class Call:
    """One CLI call in its own process group, under one absolute deadline set
    at launch, owned until its group is gone. Ending it (TERM, then KILL,
    then reaping) has its own reserve beyond that deadline."""

    current: "Call | None" = None

    def __init__(self, command: list[str], budget: float = CALL_BUDGET):
        self.deadline = time.monotonic() + budget
        self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                        start_new_session=True)
        Call.current = self

    def remaining(self) -> float:
        return max(0.0, self.deadline - time.monotonic())

    def end(self) -> bool:
        """TERM to the group, then KILL, then reap; whether the group is gone."""
        for sent, grace in ((signal.SIGTERM, 10), (signal.SIGKILL, 10)):
            if group_gone(self.process.pid):
                break
            try:
                os.killpg(self.process.pid, sent)
            except ProcessLookupError:
                break
            try:
                self.process.wait(timeout=grace)
            except subprocess.TimeoutExpired:
                pass
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass
        return group_gone(self.process.pid)

    def release(self) -> None:
        """Closes the call's pipes once it is ended, and lets it go."""
        for stream in (self.process.stdout, self.process.stderr):
            if stream is not None and not stream.closed:
                stream.close()
        Call.current = None

    def result(self) -> subprocess.CompletedProcess:
        """Waits for the call within what is left of its deadline; past it,
        ends the group."""
        try:
            stdout, stderr = self.process.communicate(timeout=self.remaining())
            note = ""
        except subprocess.TimeoutExpired:
            gone = self.end()
            stdout, stderr = self.process.communicate()
            note = f"\n[check] the call passed its deadline; its group was ended; group gone: {gone}"
        Call.current = None
        return subprocess.CompletedProcess(self.process.args, self.process.returncode, stdout, stderr + note)


def tool(*args: str) -> list[str]:
    return [sys.executable, "-I", str(TOOL), *args]


def cli(*args: str) -> subprocess.CompletedProcess:
    return Call(tool(*args)).result()


def holds(condition) -> bool:
    """An observation of the filesystem; one that fails is "not yet"."""
    try:
        return bool(condition())
    except OSError:
        return False


def partial_has_bytes(partial: Path):
    return lambda: partial.stat().st_size > 0


def wait_for(condition, call: Call) -> bool:
    """Polls condition every 5 ms until it holds, the call exits, or the
    call's own deadline passes."""
    while call.remaining() > 0:
        if holds(condition):
            return True
        if call.process.poll() is not None:
            return False
        time.sleep(0.005)
    return False


def terminated_in_progress(call: Call, started) -> dict:
    """Stops the call's group once started() holds, then sends the CLI
    SIGTERM and continues the group; returns what was seen. A call that
    finished first, a failed observation or a failed signal fails the case
    with the call ended; an interrupt of the check ends the call and goes on."""
    seen: dict = {"caught_in_progress": False}
    try:
        if wait_for(started, call):
            os.killpg(call.process.pid, signal.SIGSTOP)
            seen["caught_in_progress"] = True
            seen["alive_when_stopped"] = call.process.poll() is None and holds(started)
            call.process.send_signal(signal.SIGTERM)
            os.killpg(call.process.pid, signal.SIGCONT)
        answer = call.result()
    except Exception as error:
        seen.update(error=f"{type(error).__name__}: {error}", group_gone=call.end())
        call.release()
        return seen
    except BaseException:
        call.end()
        call.release()
        raise
    seen.update(rc=answer.returncode, stderr=answer.stderr.strip()[-400:], group_gone=group_gone(call.process.pid))
    return seen


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--age", type=Path, required=True)
    parser.add_argument("--age-sha256", required=True)
    parser.add_argument("--age-keygen", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        print("FAILED: run as root, to make and restore numeric owners")
        return 2
    if os.path.lexists(args.work):
        print(f"FAILED: {args.work} exists; each run has its own directory")
        return 2
    signal.signal(signal.SIGTERM, terminate)
    try:
        return check(args)
    except BaseException as stopped:
        # Every exit that is not the check's own verdict ends the call in
        # flight first, and says whether its group is gone.
        gone = True
        if Call.current is not None:
            gone = Call.current.end()
            Call.current.release()
        reason = "the check was terminated" if isinstance(stopped, Terminated) else (
            f"the check stopped on {type(stopped).__name__}: {stopped}")
        print(json.dumps({"result": "INCOMPLETE", "reason": reason, "call_in_flight_group_gone": gone},
                         sort_keys=True))
        return 3


def check(args: argparse.Namespace) -> int:
    work = args.work
    work.mkdir(mode=0o700)
    keys = work / "keys"
    keys.mkdir(mode=0o700)
    for name in ("identity", "other-identity"):
        made = subprocess.run([str(args.age_keygen), "-o", str(keys / name)], capture_output=True, text=True,
                              timeout=30, check=False)
        if made.returncode != 0:
            print(f"FAILED: age-keygen {name}: {made.stderr.strip()}")
            return 1
    recipient = subprocess.run([str(args.age_keygen), "-y", str(keys / "identity")], capture_output=True, text=True,
                               timeout=30, check=True).stdout
    (keys / "recipients").write_text(recipient)
    state = work / "state"
    state.mkdir(mode=0o700)
    listener = fixture(state)
    large = work / "state-large"
    large.mkdir(mode=0o700)
    with open(large / "sparse.bin", "wb") as sparse:
        sparse.truncate(512 << 20)
    deadline = ["--deadline", str(AGE_DEADLINE)]
    pinned = ["--age", str(args.age), "--age-sha256", args.age_sha256]
    container = ["--container", "acwd25-age-check-no-such-container"]
    recipients = ["--recipients", str(keys / "recipients")]
    results: dict[str, str] = {}

    def case(name: str, ok: bool, detail: dict) -> None:
        results[name] = "PASS" if ok else "FAILED"
        print(json.dumps({"case": name, "result": results[name], **detail}, sort_keys=True), flush=True)

    try:
        backup = work / "backup"
        captured = cli("capture", "--state", str(state), *container, *pinned, *recipients, *deadline,
                       "--out", str(backup))
        manifest = json.loads((backup / "manifest.json").read_text()) if captured.returncode == 0 else {}
        plaintext = [path.name for path in backup.iterdir() if path.name.endswith(".tar")] if backup.exists() else []
        case("capture", captured.returncode == 0 and plaintext == [] and manifest.get("omitted") == [
            {"path": "home/.config/aw/wake/control.sock", "type": "socket",
             "reason": "aw wake broker control socket of the store home/.config/aw/wake"}],
             {"rc": captured.returncode, "stderr": captured.stderr.strip()[-400:], "omitted": manifest.get("omitted"),
              "members": manifest.get("members"), "plaintext": plaintext})

        restored = work / "restored"
        answer = cli("restore", "--backup", str(backup), *container, *pinned, *deadline, "--identity",
                     str(keys / "identity"), "--target", str(restored))
        before = {path: entry for path, entry in tree(state).items() if not path.endswith("control.sock")}
        after = tree(restored) if answer.returncode == 0 else {}
        differ = sorted(path for path in set(before) | set(after) if before.get(path) != after.get(path))
        case("restore", answer.returncode == 0 and not differ,
             {"rc": answer.returncode, "stderr": answer.stderr.strip()[-400:], "entries": len(after),
              "differ": differ[:20], "setgid": after.get("shared", (0, 0, 0, None))[3],
              "setuid": after.get("tool", (0, 0, 0, None))[3]})

        def refused(name: str, backup_dir: Path, identity: Path, expect: str) -> None:
            target = work / f"target-{name}"
            answer = cli("restore", "--backup", str(backup_dir), *container, *pinned, *deadline, "--identity",
                         str(identity), "--target", str(target))
            case(name, answer.returncode == 1 and not os.path.lexists(target) and expect in answer.stderr,
                 {"rc": answer.returncode, "stderr": answer.stderr.strip()[-400:],
                  "target_exists": os.path.lexists(target)})

        if manifest:
            ciphertext = (backup / "state.tar.age").read_bytes()
            tampered = work / "backup-tampered"
            tampered.mkdir(mode=0o700)
            middle = len(ciphertext) // 2
            changed = ciphertext[:middle] + bytes([ciphertext[middle] ^ 0x01]) + ciphertext[middle + 1:]
            (tampered / "state.tar.age").write_bytes(changed)
            (tampered / "manifest.json").write_text(json.dumps(
                {**manifest, "ciphertext": {**manifest["ciphertext"], "sha256": hashlib.sha256(changed).hexdigest()}}))
            refused("tampered", tampered, keys / "identity", "exited 1")
            refused("wrong-key", backup, keys / "other-identity", "exited 1")
            digest = work / "backup-digest"
            digest.mkdir(mode=0o700)
            (digest / "state.tar.age").write_bytes(ciphertext)
            (digest / "manifest.json").write_text(json.dumps(
                {**manifest, "ciphertext": {**manifest["ciphertext"], "sha256": "0" * 64}}))
            refused("digest", digest, keys / "identity", "does not match the manifest's digest")
        else:
            for name in ("tampered", "wrong-key", "digest"):
                case(name, False, {"reason": "no capture to start from"})

        expired = work / "backup-deadline"
        answer = cli("capture", "--state", str(state), *container, *pinned, *recipients, "--out", str(expired),
                     "--deadline", "0.001")
        left = sorted(path.name for path in expired.iterdir()) if expired.exists() else []
        case("deadline-expiry", answer.returncode == 1 and "passed its deadline" in answer.stderr and left == [],
             {"rc": answer.returncode, "stderr": answer.stderr.strip()[-400:], "left": left})

        stopped = work / "backup-terminated"
        partial = stopped / "state.tar.age.partial"
        call = Call(tool("capture", "--state", str(large), *container, *pinned, *recipients, *deadline,
                         "--out", str(stopped)))
        seen = terminated_in_progress(call, partial_has_bytes(partial))
        left = sorted(path.name for path in stopped.iterdir()) if stopped.exists() else []
        case("capture-terminated", seen["caught_in_progress"] and bool(seen.get("alive_when_stopped"))
             and seen.get("rc") == 143 and "terminated" in seen.get("stderr", "") and left == []
             and seen["group_gone"], {**seen, "left": left})

        large_backup = work / "backup-large"
        answer = cli("capture", "--state", str(large), *container, *pinned, *recipients, *deadline,
                     "--out", str(large_backup))
        target = work / "restored-terminated"
        if answer.returncode == 0:
            call = Call(tool("restore", "--backup", str(large_backup), *container, *pinned, *deadline, "--identity",
                             str(keys / "identity"), "--target", str(target)))
            seen = terminated_in_progress(call, lambda: os.path.lexists(target))
            private = sorted(path.name for path in work.iterdir() if path.name.startswith(".agent-state-restore-"))
            case("restore-terminated", seen["caught_in_progress"] and bool(seen.get("alive_when_stopped"))
                 and seen.get("rc") == 143 and "incomplete" in seen.get("stderr", "") and os.path.lexists(target)
                 and private == [] and seen["group_gone"], {**seen, "target_left": os.path.lexists(target),
                                                            "private_copies_left": private})
        else:
            case("restore-terminated", False, {"reason": "the large capture failed", "rc": answer.returncode,
                                               "stderr": answer.stderr.strip()[-400:]})
    finally:
        listener.close()
    passed = set(results) == set(CASES) and set(results.values()) == {"PASS"}
    print(json.dumps({"result": "PASS" if passed else "FAILED", "cases": results}, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
