"""Installed, stdlib-only HO6 supervisor. No command-line arguments or path inputs.

Driver transport uses fd 0/1 through sudo. A guardian owns/reaps the worker;
its private control pipe closes even if the supervisor dies on macOS. No extra
descriptor needs to cross sudo, and none survives worker exec.
"""

from __future__ import annotations

import json
import os
import pwd
import resource
import selectors
import signal
import stat
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

PREFIX = Path("/opt/aweb-secrets-e2e")
MAX_REQUEST = 4096
GRACE_SECONDS = 3


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def _object(raw):
    value = json.loads(raw, object_pairs_hook=_unique)
    if not isinstance(value, dict):
        raise ValueError("object required")
    return value


@dataclass(frozen=True)
class Policy:
    prefix: Path
    runner_uid: int
    protected_uid: int = 0
    ancestor_root: Path = Path("/")
    interpreter: Path | None = None

    def __post_init__(self):
        object.__setattr__(self, "prefix", Path(self.prefix))
        object.__setattr__(self, "ancestor_root", Path(self.ancestor_root))
        object.__setattr__(
            self,
            "interpreter",
            Path(self.interpreter)
            if self.interpreter
            else self.prefix / "runtime" / "bin" / "python3.13",
        )
        if not self.prefix.is_absolute() or ".." in self.prefix.parts:
            raise ValueError("invalid prefix")

    @classmethod
    def deployed(cls):
        return cls(PREFIX, pwd.getpwnam("aweb-runner").pw_uid)

    @property
    def state(self):
        return self.prefix / "runner-state"

    def _entry(self, path, uid, *, mode=None, directory=False):
        info = path.lstat()
        if (
            info.st_uid != uid
            or stat.S_ISLNK(info.st_mode)
            or info.st_mode & 0o022
            or (mode is not None and stat.S_IMODE(info.st_mode) != mode)
            or (directory and not stat.S_ISDIR(info.st_mode))
            or (not directory and not stat.S_ISREG(info.st_mode))
        ):
            raise ValueError("unsafe installation")

    def check(self):
        if os.geteuid() != self.runner_uid:
            raise ValueError("wrong uid")
        # Exact ancestor checks, not resolve(): a symlink must never be adopted.
        for parent in reversed((self.prefix, *self.prefix.parents)):
            if parent == self.ancestor_root or self.ancestor_root in parent.parents:
                self._entry(parent, self.protected_uid, directory=True)
        self._entry(self.state, self.runner_uid, mode=0o700, directory=True)
        self._entry(self.prefix / "runner-config.json", self.runner_uid, mode=0o600)

        # Check the whole installed Python/import/native closure, including .pth
        # files. Only persistent state and the explicit runner-owned config differ.
        def tree(directory):
            for path in directory.iterdir():
                if path in (self.state, self.prefix / "runner-config.json"):
                    continue
                info = path.lstat()
                is_dir = stat.S_ISDIR(info.st_mode)
                self._entry(path, self.protected_uid, directory=is_dir)
                if is_dir:
                    tree(path)

        tree(self.prefix)
        self._entry(self.interpreter, self.protected_uid)
        for name in ("aweb-secrets-runner", "aweb-secrets-supervisor"):
            with (self.prefix / "bin" / name).open("rb") as source:
                if source.readline(1024) != f"#!{self.interpreter} -I\n".encode():
                    raise ValueError("unsafe interpreter")
        self.origin()  # Invalid configuration refuses before a worker is forked.

    def origin(self):
        value = _object((self.prefix / "supervisor-config.json").read_bytes())
        if set(value) != {"origin"} or not isinstance(value["origin"], str):
            raise ValueError("invalid service configuration")
        origin = value["origin"]
        parsed = urlsplit(origin)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
            or any(c in origin for c in "\x00\r\n")
        ):
            raise ValueError("invalid origin")
        return origin

    def argv(self, command, *, ca=False):
        args = (str(self.prefix / "bin" / "aweb-secrets-runner"), command)
        if command == "register":
            args += ("--origin", self.origin(), "--state-dir", str(self.state))
        elif command in ("doctor", "run"):
            args += (
                "--config",
                str(self.prefix / "runner-config.json"),
                "--state-dir",
                str(self.state),
            )
        else:
            raise ValueError("invalid command")
        if ca:
            if command == "doctor":
                raise ValueError("invalid ca option")
            args += ("--ca-file", str(self.prefix / "service-ca.pem"))
        return args

    def request(self, value):
        if not isinstance(value, dict) or "command" not in value:
            raise ValueError("invalid request")
        command = value["command"]
        allowed = {"command", "code", "ca"} if command == "register" else {"command", "ca"}
        if set(value) - allowed or type(value.get("ca", False)) is not bool:
            raise ValueError("invalid fields")
        data = b""
        if command == "register":
            code = value.get("code")
            if not isinstance(code, str) or not code or any(c in code for c in "\x00\r\n"):
                raise ValueError("invalid registration")
            data = (code + "\n").encode("utf-8")
            if len(data) > 255:
                raise ValueError("invalid registration")
        ca = value.get("ca", False)
        if ca:
            self._entry(self.prefix / "service-ca.pem", self.protected_uid)
        return self.argv(command, ca=ca), data


def _line(fd, bound):
    data = bytearray()
    while len(data) <= bound:
        part = os.read(fd, 1)
        if not part:
            raise ValueError("unexpected eof")
        if part == b"\n":
            return bytes(data)
        data.extend(part)
    raise ValueError("frame too large")


def _emit(fd, value):
    os.write(fd, json.dumps(value, separators=(",", ":")).encode() + b"\n")


def _ignore_other_signals():
    for name in ("SIGHUP", "SIGUSR1", "SIGUSR2", "SIGQUIT", "SIGTSTP", "SIGCONT"):
        signal.signal(getattr(signal, name), signal.SIG_IGN)


def _worker(argv, data, report):
    identity_r, identity_w = os.pipe()
    error_r, error_w = os.pipe()
    input_r, input_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        failure = error_w
        try:
            os.close(identity_r)
            _emit(identity_w, {"pid": os.getpid(), "uid": os.geteuid()})
            os.close(identity_w)
            os.chdir("/")
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            for number in (signal.SIGTERM, signal.SIGINT):
                signal.signal(number, signal.SIG_DFL)
            os.dup2(input_r, 0)
            null = os.open(os.devnull, os.O_WRONLY)
            os.dup2(null, 1)
            os.dup2(null, 2)
            # Only fd3 carries exec failure. CLOEXEC makes success unambiguous.
            os.dup2(error_w, 3, inheritable=False)
            failure = 3
            os.closerange(4, resource.getrlimit(resource.RLIMIT_NOFILE)[0])
            os.execve(argv[0], argv, {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
        except BaseException:
            try:
                os.write(failure, b"failed")
            finally:
                os._exit(127)
    os.close(identity_w)
    os.close(error_w)
    os.close(input_r)
    try:
        _emit(report, _object(_line(identity_r, 128)))
        if data:
            os.write(input_w, data)
        os.close(input_w)
        input_w = -1
        failed = os.read(error_r, 16)
        _emit(report, {"exec": not bool(failed)})
    except BaseException:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        raise
    finally:
        for fd in (identity_r, error_r, input_w):
            if fd >= 0:
                os.close(fd)
    return pid


def _guardian(control, report, argv, data):
    """The worker's parent survives supervisor death, kills and reaps its child.

    macOS has no PR_SET_PDEATHSIG. EOF on this private, non-inherited pipe
    is the parent-death watch; only the supervisor owns its write end.
    """
    pid = None
    status = None
    deadline = None
    try:
        # sudo may relay to a process group. Only this guardian's private
        # channel controls its child; external signals must not orphan it.
        for number in (signal.SIGTERM, signal.SIGINT):
            signal.signal(number, signal.SIG_IGN)
        pid = _worker(argv, data, report)
        with selectors.DefaultSelector() as poll:
            poll.register(control, selectors.EVENT_READ)
            while True:
                reaped, status_value = os.waitpid(pid, os.WNOHANG)
                if reaped:
                    status = status_value
                    break
                if poll.select(0.05):
                    command = os.read(control, 64)
                    for item in command.splitlines() or [b"TERM"]:
                        os.kill(pid, signal.SIGINT if item == b"INT" else signal.SIGTERM)
                    deadline = time.monotonic() + GRACE_SECONDS if deadline is None else deadline
                    if not command:
                        poll.unregister(control)
                if deadline is not None and time.monotonic() >= deadline:
                    os.kill(pid, signal.SIGKILL)
                    _, status = os.waitpid(pid, 0)
                    break
        _emit(report, {"exit": os.waitstatus_to_exitcode(status)})
    finally:
        if pid is not None and status is None:
            # Only our unreaped child: its PID cannot have been reused.
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)


def supervise(policy):
    """No CLI policy overrides; Policy injection is for existing-UID tests only."""
    parent = os.getppid()
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        _ignore_other_signals()
        policy.check()
        argv, data = policy.request(_object(_line(0, MAX_REQUEST)))
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        return 2
    control_r, control_w = os.pipe()
    report_r, report_w = os.pipe()
    guardian = os.fork()
    if guardian == 0:
        os.close(control_w)
        os.close(report_r)
        # Do not keep the driver/sudo transport alive in the guardian.
        os.close(0)
        os.close(1)
        os.close(2)
        try:
            _guardian(control_r, report_w, argv, data)
            os._exit(0)
        except BaseException:
            os._exit(1)
    os.close(control_r)
    os.close(report_w)
    data = b""
    pending = []
    for number in (signal.SIGTERM, signal.SIGINT):
        signal.signal(number, lambda n, f: pending.append(n))
    buffer = bytearray()
    try:
        with selectors.DefaultSelector() as poll:
            poll.register(0, selectors.EVENT_READ)
            poll.register(report_r, selectors.EVENT_READ)
            while True:
                if os.getppid() != parent:
                    pending.append(signal.SIGTERM)
                for number in pending:
                    os.write(control_w, b"INT\n" if number == signal.SIGINT else b"TERM\n")
                pending.clear()
                for key, _ in poll.select(0.05):
                    chunk = os.read(key.fd, 512)
                    if key.fd == report_r:
                        if not chunk:
                            return 0
                        os.write(1, chunk)  # Only guardian's fixed, public frames.
                    elif not chunk:
                        os.close(control_w)
                        control_w = -1
                        poll.unregister(0)
                    else:
                        buffer.extend(chunk)
                        if len(buffer) > 1024:
                            raise ValueError("control too large")
                        while b"\n" in buffer:
                            line, _, rest = buffer.partition(b"\n")
                            buffer = bytearray(rest)
                            value = _object(line)
                            if set(value) != {"signal"} or type(value["signal"]) is not int:
                                raise ValueError("invalid control")
                            if value["signal"] not in (signal.SIGTERM, signal.SIGINT):
                                raise ValueError("invalid signal")
                            pending.append(value["signal"])
    except (OSError, ValueError, TypeError, UnicodeError):
        return 1
    finally:
        if control_w >= 0:
            os.close(control_w)
        os.close(report_r)
        os.waitpid(guardian, 0)  # Guardian waits/reaps worker before exiting.


def main():
    if len(sys.argv) != 1:
        return 2
    try:
        return supervise(Policy.deployed())
    except (OSError, KeyError, ValueError):
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
