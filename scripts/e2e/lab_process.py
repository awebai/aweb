"""Linux kernel containment shared by lab supervisors, never by product code."""
import ctypes
import os
from pathlib import Path
import re
import signal
import time


class Containment:
    """A kernel cgroup-v2 anchor, unaffected by nested setsid/process groups.

    The child enters before exec. The outer supervisor never enters this
    cgroup. cgroup.kill stops every descendant producer before Docker cleanup.
    There is deliberately no process-name or check-then-kill PID fallback.
    """
    def __init__(self, fixture_id):
        if (os.geteuid() != 0 or not Path("/sys/fs/cgroup/cgroup.controllers").is_file()
                or not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal")):
            raise RuntimeError("Linux root/cgroup-v2/pidfd containment is required before launch")
        if not re.fullmatch(r"(?:adaz|preserve-control)-[0-9a-f]{32}", fixture_id):
            raise ValueError("invalid containment identity")
        self.parent_pid = os.getpid()
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
            raise OSError(ctypes.get_errno(), "subreaper API unavailable")
        enabled = ctypes.c_int()
        if libc.prctl(37, ctypes.byref(enabled), 0, 0, 0) != 0 or enabled.value != 1:
            raise RuntimeError("subreaper readback failed")
        probe = os.pidfd_open(os.getpid())
        try:
            signal.pidfd_send_signal(probe, 0)
        finally:
            os.close(probe)
        self.path = Path("/sys/fs/cgroup") / fixture_id
        self.path.mkdir()  # existing groups are never adopted
        self.fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        if not (self.path / "cgroup.kill").is_file():
            os.close(self.fd)
            self.path.rmdir()
            raise RuntimeError("kernel cgroup.kill is required; no process-group fallback")
        try:
            self.write("cgroup.kill", "1")  # actual API probe on the empty owned cgroup
        except BaseException:
            self.close_empty()
            raise

    def limits(self, cpus, memory_bytes, pids):
        values = {"cpu.max": f"{int(cpus * 100000)} 100000", "memory.max": str(memory_bytes), "pids.max": str(pids)}
        for name, value in values.items():
            self.write(name, value)
            if (self.path / name).read_text().strip() != value:
                raise RuntimeError("kernel resource limit readback differs: " + name)

    def write(self, name, value):
        descriptor = os.open(name, os.O_WRONLY | os.O_NOFOLLOW, dir_fd=self.fd)
        try:
            os.write(descriptor, value.encode())
        finally:
            os.close(descriptor)

    def enter(self):
        self.write("cgroup.procs", str(os.getpid()))
        self.parent_death()

    def parent_death(self):
        # Credential changes clear PDEATHSIG. Call again after dropping UID.
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "parent-death API unavailable")
        if os.getppid() != self.parent_pid:
            os._exit(125)

    def close_empty(self):
        if self.populated():
            raise RuntimeError("cannot release a populated containment")
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        self.path.rmdir()

    def populated(self):
        return dict(line.split() for line in (self.path / "cgroup.events").read_text().splitlines())["populated"] != "0"

    def stop(self, process, deadline):
        """Always attempt kernel termination, including an uncertain Popen.

        Leader bookkeeping is optional. Failed reads never skip cgroup.kill
        and never become a clean verdict after a later successful observation.
        """
        signals, errors, reaped = [], [], []
        def failure(phase, error):
            errors.append({"phase": phase, "error": type(error).__name__, "errno": getattr(error, "errno", None)})
        try:
            members = (self.path / "cgroup.procs").read_text().split()
            for value in members:
                try:
                    descriptor = os.pidfd_open(int(value))
                    try:
                        membership = Path("/proc", value, "cgroup").read_text()
                        if any(line == "0::/" + self.path.name for line in membership.splitlines()):
                            signal.pidfd_send_signal(descriptor, signal.SIGTERM)
                            signals.append(int(value))
                    finally:
                        os.close(descriptor)
                except ProcessLookupError:
                    pass  # this process exited; kernel kill still covers the subtree
                except OSError as error:
                    failure("term-member", error)
            grace = min(deadline, time.monotonic() + 5)
            while self.populated() and time.monotonic() < grace:
                if process is not None:
                    process.poll()
                time.sleep(0.05)
        except BaseException as error:
            failure("preliminary-observation", error)
        # This does not depend on successful enumeration, a leader PID, or a
        # populated read. The already-open owned cgroup is the kill anchor.
        try:
            self.write("cgroup.kill", "1")
            kill_attempted, kill_succeeded = True, True
        except BaseException as error:
            kill_attempted, kill_succeeded = True, False
            failure("kernel-kill", error)
        gone = False
        while time.monotonic() < deadline:
            try:
                if process is not None:
                    process.poll()
                if not self.populated():
                    gone = True
                    break
            except BaseException as error:
                failure("terminal-observation", error)
                break
            time.sleep(0.05)
        all_reaped = False
        if gone:
            try:
                if process is not None:
                    process.wait(timeout=max(0.01, deadline - time.monotonic()))
                while time.monotonic() < deadline:
                    try:
                        pid, status = os.waitpid(-1, os.WNOHANG)
                    except ChildProcessError:
                        all_reaped = True
                        break
                    if pid:
                        reaped.append({"pid": pid, "status": status})
                    else:
                        time.sleep(0.01)
            except BaseException as error:
                failure("reap", error)
        if gone:
            try:
                self.close_empty()
            except BaseException as error:
                failure("release-cgroup", error)
        return {"path": str(self.path), "term_pidfds": signals, "populated": not gone,
                "leader_handle_returned": process is not None,
                "leader_reaped": process is not None and process.returncode is not None,
                "errors": errors, "adopted_reaped": reaped, "all_children_reaped": all_reaped,
                "kernel_kill_attempted": kill_attempted, "kernel_kill_succeeded": kill_succeeded,
                "verdict": "CLEAN" if gone and all_reaped and kill_succeeded and not errors else "UNKNOWN"}
