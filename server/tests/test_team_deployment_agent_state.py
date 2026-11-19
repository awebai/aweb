"""deploy/team/agent_state.py: one agent state as a checked tar stream and
back (aweb-acwd.25.1). The stream is what the CLI encrypts with age to its
recipients and decrypts again. These tests drive the stream on real
directories, and the child-process boundary with real child processes that
stand where age stands (a hang, a failing exit, a partial stream): what they
test is this module's ownership of the child, not age. age itself runs in the
lab's functional packet."""

import importlib.util
import io
import json
import os
import socket
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

TEAM = Path(__file__).resolve().parents[2] / "deploy" / "team"
sys.path.insert(0, str(TEAM))
spec = importlib.util.spec_from_file_location("agent_state", TEAM / "agent_state.py")
agent_state = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent_state)

WAKE = "home/.config/aw/wake"


def state(base: Path) -> Path:
    """An agent's state: an OATS home with its links, a seat, and aw's wake store."""
    root = base / "state"
    instance = root / "deploy" / "agents" / "soul" / "instances" / "one"
    (instance / ".agents" / "skills").mkdir(parents=True)
    (instance / ".claude").mkdir()
    (instance / "AGENTS.md").write_text("instructions")
    (instance / "CLAUDE.md").symlink_to("AGENTS.md")
    (instance / ".claude" / "skills").symlink_to("../.agents/skills")
    seat = root / "seats" / "one" / ".aw"
    (seat / "run").mkdir(parents=True)
    (seat / "signing.key").write_text("key")
    (seat / "signing.key").chmod(0o600)
    (root / WAKE / "registry.d").mkdir(parents=True)
    root.chmod(0o700)
    return root


def bind(path: Path) -> socket.socket:
    """A listening Unix socket at path (bound from its directory: the full
    path may pass the platform's limit)."""
    here = os.getcwd()
    os.chdir(path.parent)
    try:
        listener = socket.socket(socket.AF_UNIX)
        listener.bind(path.name)
    finally:
        os.chdir(here)
    return listener


def capture(root: Path, endpoints=None) -> tuple[bytes, dict]:
    sink = io.BytesIO()
    inventory = agent_state.capture(root, sink, endpoints or agent_state.DEFAULT_ENDPOINTS)
    return sink.getvalue(), inventory


# --- what a capture holds and leaves out ------------------------------------


def test_the_declared_endpoints_at_their_configured_roots_are_recorded_omissions(tmp_path):
    root = state(tmp_path)
    endpoints = agent_state.Endpoints([WAKE], ["seats/one/.aw"])
    sockets = [bind(root / WAKE / "control.sock"), bind(root / "seats" / "one" / ".aw" / "run" / "custody.sock")]
    try:
        stream, inventory = capture(root, endpoints)
    finally:
        for listener in sockets:
            listener.close()
    assert inventory["omitted"] == [
        {"path": f"{WAKE}/control.sock", "type": "socket",
         "reason": f"aw wake broker control socket of the store {WAKE}"},
        {"path": "seats/one/.aw/run/custody.sock", "type": "socket",
         "reason": "aw custody socket of the grant home seats/one/.aw"},
    ]
    with tarfile.open(fileobj=io.BytesIO(stream)) as tar:
        names = tar.getnames()
    assert inventory["members"] == len(names)
    assert not [name for name in names if name.endswith(".sock")]


@pytest.mark.parametrize("where", [
    f"{WAKE}/registry.d/control.sock",  # not the store itself
    "seats/one/.aw/run/custody.sock",  # no custody root is configured by default
    "home/queue",
])
def test_a_socket_no_configured_rule_names_refuses_the_capture(tmp_path, where):
    root = state(tmp_path)
    listener = bind(root / where)
    try:
        with pytest.raises(agent_state.Refused, match=f"{where}: a socket no declared rule recreates"):
            capture(root)
    finally:
        listener.close()


def test_a_fifo_refuses_the_capture_even_at_a_declared_place(tmp_path):
    root = state(tmp_path)
    os.mkfifo(root / WAKE / "control.sock")
    with pytest.raises(agent_state.Refused, match="control.sock: a FIFO no declared rule recreates"):
        capture(root)


def test_a_directory_the_walk_cannot_read_refuses_the_capture(tmp_path):
    root = state(tmp_path)
    locked = root / "seats" / "one" / ".aw" / "run"
    locked.chmod(0o000)
    try:
        with pytest.raises(agent_state.Refused, match="run: cannot be read .*no backup is complete without it"):
            capture(root)
    finally:
        locked.chmod(0o700)


def test_links_come_after_every_other_member_of_the_stream(tmp_path):
    stream, _ = capture(state(tmp_path))
    with tarfile.open(fileobj=io.BytesIO(stream)) as tar:
        kinds = ["link" if member.issym() else "other" for member in tar.getmembers()]
    assert kinds == sorted(kinds, key=lambda kind: kind == "link") and "link" in kinds


# --- restore ---------------------------------------------------------------


def test_a_capture_and_a_restore_round_trip_the_state(tmp_path):
    root = state(tmp_path)
    stream, inventory = capture(root)
    target = tmp_path / "restored"
    restored = agent_state.restore(lambda: io.BytesIO(stream), target, inventory["members"])
    assert restored == inventory["members"]
    assert os.readlink(target / "deploy/agents/soul/instances/one/CLAUDE.md") == "AGENTS.md"
    assert (target / "seats/one/.aw/signing.key").read_text() == "key"
    assert oct((target / "seats/one/.aw/signing.key").stat().st_mode & 0o7777) == "0o600"
    assert oct(target.stat().st_mode & 0o7777) == "0o700"


def crafted(*members: tuple[str, bytes, str]) -> bytes:
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for name, kind, link in members:
            info = tarfile.TarInfo(name)
            info.type = kind
            info.linkname = link
            info.mode = 0o700
            tar.addfile(info, io.BytesIO(b"") if kind == tarfile.REGTYPE else None)
    return out.getvalue()


TWO = crafted((".", tarfile.DIRTYPE, ""), ("./b", tarfile.REGTYPE, ""))


@pytest.mark.parametrize("stream, count, refusal", [
    (crafted((".", tarfile.DIRTYPE, ""), ("./a", tarfile.SYMTYPE, "b"), ("./b", tarfile.REGTYPE, "")), 3,
     "./b: after a link; every link comes last"),
    (crafted((".", tarfile.DIRTYPE, ""), ("./a", tarfile.SYMTYPE, "../out")), 2, "a link out of the archive"),
    (TWO, 3, "2 members, not the 3 the manifest records"),
    (b"not a tar stream at all" * 1000, 1, "header"),
])
def test_a_restore_refuses_before_writing_anything(tmp_path, stream, count, refusal):
    target = tmp_path / "restored"
    with pytest.raises(agent_state.Refused, match=refusal):
        agent_state.restore(lambda: io.BytesIO(stream), target, count)
    assert not os.path.lexists(target)


def test_a_restore_through_a_linked_parent_refuses_and_writes_nothing(tmp_path):
    (tmp_path / "real").mkdir()
    (tmp_path / "linked").symlink_to(tmp_path / "real")
    with pytest.raises(agent_state.Refused, match="reached through a symbolic link"):
        agent_state.restore(lambda: io.BytesIO(TWO), tmp_path / "linked" / "restored", 2)
    assert list((tmp_path / "real").iterdir()) == []


def test_a_restore_under_a_parent_others_can_change_refuses(tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o777)
    with pytest.raises(agent_state.Refused, match="shared is writable by others"):
        agent_state.restore(lambda: io.BytesIO(TWO), shared / "restored", 2)
    assert not os.path.lexists(shared / "restored")


def test_a_second_read_that_differs_from_the_checked_one_stops_the_restore(tmp_path):
    second = crafted((".", tarfile.DIRTYPE, ""), ("./c", tarfile.REGTYPE, ""))
    reads = iter([TWO, second])
    with pytest.raises(agent_state.Refused, match="differs from the checked one at ./c; .* is incomplete"):
        agent_state.restore(lambda: io.BytesIO(next(reads)), tmp_path / "restored", 2)


def test_a_restore_writes_only_where_nothing_is(tmp_path):
    (tmp_path / "dangling").symlink_to(tmp_path / "nowhere")
    with pytest.raises(agent_state.Refused, match="exists"):
        agent_state.restore(lambda: io.BytesIO(TWO), tmp_path / "dangling", 2)


# --- the child process at the boundary --------------------------------------


def child(tmp_path: Path, name: str, body: str) -> list[str]:
    script = tmp_path / f"{name}.py"
    script.write_text("import sys, time\n" + body)
    return [sys.executable, str(script)]


def emits(tmp_path: Path, name: str, data: bytes, then: str) -> list[str]:
    (tmp_path / f"{name}.bin").write_bytes(data)
    return child(tmp_path, name, f"sys.stdout.buffer.write(open({str(tmp_path / f'{name}.bin')!r}, 'rb').read())\n"
                                 f"sys.stdout.buffer.flush()\n{then}\n")


def test_a_decrypt_that_fails_after_a_whole_stream_refuses_before_the_target_exists(tmp_path):
    # age writes plaintext as it authenticates each chunk and fails at the
    # first bad one: a whole-looking stream with a failed exit is no archive.
    command = emits(tmp_path, "fails", TWO, "sys.exit(1)")
    target = tmp_path / "restored"
    with pytest.raises(agent_state.Refused, match="exited 1"):
        agent_state.restore(lambda: agent_state.Decrypted(command, 30), target, 2)
    assert not os.path.lexists(target)


def test_a_decrypt_that_hangs_is_killed_at_its_deadline_and_reaped(tmp_path):
    command = emits(tmp_path, "hangs", TWO[:1024], "time.sleep(600)")
    children = []

    def read():
        children.append(agent_state.Decrypted(command, 2))
        return children[-1]

    with pytest.raises(agent_state.Refused, match="passed its deadline and was killed"):
        agent_state.restore(read, tmp_path / "restored", 2)
    assert children[0].process.returncode is not None
    assert not os.path.lexists(tmp_path / "restored")


def test_a_decrypt_whose_output_is_no_archive_is_killed_and_reaped_with_the_first_error_kept(tmp_path):
    # More than tarfile's 10 KiB stream record, so the parser fails without waiting on the child.
    command = emits(tmp_path, "garbage", b"x" * 20480, "time.sleep(600)")
    children = []

    def read():
        children.append(agent_state.Decrypted(command, 60))
        return children[-1]

    with pytest.raises(agent_state.Refused) as refused:
        agent_state.restore(read, tmp_path / "restored", 2)
    assert "exited -9" in str(refused.value) and children[0].process.returncode == -9


def test_an_encrypt_that_fails_leaves_no_partial_and_says_why(tmp_path):
    root = state(tmp_path)
    partial = tmp_path / "state.tar.age.partial"
    command = child(tmp_path, "encrypt-fails",
                    f"open({str(partial)!r}, 'wb').write(sys.stdin.buffer.read(10))\nsys.exit(3)")
    with pytest.raises(agent_state.Refused, match="exited 3; no backup was written"):
        agent_state.encrypt(root, partial, command, 30, agent_state.DEFAULT_ENDPOINTS)
    assert not partial.exists()


def test_an_encrypt_that_hangs_is_killed_at_its_deadline_and_leaves_no_partial(tmp_path):
    root = state(tmp_path)
    # Enough state to fill the pipe, so the capture blocks on a child that reads nothing.
    (root / "home" / "large").write_bytes(os.urandom(1 << 20))
    partial = tmp_path / "state.tar.age.partial"
    command = child(tmp_path, "encrypt-hangs", f"open({str(partial)!r}, 'wb').write(b'x')\ntime.sleep(600)")
    with pytest.raises(agent_state.Refused, match="passed its deadline and was killed; no backup was written"):
        agent_state.encrypt(root, partial, command, 2, agent_state.DEFAULT_ENDPOINTS)
    assert not partial.exists()


def test_the_encrypt_stream_holds_the_state_when_the_child_succeeds(tmp_path):
    root = state(tmp_path)
    out = tmp_path / "copied.tar"
    command = child(tmp_path, "copies", f"open({str(out)!r}, 'wb').write(sys.stdin.buffer.read())")
    inventory = agent_state.encrypt(root, out, command, 30, agent_state.DEFAULT_ENDPOINTS)
    with tarfile.open(out) as tar:
        assert len(tar.getmembers()) == inventory["members"]


# --- the writer and the daemon's answers ------------------------------------


def answer(rc: int, stdout: str, stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess([], rc, stdout, stderr)


def line(name: str, state: str = "exited", identity: str = "c1") -> str:
    return json.dumps({"ID": identity, "Names": name, "State": state})


def test_a_failed_or_mixed_answer_is_never_absence():
    # Reproduced by servers: rc 125, a stray line, and a diagnostic naming another container.
    with pytest.raises(agent_state.Refused, match="docker container ls failed"):
        agent_state.listed(answer(125, "unexpected data", "permission denied; no such container: another-name"),
                           "intended-name")
    with pytest.raises(agent_state.Refused, match="docker container ls failed"):
        agent_state.listed(answer(0, "", "Cannot connect to the Docker daemon"), "agent")
    with pytest.raises(agent_state.Refused, match="unreadable line"):
        agent_state.listed(answer(0, "unexpected data\n"), "agent")


def test_the_container_is_found_by_its_exact_name_only():
    assert agent_state.listed(answer(0, ""), "agent") is None
    assert agent_state.listed(answer(0, line("agent-two") + "\n"), "agent") is None
    assert agent_state.listed(answer(0, line("agent", "running") + "\n"), "agent") == {"id": "c1", "state": "running"}
    assert agent_state.listed(answer(0, line("other,agent") + "\n"), "agent") == {"id": "c1", "state": "exited"}
    with pytest.raises(agent_state.Refused, match="2 containers are named agent"):
        agent_state.listed(answer(0, line("agent") + "\n" + line("agent", identity="c2") + "\n"), "agent")


def test_with_no_daemon_to_ask_the_writer_is_not_fenced(tmp_path, monkeypatch):
    monkeypatch.setitem(agent_state.DOCKER_ENV, "PATH", str(tmp_path))
    with pytest.raises(agent_state.Refused, match="docker info failed"):
        agent_state.writer("agent")


def fake_age(directory: Path, version: str = "v1.3.2") -> tuple[Path, str]:
    import hashlib

    directory.mkdir(parents=True, exist_ok=True)
    binary = directory / "age"
    binary.write_text(f"#!/bin/sh\necho {version}\n")
    binary.chmod(0o755)
    return binary, hashlib.sha256(binary.read_bytes()).hexdigest()


def test_an_age_binary_other_than_the_pinned_one_refuses(tmp_path):
    impostor, _ = fake_age(tmp_path / "bin")
    with pytest.raises(agent_state.Refused, match="is not the pinned age binary"):
        agent_state.pinned_age(impostor, "0" * 64)


def test_the_pinned_age_is_one_absolute_file_hashed_and_run_by_the_same_path(tmp_path):
    binary, pin = fake_age(tmp_path / "bin")
    (tmp_path / "linked").symlink_to(binary)
    path, version = agent_state.pinned_age(tmp_path / "linked", pin)
    assert path == str(binary) and version == "v1.3.2"


def test_a_relative_age_is_refused_whatever_path_would_find(tmp_path, monkeypatch):
    # "./age" becomes the bare name "age" through pathlib, which PATH resolves:
    # the file hashed and the file run could differ.
    here, pin = fake_age(tmp_path / "here")
    other, _ = fake_age(tmp_path / "elsewhere", version="v0.0.0-other")
    monkeypatch.chdir(tmp_path / "here")
    monkeypatch.setenv("PATH", str(other.parent))
    with pytest.raises(agent_state.Refused, match="not an absolute path"):
        agent_state.pinned_age(Path("./age"), pin)


@pytest.mark.parametrize("make_open", [
    lambda binary: binary.chmod(0o777),
    lambda binary: binary.parent.chmod(0o777),
])
def test_an_age_others_can_replace_is_refused(tmp_path, make_open):
    binary, pin = fake_age(tmp_path / "bin")
    make_open(binary)
    with pytest.raises(agent_state.Refused, match="writable by others"):
        agent_state.pinned_age(binary, pin)


def test_an_interrupt_while_the_last_read_drains_the_child_kills_and_reaps_it(tmp_path):
    # Reproduced by servers: a child that writes a whole archive and then
    # sleeps holds the final drain; an interrupt there must still end it.
    import signal
    import threading
    import time

    command = emits(tmp_path, "drain", TWO, "time.sleep(120)")
    children = []
    draining = threading.Event()

    class Observed(agent_state.Decrypted):
        """The real Decrypted, with the test seeing when its final drain begins."""

        def close(self) -> None:
            draining.set()
            super().close()

    def read():
        children.append(Observed(command, 60))
        return children[-1]

    # A process started in the background may inherit SIGINT ignored: this
    # test installs Python's own handler, so the interrupt is raised here.
    previous = signal.signal(signal.SIGINT, signal.default_int_handler)
    try:
        # The interrupt comes once close() has begun its drain, which then
        # waits on the sleeping child. (The drain may already be blocked or
        # just about to read; either way the interrupt lands in close().)
        def interrupt():
            if draining.wait(30):
                time.sleep(0.2)
            os.kill(os.getpid(), signal.SIGINT)

        threading.Thread(target=interrupt, daemon=True).start()
        with pytest.raises(KeyboardInterrupt):
            agent_state.read_whole(read, lambda tar: list(tar))
    finally:
        signal.signal(signal.SIGINT, previous)
    assert draining.is_set(), "the interrupt did not come during the final drain"
    assert children[0].process.returncode is not None


def test_a_failed_exit_found_at_the_final_drain_is_reported_once_and_reaped(tmp_path):
    command = emits(tmp_path, "late-failure", TWO, "sys.exit(1)")
    children = []

    def read():
        children.append(agent_state.Decrypted(command, 30))
        return children[-1]

    with pytest.raises(agent_state.Refused) as refused:
        agent_state.read_whole(read, lambda tar: list(tar))
    assert str(refused.value).count("exited 1") == 1
    assert children[0].process.returncode == 1


def test_a_terminated_cli_ends_its_age_child_and_leaves_no_partial(tmp_path):
    # SIGTERM to the CLI is turned into the same cleanup as an interrupt. The
    # docker and age here are stand-ins at the process boundary: what is
    # tested is the CLI's ownership of its child, not docker or age.
    import hashlib
    import signal
    import time

    root = state(tmp_path)
    # More than any pipe buffer: the stand-in never reads, so the CLI is
    # blocked writing the archive when the signal comes. Ending must not
    # first try to finish the archive into that full pipe.
    (root / "home" / "large").write_bytes(os.urandom(1 << 20))
    out = tmp_path / "backup"
    started = tmp_path / "started"
    fake_age = tmp_path / "age"
    fake_age.write_text(f"#!{sys.executable}\nimport sys, time\n"
                        "if sys.argv[1:] == ['--version']:\n    print('v1.3.2'); sys.exit(0)\n"
                        f"open({str(started)!r}, 'w').close()\n"
                        "out = sys.argv[sys.argv.index('--output') + 1]\n"
                        "open(out, 'wb').write(b'partial')\n"
                        "time.sleep(600)\n")
    fake_age.chmod(0o755)
    pin = hashlib.sha256(fake_age.read_bytes()).hexdigest()
    recipients = tmp_path / "recipients"
    recipients.write_text("age1fictional\n")
    # The writer is absent: a docker that lists no container.
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "docker").write_text("#!/bin/sh\ncase \"$1\" in info) echo daemon-1 ;; *) ;; esac\n")
    (bin_dir / "docker").chmod(0o755)
    err = open(tmp_path / "cli.err", "w")
    cli = subprocess.Popen(
        [sys.executable, "-c",
         "import sys; sys.path.insert(0, sys.argv[1]); import agent_state; "
         "agent_state.DOCKER_ENV['PATH'] = sys.argv[2]; sys.exit(agent_state.main(sys.argv[3:]))",
         str(TEAM), str(bin_dir), "capture", "--state", str(root), "--container", "agent", "--age", str(fake_age),
         "--age-sha256", pin, "--recipients", str(recipients), "--out", str(out), "--deadline", "600"],
        stderr=err, start_new_session=True)
    try:
        # The age stand-in marks that it has started writing; the signal comes after.
        deadline = time.monotonic() + 30
        while not started.exists():
            assert time.monotonic() < deadline and cli.poll() is None, "the capture never started its age"
            time.sleep(0.05)
        cli.send_signal(signal.SIGTERM)
        # stderr is a file, not a pipe: a child the CLI left behind cannot
        # hold this wait open, so the ownership assertion below decides.
        cli.wait(timeout=30)
        stderr = (tmp_path / "cli.err").read_text()
        # Observed before any cleanup of the test's own: what the CLI left.
        left = sorted(path.name for path in out.iterdir())
        try:
            os.killpg(cli.pid, 0)
            group_gone = False
        except ProcessLookupError:
            group_gone = True
    finally:
        err.close()
        # Only a failed test reaches here with work left; it is ended so as
        # not to outlive the test.
        try:
            os.killpg(cli.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    assert cli.returncode == 143 and "terminated" in stderr
    assert left == []
    assert group_gone, "the CLI left a process in its group (its age child)"


def test_a_refused_mode_change_fails_the_restore_and_names_the_incomplete_target(tmp_path, monkeypatch):
    stream, inventory = capture(state(tmp_path))

    def refused(path, mode, **kwargs):
        raise PermissionError(1, "Operation not permitted", str(path))

    monkeypatch.setattr(os, "chmod", refused)
    target = tmp_path / "restored"
    with pytest.raises(agent_state.Refused, match=f"{target} is incomplete"):
        agent_state.restore(lambda: io.BytesIO(stream), target, inventory["members"])


def test_the_restore_command_refuses_to_run_unprivileged(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    code = agent_state.main(["restore", "--backup", str(tmp_path), "--container", "agent", "--age", "/usr/bin/age",
                             "--age-sha256", "0" * 64, "--identity", str(tmp_path / "id"),
                             "--target", str(tmp_path / "restored")])
    assert code == 1 and "runs as root" in capsys.readouterr().err


def daemon_answers(monkeypatch, listing: str) -> None:
    """The local daemon's answers to writer(), substituted in process: what
    is tested is how writer() reads them."""
    def docker(*args):
        if args[0] == "info":
            return answer(0, "daemon-1\n")
        if args[:2] == ("container", "ls"):
            return answer(0, listing)
        raise AssertionError(f"writer() asked docker {args}")
    monkeypatch.setattr(agent_state, "docker", docker)


def test_the_capture_fence_is_the_container_removed(tmp_path, monkeypatch):
    # The supported sequence: stop, remove the verified container, rename the
    # state directory (its bind then refuses any restart), capture the renamed
    # directory. A container still there, stopped or not, is no fence.
    for state in ("exited", "created", "running"):
        daemon_answers(monkeypatch, line("agent", state) + "\n")
        with pytest.raises(agent_state.Refused, match="remove the verified container"):
            agent_state.writer("agent")


def test_with_the_container_removed_the_capture_records_the_daemon_and_its_absence(tmp_path, monkeypatch):
    daemon_answers(monkeypatch, line("agent-two") + "\n")
    assert agent_state.writer("agent") == {"daemon": "daemon-1", "container": "agent", "state": "absent"}


def test_an_interrupt_as_a_decrypt_child_is_acquired_still_ends_it(tmp_path):
    # Deterministic: the interrupt is sent inside read(), after the child
    # exists and before read_whole holds it.
    import signal

    command = emits(tmp_path, "acquired", TWO, "time.sleep(120)")
    children = []

    def read():
        children.append(agent_state.Decrypted(command, 60))
        os.kill(os.getpid(), signal.SIGINT)
        return children[-1]

    previous = signal.signal(signal.SIGINT, signal.default_int_handler)
    try:
        with pytest.raises(KeyboardInterrupt):
            agent_state.read_whole(read, lambda tar: list(tar))
    finally:
        signal.signal(signal.SIGINT, previous)
    assert children[0].process.returncode is not None


def test_an_interrupt_as_an_encrypt_child_is_acquired_still_ends_it(tmp_path, monkeypatch):
    import signal

    root = state(tmp_path)
    partial = tmp_path / "state.tar.age.partial"
    children = []

    class Interrupted(agent_state.Child):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            children.append(self)
            os.kill(os.getpid(), signal.SIGINT)

    monkeypatch.setattr(agent_state, "Child", Interrupted)
    command = child(tmp_path, "encrypt-sleeps", "time.sleep(120)")
    previous = signal.signal(signal.SIGINT, signal.default_int_handler)
    try:
        with pytest.raises(KeyboardInterrupt):
            agent_state.encrypt(root, partial, command, 60, agent_state.DEFAULT_ENDPOINTS)
    finally:
        signal.signal(signal.SIGINT, previous)
    assert children[0].process.returncode is not None
    assert not partial.exists()


def test_a_child_started_while_signals_are_held_does_not_inherit_the_hold(tmp_path):
    # The hold covers only the parent's acquisition: a child that inherited
    # it would ignore the SIGTERM that ends it.
    import signal

    probe = [sys.executable, "-c", "import signal; print(sorted(int(s) for s in signal.pthread_sigmask(signal.SIG_BLOCK, [])))"]
    with agent_state.signals_held():
        child = agent_state.Child(probe, 30, stdout=subprocess.PIPE, text=True)
    out, _ = child.process.communicate(timeout=30)
    child.finish()
    blocked = json.loads(out)
    assert int(signal.SIGTERM) not in blocked and int(signal.SIGINT) not in blocked


def test_no_child_is_launched_with_python_code_between_fork_and_exec(tmp_path, monkeypatch):
    # preexec_fn runs Python in the forked child, which can deadlock once
    # threads exist (the deadline timers); no launch may use it.
    seen = []
    real = subprocess.Popen

    def recording(*args, **kwargs):
        seen.append(kwargs)
        return real(*args, **kwargs)

    monkeypatch.setattr(agent_state.subprocess, "Popen", recording)
    child = agent_state.Child([sys.executable, "-c", "pass"], 30)
    child.finish()
    decrypted = agent_state.Decrypted([sys.executable, "-c", "pass"], 30)
    decrypted.close()
    assert seen and all("preexec_fn" not in kwargs for kwargs in seen)


def test_a_launch_refuses_a_command_that_is_not_an_absolute_path():
    with pytest.raises(agent_state.Refused, match="not an absolute path"):
        agent_state.Child(["age", "--version"], 30)


def test_a_second_launch_while_the_first_timer_thread_lingers_completes_unheld(tmp_path):
    # The reviewer's sequence: one age child ends, its timer thread is kept
    # alive (teardown delayed), and the next child is launched with SIGINT
    # and SIGTERM held. Run in its own process under an external timeout, so
    # a stall fails this test instead of hanging the suite.
    script = tmp_path / "second.py"
    script.write_text(f"""
import json, subprocess, sys, threading, time
sys.path.insert(0, {str(TEAM)!r})
import agent_state

lingering = threading.Event()
real_cancel = threading.Timer.cancel

def delayed_cancel(self):
    real_cancel(self)
    # Keep a thread alive through the next launch, as a slow teardown would.
    threading.Thread(target=lingering.wait, args=(5,), daemon=True).start()

threading.Timer.cancel = delayed_cancel
probe = [sys.executable, "-c", "import signal; print(sorted(int(s) for s in signal.pthread_sigmask(signal.SIG_BLOCK, [])))"]
first = agent_state.Decrypted([sys.executable, "-c", "pass"], 30)
first.close()
assert threading.active_count() > 1
with agent_state.signals_held():
    second = agent_state.Child(probe, 30, stdout=subprocess.PIPE, text=True)
out, _ = second.process.communicate(timeout=30)
second.finish()
lingering.set()
print(out.strip())
""")
    answer = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, timeout=60)
    assert answer.returncode == 0, answer.stderr
    blocked = json.loads(answer.stdout.strip().splitlines()[-1])
    import signal
    assert int(signal.SIGTERM) not in blocked and int(signal.SIGINT) not in blocked
