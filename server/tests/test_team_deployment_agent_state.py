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
        agent_state.writer("agent", tmp_path)


def test_an_age_binary_other_than_the_pinned_one_refuses(tmp_path):
    impostor = tmp_path / "age"
    impostor.write_text("#!/bin/sh\necho v1.3.2\n")
    impostor.chmod(0o755)
    with pytest.raises(agent_state.Refused, match="is not the pinned age binary"):
        agent_state.pinned_age(impostor, "0" * 64)
