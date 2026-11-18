"""deploy/team/agent_state.py: one agent state as a checked tar stream and
back (aweb-acwd.25.1). The stream is what the CLI encrypts with age to its
recipients and decrypts again; these tests drive the stream itself on real
directories."""

import importlib.util
import io
import os
import socket
import sys
import tarfile
from pathlib import Path

import pytest

TEAM = Path(__file__).resolve().parents[2] / "deploy" / "team"
sys.path.insert(0, str(TEAM))
spec = importlib.util.spec_from_file_location("agent_state", TEAM / "agent_state.py")
agent_state = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent_state)


def state(base: Path) -> Path:
    """An agent's state: an OATS home with its links, a seat, and the two
    endpoints aw's daemons create and create again when they start."""
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
    (root / "home" / ".config" / "aw" / "wake" / "b1").mkdir(parents=True)
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


def capture(root: Path) -> tuple[bytes, dict]:
    sink = io.BytesIO()
    inventory = agent_state.capture(root, sink)
    return sink.getvalue(), inventory


def test_a_state_with_the_declared_endpoints_captures_them_as_omissions_with_their_rule(tmp_path):
    root = state(tmp_path)
    sockets = [bind(root / "seats" / "one" / ".aw" / "run" / "custody.sock"),
               bind(root / "home" / ".config" / "aw" / "wake" / "b1" / "control.sock")]
    try:
        stream, inventory = capture(root)
    finally:
        for listener in sockets:
            listener.close()
    assert inventory["omitted"] == [
        {"path": "home/.config/aw/wake/b1/control.sock", "type": "socket", "reason": "aw wake broker control socket"},
        {"path": "seats/one/.aw/run/custody.sock", "type": "socket", "reason": "aw custody socket"},
    ]
    with tarfile.open(fileobj=io.BytesIO(stream)) as tar:
        names = tar.getnames()
    assert inventory["members"] == len(names)
    assert not [name for name in names if name.endswith(".sock")]


@pytest.mark.parametrize("make, what", [
    (lambda path: bind(path), "socket"),
    (lambda path: os.mkfifo(path), "FIFO"),
])
def test_an_undeclared_socket_or_fifo_refuses_the_capture(tmp_path, make, what):
    root = state(tmp_path)
    held = make(root / "home" / "queue")
    try:
        with pytest.raises(agent_state.Refused, match=f"home/queue: a {what} no declared rule recreates"):
            capture(root)
    finally:
        if held is not None:
            held.close()


def test_a_declared_name_of_the_wrong_kind_is_not_omitted(tmp_path):
    # A FIFO named like the custody socket is not the socket aw recreates.
    root = state(tmp_path)
    os.mkfifo(root / "seats" / "one" / ".aw" / "run" / "custody.sock")
    with pytest.raises(agent_state.Refused, match="custody.sock: a FIFO no declared rule recreates"):
        capture(root)


def test_links_come_after_every_other_member_of_the_stream(tmp_path):
    stream, _ = capture(state(tmp_path))
    with tarfile.open(fileobj=io.BytesIO(stream)) as tar:
        kinds = ["link" if member.issym() else "other" for member in tar.getmembers()]
    assert kinds == sorted(kinds, key=lambda kind: kind == "link") and "link" in kinds


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


@pytest.mark.parametrize("stream, count, refusal", [
    (crafted((".", tarfile.DIRTYPE, ""), ("./a", tarfile.SYMTYPE, "b"), ("./b", tarfile.REGTYPE, "")), 3,
     "./b: after a link; every link comes last"),
    (crafted((".", tarfile.DIRTYPE, ""), ("./a", tarfile.SYMTYPE, "../out")), 2, "a link out of the archive"),
    (crafted((".", tarfile.DIRTYPE, ""), ("./b", tarfile.REGTYPE, "")), 3, "2 members, not the 3 the manifest records"),
])
def test_a_restore_refuses_before_writing_anything(tmp_path, stream, count, refusal):
    target = tmp_path / "restored"
    with pytest.raises(agent_state.Refused, match=refusal):
        agent_state.restore(lambda: io.BytesIO(stream), target, count)
    assert not os.path.lexists(target)


def test_a_second_read_that_differs_from_the_checked_one_stops_the_restore(tmp_path):
    first = crafted((".", tarfile.DIRTYPE, ""), ("./b", tarfile.REGTYPE, ""))
    second = crafted((".", tarfile.DIRTYPE, ""), ("./c", tarfile.REGTYPE, ""))
    reads = iter([first, second])
    with pytest.raises(agent_state.Refused, match="the second read differs from the checked one at ./c"):
        agent_state.restore(lambda: io.BytesIO(next(reads)), tmp_path / "restored", 2)


def test_a_restore_writes_only_where_nothing_is(tmp_path):
    stream, inventory = capture(state(tmp_path))
    (tmp_path / "dangling").symlink_to(tmp_path / "nowhere")
    with pytest.raises(agent_state.Refused, match="exists"):
        agent_state.restore(lambda: io.BytesIO(stream), tmp_path / "dangling", inventory["members"])


def test_an_age_binary_other_than_the_pinned_one_refuses(tmp_path):
    impostor = tmp_path / "age"
    impostor.write_text("#!/bin/sh\necho v1.2.1\n")
    impostor.chmod(0o755)
    with pytest.raises(agent_state.Refused, match="is not the pinned age binary"):
        agent_state.pinned_age(impostor, "0" * 64)


def test_a_failed_look_at_the_writer_is_no_fence(tmp_path, monkeypatch):
    # With no docker to ask, the writer's state is unknown: the capture refuses.
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(agent_state.Refused, match="docker container inspect agent failed"):
        agent_state.container_state("agent")
