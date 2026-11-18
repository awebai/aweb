"""deploy/team/state_archive.py: a directory as a tar archive and back, owners,
modes and symbolic links kept, with every path and link checked before
anything is written (aweb-acwd.25.1). An OATS home holds links
(CLAUDE.md -> AGENTS.md, .claude/skills -> ../.agents/skills), so an archive
that refuses every link refuses every agent's state."""

import importlib.util
import io
import os
import socket
import tarfile
from pathlib import Path

import pytest

TEAM = Path(__file__).resolve().parents[2] / "deploy" / "team"
spec = importlib.util.spec_from_file_location("state_archive", TEAM / "state_archive.py")
state_archive = importlib.util.module_from_spec(spec)
spec.loader.exec_module(state_archive)


def home(base: Path) -> Path:
    """An agent's state with an OATS instance home in its deployment."""
    root = base / "state"
    instance = root / "deploy" / "agents" / "soul" / "instances" / "one"
    (instance / ".agents" / "skills" / "skill").mkdir(parents=True)
    (instance / ".claude").mkdir()
    (instance / "AGENTS.md").write_text("instructions")
    (instance / "CLAUDE.md").symlink_to("AGENTS.md")
    (instance / ".claude" / "skills").symlink_to("../.agents/skills")
    (instance / ".agents" / "skills" / "skill" / "SKILL.md").write_text("a skill")
    (root / "seats" / "one" / ".aw").mkdir(parents=True)
    (root / "seats" / "one" / ".aw" / "signing.key").write_text("key")
    (root / "seats" / "one" / ".aw" / "signing.key").chmod(0o600)
    (root / "bin").mkdir()
    (root / "bin" / "tool").write_text("#!/bin/sh\n")
    (root / "bin" / "tool").chmod(0o750)
    (root / "shared").mkdir()
    (root / "shared").chmod(0o2750)
    for directory in (root, root / "seats", root / "seats" / "one", root / "seats" / "one" / ".aw"):
        directory.chmod(0o700)
    return root


def tree(root: Path) -> dict[str, tuple]:
    """Every entry under root, not following links: its kind, mode, and its
    bytes or link target."""
    entries = {}
    for path in sorted(root.rglob("*")):
        relative = str(path.relative_to(root))
        info = path.lstat()
        if path.is_symlink():
            entries[relative] = ("link", os.readlink(path))
        elif path.is_dir():
            entries[relative] = ("dir", oct(info.st_mode & 0o7777))
        else:
            entries[relative] = ("file", oct(info.st_mode & 0o7777), path.read_bytes())
    return entries


def test_an_agents_state_with_an_oats_home_round_trips_with_its_links_and_modes(tmp_path):
    root = home(tmp_path)
    archive = tmp_path / "state.tar"
    assert state_archive.pack(root, archive) == []
    restored = tmp_path / "restored"
    state_archive.unpack(archive, restored)
    assert tree(restored) == tree(root)
    assert oct(restored.stat().st_mode & 0o7777) == "0o700"
    instance = restored / "deploy" / "agents" / "soul" / "instances" / "one"
    assert os.readlink(instance / "CLAUDE.md") == "AGENTS.md"
    assert (instance / ".claude" / "skills" / "skill" / "SKILL.md").read_text() == "a skill"


def test_the_archive_records_each_entrys_numeric_owner(tmp_path):
    root = home(tmp_path)
    archive = tmp_path / "state.tar"
    state_archive.pack(root, archive)
    with tarfile.open(archive) as tar:
        members = {member.name: member for member in tar.getmembers()}
    key = members["./seats/one/.aw/signing.key"]
    assert (key.uid, key.gid) == (os.getuid(), (root / "seats" / "one" / ".aw" / "signing.key").stat().st_gid)


def test_a_left_out_member_is_left_out_with_everything_under_it(tmp_path):
    root = home(tmp_path)
    archive = tmp_path / "state.tar"
    state_archive.pack(root, archive, left_out=["./seats"])
    with tarfile.open(archive) as tar:
        names = tar.getnames()
    assert not [name for name in names if name == "./seats" or name.startswith("./seats/")]


def test_a_socket_or_a_fifo_is_left_out_and_reported(tmp_path):
    root = home(tmp_path)
    os.mkfifo(root / "pipe")
    # A Unix socket path is limited in length; bind it from inside the state.
    here = os.getcwd()
    os.chdir(root)
    try:
        listener = socket.socket(socket.AF_UNIX)
        listener.bind("wake.sock")
    finally:
        os.chdir(here)
    archive = tmp_path / "state.tar"
    try:
        findings = state_archive.pack(root, archive)
    finally:
        listener.close()
    assert findings == ["./pipe: a FIFO, left out", "./wake.sock: a socket, left out"]
    with tarfile.open(archive) as tar:
        assert "./pipe" not in tar.getnames() and "./wake.sock" not in tar.getnames()


@pytest.mark.parametrize("name, target, refusal", [
    ("absolute", "/etc/passwd", "an absolute link"),
    ("escape", "../../outside", "a link out of the archive"),
    ("seats/one/escape", "../../../outside", "a link out of the archive"),
])
def test_pack_refuses_a_link_it_could_not_restore_and_writes_no_archive(tmp_path, name, target, refusal):
    root = home(tmp_path)
    (root / name).symlink_to(target)
    archive = tmp_path / "state.tar"
    with pytest.raises(state_archive.Refused, match=f"./{name}: {refusal}"):
        state_archive.pack(root, archive)
    assert not archive.exists()


def test_pack_refuses_a_chain_of_links_that_climbs_out(tmp_path):
    # Read lexically, "here/.." stays inside; resolved, "here" is the root
    # itself and its parent is outside.
    root = home(tmp_path)
    (root / "here").symlink_to(".")
    (root / "out").symlink_to("here/..")
    with pytest.raises(state_archive.Refused, match=r"./out: a link out of the archive"):
        state_archive.pack(root, tmp_path / "state.tar")


def crafted(tmp_path: Path, *members: tuple[tarfile.TarInfo, bytes | None]) -> Path:
    path = tmp_path / "crafted.tar"
    with tarfile.open(path, "w") as tar:
        for info, data in members:
            tar.addfile(info, io.BytesIO(data) if data is not None else None)
    return path


def entry(name: str, kind: bytes = tarfile.REGTYPE, link: str = "", data: bytes | None = None) -> tuple:
    info = tarfile.TarInfo(name)
    info.type = kind
    info.linkname = link
    info.mode = 0o700 if kind == tarfile.DIRTYPE else 0o600
    if data is not None:
        info.size = len(data)
    return info, data


DIRECTORY = entry(".", tarfile.DIRTYPE)


@pytest.mark.parametrize("members, refusal", [
    ([DIRECTORY, entry("/etc/cron.d/x", data=b"")], "not a path inside the archive"),
    ([DIRECTORY, entry("./../x", data=b"")], "not a path inside the archive"),
    ([DIRECTORY, entry("./a", tarfile.SYMTYPE, "/etc")], "an absolute link"),
    ([DIRECTORY, entry("./a", tarfile.SYMTYPE, "../outside")], "a link out of the archive"),
    ([DIRECTORY, entry("./here", tarfile.SYMTYPE, "."), entry("./out", tarfile.SYMTYPE, "here/..")],
     "a link out of the archive"),
    ([DIRECTORY, entry("./d", tarfile.DIRTYPE), entry("./a", tarfile.SYMTYPE, "d"), entry("./a/x", data=b"")],
     "under the link ./a"),
    ([DIRECTORY, entry("./dev", tarfile.CHRTYPE)], "not a regular file, a directory or a link"),
    ([DIRECTORY, entry("./fifo", tarfile.FIFOTYPE)], "not a regular file, a directory or a link"),
    ([DIRECTORY, entry("./hard", tarfile.LNKTYPE, "./missing")], "a hard link to no earlier file"),
    ([DIRECTORY, entry("./x", data=b""), entry("./x", data=b"")], "named twice"),
    ([DIRECTORY, entry("./a", tarfile.SYMTYPE, "")], "an empty link"),
])
def test_unpack_refuses_before_writing_anything(tmp_path, members, refusal):
    archive = crafted(tmp_path, *members)
    destination = tmp_path / "restored"
    with pytest.raises(state_archive.Refused, match=refusal):
        state_archive.unpack(archive, destination)
    assert not os.path.lexists(destination)
    assert not os.path.lexists(tmp_path / "outside") and not os.path.lexists(tmp_path / "x")


def test_unpack_keeps_a_hard_link_to_an_earlier_file(tmp_path):
    archive = crafted(tmp_path, DIRECTORY, entry("./file", data=b"bytes"), entry("./same", tarfile.LNKTYPE, "./file"))
    destination = tmp_path / "restored"
    state_archive.unpack(archive, destination)
    assert (destination / "same").read_bytes() == b"bytes"
    assert (destination / "same").stat().st_ino == (destination / "file").stat().st_ino


def test_unpack_writes_only_where_nothing_is(tmp_path):
    root = home(tmp_path)
    archive = tmp_path / "state.tar"
    state_archive.pack(root, archive)
    for occupied in (tmp_path / "existing", tmp_path / "dangling"):
        if occupied.name == "existing":
            occupied.mkdir()
        else:
            occupied.symlink_to(tmp_path / "nowhere")
        with pytest.raises(state_archive.Refused, match="exists"):
            state_archive.unpack(archive, occupied)
    assert not (tmp_path / "nowhere").exists()
