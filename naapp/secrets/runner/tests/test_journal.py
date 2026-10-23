import os
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from threading import Barrier, Event

import pytest

from aweb_secrets_runner.journal import Journal
from aweb_secrets_runner.protocol import Refused

DISPATCH = "dsp_240bbWTk7JDOszX8Q0TnVw"


def test_expiry_is_rechecked_after_waiting_for_the_write_lock(tmp_path):
    path = tmp_path / "journal.sqlite3"
    current = [199.0]
    started = Event()
    read = Event()

    def clock():
        read.set()
        return current[0]

    journal = Journal(path, clock=clock)
    journal.accept(DISPATCH, expires_at=200)
    read.clear()
    with closing(sqlite3.connect(path, isolation_level=None)) as blocker:
        blocker.execute("BEGIN IMMEDIATE")
        blocker.execute("DELETE FROM dispatches WHERE expires_at <= 201")

        def accept():
            started.set()
            journal.accept(DISPATCH, expires_at=200)

        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(accept)
            try:
                assert started.wait(timeout=5)
                assert not read.wait(timeout=0.05), "clock read before obtaining the lock"
                current[0] = 201.0
            finally:
                blocker.execute("COMMIT")
            with pytest.raises(Refused, match="assignment_expired"):
                future.result(timeout=5)
    with closing(sqlite3.connect(path)) as connection:
        assert connection.execute("SELECT * FROM dispatches").fetchall() == []


def test_replay_survives_reopening_and_is_private(tmp_path):
    path = tmp_path / "journal.sqlite3"
    Journal(path, clock=lambda: 100).accept(DISPATCH, expires_at=200)
    with pytest.raises(Refused, match="assignment_replayed"):
        Journal(path, clock=lambda: 101).accept(DISPATCH, expires_at=200)
    assert path.stat().st_mode & 0o777 == 0o600
    with closing(sqlite3.connect(path)) as conn:
        assert conn.execute("PRAGMA integrity_check").fetchone() == ("ok",)


def test_concurrent_acceptance_has_one_winner(tmp_path):
    path = tmp_path / "journal.sqlite3"
    journals = [Journal(path, clock=lambda: 100), Journal(path, clock=lambda: 100)]
    barrier = Barrier(2)

    def attempt(journal):
        barrier.wait(timeout=5)
        try:
            journal.accept(DISPATCH, expires_at=200)
            return "accepted"
        except Refused as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(attempt, journals)) == ["accepted", "assignment_replayed"]


def test_acceptance_is_visible_to_another_process(tmp_path):
    path = tmp_path / "journal.sqlite3"
    script = """
import sys
from pathlib import Path
from aweb_secrets_runner.journal import Journal
from aweb_secrets_runner.protocol import Refused
try:
    Journal(Path(sys.argv[1]), clock=lambda: 100).accept(sys.argv[2], expires_at=200)
except Refused as error:
    print(error.code)
    sys.exit(2)
"""
    first = subprocess.run(
        [sys.executable, "-c", script, str(path), DISPATCH], capture_output=True, check=False
    )
    assert first.returncode == 0, first.stderr.decode()
    second = subprocess.run(
        [sys.executable, "-c", script, str(path), DISPATCH], capture_output=True, check=False
    )
    assert second.returncode == 2, second.stderr.decode()
    assert second.stdout == b"assignment_replayed\n"


@pytest.mark.parametrize("unsafe", ["symlink", "public-file", "public-directory"])
def test_journal_refuses_unsafe_storage(tmp_path, unsafe):
    path = tmp_path / "journal.sqlite3"
    if unsafe == "symlink":
        target = tmp_path / "target"
        target.touch(mode=0o600)
        path.symlink_to(target)
    elif unsafe == "public-file":
        path.touch(mode=0o644)
    else:
        os.chmod(tmp_path, 0o755)
    with pytest.raises(Refused, match="state_permissions"):
        Journal(path)


def test_expired_assignment_cannot_reenter_after_pruning(tmp_path):
    current = [100]
    journal = Journal(tmp_path / "journal.sqlite3", clock=lambda: current[0])
    journal.accept(DISPATCH, expires_at=200)
    current[0] = 201
    with pytest.raises(Refused, match="assignment_expired"):
        journal.accept(DISPATCH, expires_at=200)
