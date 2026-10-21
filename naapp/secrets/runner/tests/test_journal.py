import os
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from threading import Barrier

import pytest

from aweb_secrets_runner.journal import Journal
from aweb_secrets_runner.protocol import Refused

DISPATCH = "dsp_240bbWTk7JDOszX8Q0TnVw"


def test_replay_survives_reopening_and_is_private(tmp_path):
    path = tmp_path / "journal.sqlite3"
    Journal(path).accept(DISPATCH, expires_at=200, now=100)
    with pytest.raises(Refused, match="assignment_replayed"):
        Journal(path).accept(DISPATCH, expires_at=200, now=101)
    assert path.stat().st_mode & 0o777 == 0o600
    with closing(sqlite3.connect(path)) as conn:
        assert conn.execute("PRAGMA integrity_check").fetchone() == ("ok",)


def test_concurrent_acceptance_has_one_winner(tmp_path):
    path = tmp_path / "journal.sqlite3"
    journals = [Journal(path), Journal(path)]
    barrier = Barrier(2)

    def attempt(journal):
        barrier.wait(timeout=5)
        try:
            journal.accept(DISPATCH, expires_at=200, now=100)
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
    Journal(Path(sys.argv[1])).accept(sys.argv[2], expires_at=200, now=100)
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
    journal = Journal(tmp_path / "journal.sqlite3")
    journal.accept(DISPATCH, expires_at=200, now=100)
    with pytest.raises(Refused, match="assignment_expired"):
        journal.accept(DISPATCH, expires_at=200, now=201)
