"""Private exact report bytes survive retries/restarts without rerunning a job."""

import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from aweb_secrets_runner.errors import Refused
from aweb_secrets_runner.journal import Journal

DISPATCH = "dsp_" + "a" * 22
BODY = b'{"exit_code":0,"stdout":"ok","stderr":"","truncated":false,"result_withheld":false,"redaction_count":0}'


def journal(tmp_path, *, now=100):
    tmp_path.chmod(0o700)
    return Journal(tmp_path / "journal.sqlite3", clock=lambda: now)


def test_exact_bytes_survive_reopen_expiry_and_other_acceptance(tmp_path):
    store = journal(tmp_path)
    store.accept(DISPATCH, expires_at=200)
    body = b" \n" + BODY + b"\n "
    store.save_result(DISPATCH, body)
    reopened = journal(tmp_path, now=300)
    reopened.accept("dsp_" + "b" * 22, expires_at=400)
    pending = reopened.pending_results()
    assert len(pending) == 1 and pending[0].dispatch_id == DISPATCH
    assert pending[0].body == body
    assert body.decode() not in repr(pending[0])
    with pytest.raises(Refused, match="assignment_replayed"):
        journal(tmp_path).accept(DISPATCH, expires_at=200)


def test_acknowledgment_clears_body_but_never_rearms_a_result(tmp_path):
    store = journal(tmp_path)
    store.accept(DISPATCH, expires_at=200)
    store.save_result(DISPATCH, BODY)
    store.ack_result(DISPATCH)
    reopened = journal(tmp_path)
    assert reopened.pending_results() == ()
    reopened.save_result(DISPATCH, BODY)  # idempotent without reviving bytes
    reopened.ack_result(DISPATCH)
    assert reopened.pending_results() == ()
    with sqlite3.connect(reopened.path) as db:
        assert db.execute(
            "SELECT result_body FROM dispatches WHERE dispatch_id=?", (DISPATCH,)
        ).fetchone() == (None,)
    with pytest.raises(Refused, match="journal_result_conflict"):
        reopened.save_result(DISPATCH, BODY + b" ")


def test_only_an_accepted_dispatch_can_record_or_ack_a_result(tmp_path):
    store = journal(tmp_path)
    with pytest.raises(Refused, match="journal_state_invalid"):
        store.save_result(DISPATCH, BODY)
    store.accept(DISPATCH, expires_at=200)
    with pytest.raises(Refused, match="journal_state_invalid"):
        store.ack_result(DISPATCH)
    assert store.pending_results() == ()


def test_conflicting_concurrent_reports_keep_one_exact_body(tmp_path):
    store = journal(tmp_path)
    store.accept(DISPATCH, expires_at=200)

    def save(body):
        try:
            journal(tmp_path).save_result(DISPATCH, body)
            return "saved"
        except Refused as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(save, [BODY, BODY + b" "]))
    assert sorted(results) == ["journal_result_conflict", "saved"]
    assert store.pending_results()[0].body in (BODY, BODY + b" ")


def test_incompatible_journal_refuses_without_erasing_accepted_dispatch(tmp_path):
    tmp_path.chmod(0o700)
    path = tmp_path / "journal.sqlite3"
    path.touch(mode=0o600)
    with sqlite3.connect(path) as db:
        db.execute(
            "CREATE TABLE dispatches (dispatch_id TEXT PRIMARY KEY, expires_at REAL NOT NULL)"
        )
        db.execute("INSERT INTO dispatches VALUES (?,?)", (DISPATCH, 200))
    with pytest.raises(Refused, match="journal_version_unsupported"):
        journal(tmp_path)
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT * FROM dispatches").fetchall() == [(DISPATCH, 200)]


def test_result_recording_is_allowed_after_the_assignment_execution_deadline(tmp_path):
    store = journal(tmp_path)
    store.accept(DISPATCH, expires_at=200)
    later = journal(tmp_path, now=300)
    later.save_result(DISPATCH, BODY)
    assert later.pending_results()[0].body == BODY
    with pytest.raises(Refused, match="assignment_expired"):
        later.accept(DISPATCH, expires_at=200)


@pytest.mark.parametrize("body", [b"", "not-bytes"])
def test_invalid_local_report_bytes_refuse_without_journal_mutation(tmp_path, body):
    store = journal(tmp_path)
    store.accept(DISPATCH, expires_at=200)
    with pytest.raises(Refused, match="journal_result_invalid"):
        store.save_result(DISPATCH, body)
    assert store.pending_results() == ()
