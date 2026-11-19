"""Trigger refusals map by SQLSTATE, not database messages or caller input."""

import secrets
from datetime import timedelta

import asyncpg
import pytest
from aweb_naapp.key_file import KeyFileError
from pgdbm.errors import QueryError

from aweb_secrets.erasure import ErasureFailure, ErasureUnavailable, map_erasure_failure
from aweb_secrets.erasure.__main__ import parser, run
from aweb_secrets.erasure.initialize import backup_age_seconds, quoted_identifier


@pytest.mark.parametrize(
    "state,reason",
    [
        ("SE001", ErasureFailure.UNAVAILABLE),
        ("SE002", ErasureFailure.ALLOCATION_REGRESSED),
        ("SE003", ErasureFailure.INCOMPLETE),
    ],
)
def test_trigger_mapping_handles_raw_and_wrapped_errors_without_input(state, reason):
    marker = secrets.token_urlsafe(32)
    error_type = type("TriggerFailure", (asyncpg.PostgresError,), {"sqlstate": state})
    original = error_type(marker)
    wrapped = QueryError("database failure", original_error=original)
    wrapped.__cause__ = original
    for error in (original, wrapped):
        refusal = map_erasure_failure(error)
        assert isinstance(refusal, ErasureUnavailable)
        assert refusal.reason is reason
        assert refusal.code == reason.value
        assert marker not in str(refusal)


def test_unrelated_errors_are_not_misclassified_by_their_text():
    error = ValueError("SE001 erasure_unavailable")
    assert map_erasure_failure(error) is None


@pytest.mark.parametrize("seconds", [0, -1, 0.5, 2147483648])
def test_backup_policy_requires_a_bounded_whole_second_lifetime(seconds):
    with pytest.raises(ValueError):
        backup_age_seconds(timedelta(seconds=seconds))


def test_backup_policy_preserves_the_operators_declared_bound():
    assert backup_age_seconds(timedelta(days=7)) == 604800


@pytest.mark.parametrize("identifier", ['"owner"', "owner; SELECT 1", "a.b", "", "x" * 64])
def test_operator_identifiers_cannot_inject_sql(identifier):
    with pytest.raises(ValueError):
        quoted_identifier(identifier)


@pytest.mark.parametrize(
    "extra",
    [
        [],
        ["--application-role", "runtime;SELECT 1", "--max-backup-age-seconds", "60"],
        ["--application-role", "runtime", "--max-backup-age-seconds", "0"],
    ],
)
async def test_operator_arguments_are_checked_before_reading_credentials(tmp_path, extra):
    arguments = parser().parse_args(
        [
            "init-erasure",
            "--operator-dsn-file",
            str(tmp_path / "does-not-exist"),
            *extra,
        ]
    )
    with pytest.raises(ValueError) as failure:
        await run(arguments)
    assert not isinstance(failure.value, KeyFileError)
