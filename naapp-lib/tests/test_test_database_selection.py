"""A naapp test database is created only on a Postgres server the run names;
with no selection it is refused rather than falling back to the host's own
localhost:5432."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
from aweb_naapp_testing.databases import PostgresNotSelected, selected_test_database_config

_SELECTIONS = ("TEST_DB_HOST", "TEST_DB_PORT", "PGHOST", "PGPORT")


@pytest.fixture
def no_selection(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    for name in _SELECTIONS:
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


def test_a_run_that_names_no_server_is_refused(no_selection: pytest.MonkeyPatch) -> None:
    with pytest.raises(PostgresNotSelected):
        selected_test_database_config()


def test_the_named_test_server_is_the_one_used(no_selection: pytest.MonkeyPatch) -> None:
    no_selection.setenv("TEST_DB_HOST", "127.0.0.1")
    no_selection.setenv("TEST_DB_PORT", "15432")

    config = selected_test_database_config()

    assert (config.host, config.port) == ("127.0.0.1", 15432)


def test_a_test_database_fixture_is_refused_before_it_reaches_the_default(
    tmp_path: Path, no_selection: pytest.MonkeyPatch
) -> None:
    # pgdbm alone resolves the run to the host's own Postgres.
    default = subprocess.run(
        [
            sys.executable,
            "-c",
            "from pgdbm.fixtures.conftest import DEFAULT_TEST_CONFIG as c; print(c.host, c.port)",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert default.stdout.split() == ["localhost", "5432"]

    (tmp_path / "conftest.py").write_text('pytest_plugins = ("aweb_naapp_testing.postgres",)\n')
    (tmp_path / "test_wants_a_database.py").write_text(
        "async def test_it(test_db_factory):\n    await test_db_factory.create_db()\n"
    )
    child = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", str(tmp_path)],
        capture_output=True,
        text=True,
        cwd=tmp_path,
    )

    assert child.returncode != 0
    assert "PostgresNotSelected" in child.stdout, child.stdout
