"""A test database is created only on the Postgres server the run names: with
no selection, or with pgdbm already pointed elsewhere, it is refused rather
than falling back to the host's own localhost:5432 (aweb-admf)."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from pgdbm.testing import DatabaseTestConfig

from awid_service.testing import (
    NO_NETWORK,
    PostgresNotSelected,
    require_selected_test_database,
    selected_test_database_config,
)

_SELECTIONS = ("TEST_DB_HOST", "TEST_DB_PORT")
# Requests pgdbm's factory; setting it up creates no database.
_WANTS_A_DATABASE = """
def test_it(test_db_factory):
    pass
"""


@pytest.fixture
def no_selection(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    for name in _SELECTIONS:
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


@pytest.mark.parametrize(
    "named",
    [{}, {"TEST_DB_HOST": "127.0.0.1"}, {"TEST_DB_PORT": "15432"}],
    ids=["neither", "only-host", "only-port"],
)
def test_a_run_that_does_not_name_host_and_port_is_refused(
    no_selection: pytest.MonkeyPatch, named: dict[str, str]
) -> None:
    for name, value in named.items():
        no_selection.setenv(name, value)
    missing = " and ".join(name for name in _SELECTIONS if name not in named)

    with pytest.raises(PostgresNotSelected, match=f"^{missing} unset"):
        selected_test_database_config()


def test_the_named_test_server_is_the_one_used(
    no_selection: pytest.MonkeyPatch,
) -> None:
    no_selection.setenv("TEST_DB_HOST", "127.0.0.1")
    no_selection.setenv("TEST_DB_PORT", "15432")

    config = selected_test_database_config()

    assert (config.host, config.port) == ("127.0.0.1", 15432)


def test_a_config_for_another_server_is_refused(
    no_selection: pytest.MonkeyPatch,
) -> None:
    no_selection.setenv("TEST_DB_HOST", "127.0.0.1")
    no_selection.setenv("TEST_DB_PORT", "15432")

    with pytest.raises(PostgresNotSelected):
        require_selected_test_database(DatabaseTestConfig(host="localhost", port=5432))


def _child_run(
    tmp_path: Path, conftest: str, environ: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    (tmp_path / "conftest.py").write_text(NO_NETWORK + conftest)
    (tmp_path / "test_wants_a_database.py").write_text(_WANTS_A_DATABASE)
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", str(tmp_path)],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        env=environ,
    )


def _environ(**selection: str) -> dict[str, str]:
    environ = {k: v for k, v in os.environ.items() if k not in _SELECTIONS}
    return {**environ, **selection}


def test_pgdbm_alone_sets_up_its_factory_on_the_hosts_default(tmp_path: Path) -> None:
    # The control: without the plugin, the factory is set up for localhost:5432.
    child = _child_run(
        tmp_path,
        'pytest_plugins = ("pgdbm.fixtures.conftest",)\n'
        "def pytest_sessionfinish(session):\n"
        "    from pgdbm.fixtures.conftest import DEFAULT_TEST_CONFIG as c\n"
        '    print("pgdbm targets", c.host, c.port)\n',
        _environ(),
    )

    assert child.returncode == 0, child.stdout + child.stderr
    assert "pgdbm targets localhost 5432" in child.stdout


def test_the_plugin_refuses_the_factory_when_the_run_names_no_server(
    tmp_path: Path,
) -> None:
    child = _child_run(
        tmp_path, 'pytest_plugins = ("awid_service.testing_postgres",)\n', _environ()
    )

    assert child.returncode != 0
    assert "PostgresNotSelected" in child.stdout, child.stdout


def test_the_plugin_refuses_a_selection_made_after_pgdbm_loaded(tmp_path: Path) -> None:
    child = _child_run(
        tmp_path,
        'pytest_plugins = ("awid_service.testing_postgres",)\n'
        "import os\n"
        "def pytest_configure(config):\n"
        '    os.environ["TEST_DB_HOST"] = "127.0.0.1"\n'
        '    os.environ["TEST_DB_PORT"] = "15432"\n',
        _environ(),
    )

    assert child.returncode != 0
    assert "PostgresNotSelected" in child.stdout, child.stdout


def test_the_plugin_admits_the_server_the_run_names(tmp_path: Path) -> None:
    child = _child_run(
        tmp_path,
        'pytest_plugins = ("awid_service.testing_postgres",)\n',
        _environ(TEST_DB_HOST="127.0.0.1", TEST_DB_PORT="15432"),
    )

    assert child.returncode == 0, child.stdout + child.stderr
