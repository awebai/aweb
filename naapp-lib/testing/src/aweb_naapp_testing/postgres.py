"""pgdbm's test database fixtures, refused unless the run names its Postgres
server (aweb_naapp_testing.databases.selected_test_database_config).

Load it as a pytest plugin instead of ``pgdbm.fixtures.conftest``::

    pytest_plugins = ("aweb_naapp_testing.postgres",)
"""

from __future__ import annotations

from typing import Any

import pytest

from aweb_naapp_testing.databases import selected_test_database_config

pytest_plugins = ("pgdbm.fixtures.conftest",)

# pgdbm's fixtures that create a test database, and every package's override of them.
_DATABASE_FIXTURES = frozenset(
    {
        "test_db",
        "test_db_with_schema",
        "test_db_factory",
        "test_db_with_tables",
        "test_db_with_data",
        "test_db_isolated",
    }
)


@pytest.hookimpl(tryfirst=True)
def pytest_fixture_setup(
    fixturedef: pytest.FixtureDef[Any], request: pytest.FixtureRequest
) -> None:
    if fixturedef.argname in _DATABASE_FIXTURES:
        selected_test_database_config()
