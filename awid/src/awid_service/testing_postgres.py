"""pgdbm's test database fixtures, refused unless the run names the Postgres
server they use (awid_service.testing.require_selected_test_database).

Load it as a pytest plugin instead of ``pgdbm.fixtures.conftest``::

    pytest_plugins = ("awid_service.testing_postgres",)

Nothing else imports this module, so pytest loads it as a plugin first.
"""

from __future__ import annotations

from typing import Any

import pytest

from awid_service.testing import require_selected_test_database

pytest_plugins = ("pgdbm.fixtures.conftest",)

# pgdbm's fixtures that create test databases; a suite's override keeps the name.
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
        # The config pgdbm captured when it loaded, which its factory creates on.
        from pgdbm.fixtures.conftest import DEFAULT_TEST_CONFIG

        require_selected_test_database(DEFAULT_TEST_CONFIG)
