"""Opt-in guard for pgdbm's otherwise implicit-localhost pytest fixtures."""

from __future__ import annotations

import pytest
from pgdbm.fixtures import conftest as pgdbm_fixtures

from awid.test_services import postgres_config


@pytest.hookimpl(tryfirst=True)
def pytest_fixture_setup(fixturedef, request):
    if fixturedef.argname not in {"test_db", "test_db_with_schema", "test_db_factory"}:
        return
    configured = postgres_config()
    # pgdbm captures these at import, before fixture setup. Never admit changed
    # environment variables while it would still connect to the old target.
    original = pgdbm_fixtures.DEFAULT_TEST_CONFIG
    if (configured.host, configured.port, configured.user, configured.password) != (
        original.host,
        original.port,
        original.user,
        original.password,
    ):
        raise RuntimeError(
            "Set TEST_DB_HOST and TEST_DB_PORT (and credentials) before starting pytest"
        )
