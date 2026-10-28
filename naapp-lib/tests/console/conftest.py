from collections.abc import AsyncIterator

import pytest

from tests.console.support import Console, console_world
from tests.runtime.credential_audit.support import world  # noqa: F401


@pytest.fixture
async def console(test_db_factory, registry) -> AsyncIterator[Console]:
    yield await console_world(test_db_factory, registry, "naapp_console")
