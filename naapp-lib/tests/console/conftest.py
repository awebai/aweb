from collections.abc import AsyncIterator

import pytest

from tests.console.support import Console, console_world


@pytest.fixture
async def console(test_db_factory) -> AsyncIterator[Console]:
    yield await console_world(test_db_factory, "naapp_console")
