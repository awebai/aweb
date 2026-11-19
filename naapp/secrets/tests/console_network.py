"""The console's real browser origin is fixed before fixture credentials bind."""

import pytest


@pytest.fixture
def passkey_origin(console_listener):
    return console_listener.origin
