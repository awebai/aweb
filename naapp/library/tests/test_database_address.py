from __future__ import annotations

from typing import Any

import pytest
from conftest import TEST_SCHEMA, _SchemaDatabases, named_database_config

# The refusal tests open no connection: with no named server, the default would
# be the host's own Postgres on localhost:5432.

_ADDRESS = {"TEST_DB_HOST": "db.test", "TEST_DB_PORT": "15432"}


class _RecordingFactory:
    def __init__(self) -> None:
        self.calls: list[tuple[str | None, str | None]] = []

    async def create_db(self, suffix: str | None, schema: str | None, **_: Any) -> None:
        self.calls.append((suffix, schema))


def _name_server(monkeypatch: pytest.MonkeyPatch, address: dict[str, str]) -> None:
    for name in _ADDRESS:
        monkeypatch.delenv(name, raising=False)
    for name, value in address.items():
        monkeypatch.setenv(name, value)


@pytest.mark.parametrize("missing", [["TEST_DB_HOST"], ["TEST_DB_PORT"], list(_ADDRESS)])
@pytest.mark.parametrize("required", [False, True])
async def test_an_unnamed_server_is_refused(
    monkeypatch: pytest.MonkeyPatch, missing: list[str], required: bool
) -> None:
    _name_server(monkeypatch, {k: v for k, v in _ADDRESS.items() if k not in missing})
    monkeypatch.setenv("LIBRARY_REQUIRE_TEST_DATABASE", "1" if required else "0")
    refusal = RuntimeError if required else pytest.skip.Exception
    named = " and ".join(missing)

    with pytest.raises(refusal, match=named):
        named_database_config()

    factory = _RecordingFactory()
    with pytest.raises(refusal, match=named):
        await _SchemaDatabases(factory).create_db("refused")
    assert factory.calls == []


async def test_a_named_server_is_used(monkeypatch: pytest.MonkeyPatch) -> None:
    _name_server(monkeypatch, _ADDRESS)

    config = named_database_config()
    assert (config.host, config.port) == ("db.test", 15432)

    factory = _RecordingFactory()
    await _SchemaDatabases(factory).create_db("named")
    assert factory.calls == [("named", TEST_SCHEMA)]
