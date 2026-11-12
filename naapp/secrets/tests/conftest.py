"""Real PostgreSQL databases for the tests (pgdbm's test_db_factory), each in
its own schema, and real AWID routes on one of them."""

from collections.abc import AsyncIterator
from typing import Any

import pytest
import pytest_asyncio
from aweb_naapp_testing.databases import SchemaDatabases
from awid_service.testing import Registry, running_registry

pytest_plugins = ("pgdbm.fixtures.conftest",)


@pytest.fixture
def human_member_cache_seconds() -> int:
    return 60


@pytest.fixture
async def test_db_factory(test_db_factory: Any) -> SchemaDatabases:
    return SchemaDatabases(test_db_factory)


@pytest_asyncio.fixture
async def registry(test_db_factory) -> AsyncIterator[Registry]:
    # AWID connects to this database by its DSN alone and keeps its tables in
    # its own explicit schema, so the test schema the factory adds goes unused.
    registry_db = await test_db_factory.create_db(suffix="secrets_awid")
    async with running_registry(registry_db.config.get_dsn()) as running:
        yield running


@pytest.fixture
def console_tls(tmp_path, monkeypatch):
    """Private CA for the real local HTTPS console and its browser clients."""
    from aweb_naapp_testing.network import make_certificates

    certificates = make_certificates(tmp_path, ["localhost"], ["127.0.0.1"])
    monkeypatch.setenv("SSL_CERT_FILE", str(certificates.ca_file))
    monkeypatch.setenv("NODE_EXTRA_CA_CERTS", str(certificates.ca_file))
    return certificates


@pytest.fixture
def passkey_origin():
    return "https://secrets.example.com"


@pytest.fixture
def console_listener(console_tls):
    import socket
    from types import SimpleNamespace

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    try:
        yield SimpleNamespace(socket=sock, port=port, origin=f"https://localhost:{port}")
    finally:
        sock.close()
