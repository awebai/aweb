"""RegistryClient address listings against AWID's real routes and database."""

from __future__ import annotations

import pytest
import pytest_asyncio
from nacl.signing import SigningKey

from awid.pagination import DEFAULT_LIMIT, MAX_LIMIT
from awid.registry import RegistryClient
from awid_service.testing import REGISTRY_URL, running_registry

DOMAINS = ("alpha.example", "beta.example")
NAMES_PER_DOMAIN = MAX_LIMIT + DEFAULT_LIMIT + 5


@pytest_asyncio.fixture
async def database_url(test_db_factory):
    return (await test_db_factory.create_db(suffix="address_listing")).config.get_dsn()


def _names() -> list[str]:
    return [f"agent-{number:04d}" for number in range(NAMES_PER_DOMAIN)]


async def _add_addresses(registry, did_aw: str) -> None:
    for domain in DOMAINS:
        namespace_id = await registry.db.fetch_value(
            """
            INSERT INTO {{tables.dns_namespaces}} (domain, verification_status)
            VALUES ($1, 'verified')
            RETURNING namespace_id
            """,
            domain,
        )
        await registry.db.execute(
            """
            INSERT INTO {{tables.public_addresses}} (namespace_id, name, did_aw)
            SELECT $1, name, $3 FROM UNNEST($2::text[]) AS name
            """,
            namespace_id,
            _names(),
            did_aw,
        )


@pytest.mark.asyncio
async def test_list_addresses_returns_every_address_of_a_namespace(database_url):
    async with running_registry(database_url) as registry:
        did_aw = await registry.register_did(SigningKey.generate())
        await _add_addresses(registry, did_aw)
        client = RegistryClient(registry_url=REGISTRY_URL, transport=registry.transport)
        try:
            addresses = await client.list_addresses(DOMAINS[0])
        finally:
            await client.aclose()

    assert [address.name for address in addresses] == _names()
    assert {address.domain for address in addresses} == {DOMAINS[0]}


@pytest.mark.asyncio
async def test_list_did_addresses_returns_every_address_of_an_identity(database_url):
    async with running_registry(database_url) as registry:
        did_aw = await registry.register_did(SigningKey.generate())
        await _add_addresses(registry, did_aw)
        client = RegistryClient(registry_url=REGISTRY_URL, transport=registry.transport)
        try:
            addresses = await client.list_did_addresses(did_aw)
        finally:
            await client.aclose()

    assert [(address.domain, address.name) for address in addresses] == [
        (domain, name) for domain in DOMAINS for name in _names()
    ]
