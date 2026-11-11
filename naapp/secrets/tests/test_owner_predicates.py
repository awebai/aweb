"""A team-local signing key is a non-owner, including at the SQL hold boundary."""

from aweb_naapp.roles import principal_key
from pgdbm import AsyncDatabaseManager, DatabaseConfig

from aweb_secrets.owners import has_owner, hold_owner
from tests.test_admission import INSTALLATION, _member
from tests.test_admission import db as db


async def test_key_only_owner_lookup_is_a_denial_before_any_database_io():
    unconnected = AsyncDatabaseManager(
        DatabaseConfig(
            host="127.0.0.1",
            port=1,
            database="fixture",
            user="fixture",
            password="",
            min_connections=0,
            max_connections=1,
        )
    )
    outsider = principal_key(_member(42, did_aw=False))
    assert outsider.principal_did.startswith("did:key:")
    assert not await has_owner(unconnected, outsider, installation_id=INSTALLATION)


async def test_key_only_owner_hold_is_a_denial_in_the_original_transaction(db):  # noqa: F811
    outsider = principal_key(_member(42, did_aw=False))
    async with db.transaction() as tx:
        assert not await has_owner(tx, outsider, installation_id=INSTALLATION)
        assert not await hold_owner(tx, outsider, installation_id=INSTALLATION)
