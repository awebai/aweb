"""A team-local signing key is a non-owner, including at the SQL hold boundary."""

import pytest
from aweb_naapp.roles import PrincipalKey, principal_key
from pgdbm import AsyncDatabaseManager, DatabaseConfig

from aweb_secrets.owners import has_owner, hold_owner
from tests.test_admission import INSTALLATION, _member
from tests.test_admission import db as db


@pytest.mark.parametrize("principal_did", [None, "did:aw:"])
async def test_nonholding_owner_lookup_is_a_denial_before_any_database_io(principal_did):
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
    if principal_did is not None:
        outsider = PrincipalKey(team_id=outsider.team_id, principal_did=principal_did)
    assert not await has_owner(unconnected, outsider, installation_id=INSTALLATION)


@pytest.mark.parametrize("principal_did", [None, "did:aw:"])
async def test_nonholding_owner_hold_is_a_denial_in_the_original_transaction(db, principal_did):  # noqa: F811
    outsider = principal_key(_member(42, did_aw=False))
    if principal_did is not None:
        outsider = PrincipalKey(team_id=outsider.team_id, principal_did=principal_did)
    async with db.transaction() as tx:
        assert not await has_owner(tx, outsider, installation_id=INSTALLATION)
        assert not await hold_owner(tx, outsider, installation_id=INSTALLATION)
