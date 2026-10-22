"""Private backend credentials reuse real native custody, never ordinary secrets."""

import asyncio
from dataclasses import replace

import pytest

from aweb_secrets.custody import Custody, CustodyUnavailable, SealedValue, unseal
from aweb_secrets.custody.values import ValueInvalid
from tests.custody.conftest import value_bytes
from tests.custody.test_store import INSTALLATION, TEAM
from tests.custody.test_store import db as _db

db = _db


async def stage(db, custody, value, *, installation=INSTALLATION, team=TEAM):
    async with db.transaction() as tx:
        return await custody.stage_backend_credential(
            tx, installation_id=installation, team_id=team, value=value
        )


async def test_staging_is_native_sealed_private_and_inert(db, provider, canary):
    custody = Custody(provider, db)
    context = await stage(db, custody, value_bytes(canary))
    assert context.secret_id == "bkc_onepassword"
    assert context.version == 1
    assert await db.fetch_value("SELECT count(*) FROM {{tables.secrets}}") == 0
    assert (
        await db.fetch_value("SELECT active_version FROM {{tables.onepassword_credentials}}")
        is None
    )
    row = await db.fetch_one("SELECT * FROM {{tables.sealed_versions}}")
    for value in row.values():
        stored = value if isinstance(value, bytes) else str(value).encode()
        if canary in stored:
            raise AssertionError("credential present in stored column")
    sealed = SealedValue(
        key_id=row["key_id"],
        wrapped_key=bytes(row["wrapped_key"]),
        nonce=bytes(row["nonce"]),
        ciphertext=bytes(row["ciphertext"]),
    )
    opened = unseal(provider, context, sealed)
    if opened.reveal() != value_bytes(canary):
        raise AssertionError("credential bytes differ")
    with pytest.raises(CustodyUnavailable):
        await custody.opener.open(context)
    async with db.transaction() as tx:
        assert await custody.backend_credential_matches(tx, context)


async def test_destroyed_or_foreign_staged_context_cannot_bind(db, provider, canary):
    custody = Custody(provider, db)
    context = await stage(db, custody, value_bytes(canary))
    async with db.transaction() as tx:
        for foreign in [
            replace(context, installation_id="other"),
            replace(context, team_id="other"),
            replace(context, secret_id="sec_other1"),
            replace(context, version=2),
        ]:
            assert not await custody.backend_credential_matches(tx, foreign)
        await custody.destroy(tx, context)
        assert not await custody.backend_credential_matches(tx, context)
    second = await stage(db, custody, value_bytes(canary))
    assert second.version == 2
    assert await db.fetch_value("SELECT last_version FROM {{tables.custody_secrets}}") == 2


async def test_stage_rollback_leaves_no_token_or_private_parent(db, provider, canary):
    custody = Custody(provider, db)

    class Abandon(Exception):
        pass

    with pytest.raises(Abandon):
        async with db.transaction() as tx:
            await custody.stage_backend_credential(
                tx, installation_id=INSTALLATION, team_id=TEAM, value=value_bytes(canary)
            )
            raise Abandon
    for table in ["onepassword_credentials", "custody_secrets", "sealed_versions"]:
        assert await db.fetch_value("SELECT count(*) FROM {{tables." + table + "}}") == 0


@pytest.mark.parametrize("raw", [b"plain", b"{}", b'{"value":""}', b'{"password":"invalid"}'])
async def test_invalid_token_shape_allocates_nothing(db, provider, raw):
    with pytest.raises(ValueInvalid):
        await stage(db, Custody(provider, db), raw)
    assert await db.fetch_value("SELECT count(*) FROM {{tables.custody_secrets}}") == 0
    assert await db.fetch_value("SELECT count(*) FROM {{tables.onepassword_credentials}}") == 0


async def test_staging_serializes_allocations_and_preserves_disabled_state(db, provider, canary):
    custody = Custody(provider, db)
    contexts = await asyncio.gather(*(stage(db, custody, value_bytes(canary)) for _ in range(2)))
    assert sorted(context.version for context in contexts) == [1, 2]
    async with db.transaction() as tx:
        await custody.disable(
            tx, installation_id=INSTALLATION, team_id=TEAM, secret_id="bkc_onepassword"
        )
    with pytest.raises(CustodyUnavailable):
        await stage(db, custody, value_bytes(canary))
    assert await db.fetch_value("SELECT last_version FROM {{tables.custody_secrets}}") == 2
    async with db.transaction() as tx:
        assert not await custody.backend_credential_matches(tx, contexts[0])
