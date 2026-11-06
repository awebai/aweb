"""Private token opening uses real PostgreSQL and local envelope encryption."""

from dataclasses import replace

import pytest

from aweb_secrets.custody import Custody, CustodyUnavailable
from tests.custody.conftest import value_bytes
from tests.custody.test_backend_tokens import stage
from tests.custody.test_store import db as _db

db = _db


async def test_console_preview_pairs_exact_unsealed_context_without_activation(
    db, provider, canary
):
    custody = Custody(provider, db)
    first = await stage(db, custody, value_bytes(canary))
    second = await stage(db, custody, value_bytes(canary[::-1]))
    for context, expected in [(first, canary), (second, canary[::-1])]:
        opened = await custody.backend_credential_preview.open(context)
        assert opened.context == context
        if opened.plaintext.reveal() != value_bytes(expected):
            raise AssertionError("opened credential differs")
        assert expected.decode() not in repr(opened) + str(opened)
        with pytest.raises(CustodyUnavailable):
            await custody.backend_credential_opener.open(context)
        with pytest.raises(CustodyUnavailable):
            await custody.opener.open(context)
    assert (
        await db.fetch_value("SELECT active_version FROM {{tables.onepassword_credentials}}")
        is None
    )


@pytest.mark.parametrize(
    "change",
    [
        {"installation_id": "foreign"},
        {"team_id": "foreign"},
        {"secret_id": "sec_other1"},
        {"version": 3},
        {"version": True},
        {"version": 0},
    ],
)
async def test_preview_refuses_missing_or_foreign_exact_context(db, provider, canary, change):
    custody = Custody(provider, db)
    context = await stage(db, custody, value_bytes(canary))
    with pytest.raises(CustodyUnavailable):
        await custody.backend_credential_preview.open(replace(context, **change))


@pytest.mark.parametrize("state", ["destroyed", "disabled", "shape"])
@pytest.mark.parametrize("active", [False, True])
async def test_opening_refuses_dead_or_incompatible_credential(db, provider, canary, state, active):
    custody = Custody(provider, db)
    context = await stage(db, custody, value_bytes(canary))
    if active:
        # Isolated opener storage fixture, not an owner-confirmation/E2E path.
        await db.execute(
            "UPDATE {{tables.onepassword_credentials}} SET active_version=$1", context.version
        )
    async with db.transaction() as tx:
        if state == "destroyed":
            await custody.destroy(tx, context)
        elif state == "disabled":
            await custody.disable(
                tx,
                installation_id=context.installation_id,
                team_id=context.team_id,
                secret_id=context.secret_id,
            )
        else:
            await tx.execute("UPDATE {{tables.custody_secrets}} SET immutable_shape='{}'::jsonb")
    with pytest.raises(CustodyUnavailable):
        await custody.backend_credential_preview.open(context)
    with pytest.raises(CustodyUnavailable):
        await custody.backend_credential_opener.open(context)


async def test_use_time_opener_requires_exact_active_version(db, provider, canary):
    custody = Custody(provider, db)
    first = await stage(db, custody, value_bytes(canary))
    second = await stage(db, custody, value_bytes(canary[::-1]))
    # Isolate the storage predicate. Full confirmed activation remains separate.
    await db.execute(
        "UPDATE {{tables.onepassword_credentials}} SET active_version=$1", first.version
    )
    opened = await custody.backend_credential_opener.open(first)
    assert opened.context == first
    if opened.plaintext.reveal() != value_bytes(canary):
        raise AssertionError("active credential differs")
    with pytest.raises(CustodyUnavailable):
        await custody.backend_credential_opener.open(second)
    await db.execute(
        "UPDATE {{tables.onepassword_credentials}} SET active_version=$1", second.version
    )
    with pytest.raises(CustodyUnavailable):
        await custody.backend_credential_opener.open(first)
    assert (await custody.backend_credential_opener.open(second)).context == second


async def test_copied_ciphertext_cannot_be_relabelled_as_new_token_version(db, provider, canary):
    custody = Custody(provider, db)
    first = await stage(db, custody, value_bytes(canary))
    second = await stage(db, custody, value_bytes(canary[::-1]))
    await db.execute(
        "UPDATE {{tables.sealed_versions}} target"
        " SET key_id=source.key_id, wrapped_key=source.wrapped_key,"
        " nonce=source.nonce, ciphertext=source.ciphertext"
        " FROM {{tables.sealed_versions}} source"
        " WHERE target.version=$1 AND source.version=$2",
        second.version,
        first.version,
    )
    with pytest.raises(CustodyUnavailable):
        await custody.backend_credential_preview.open(second)
    opened = await custody.backend_credential_preview.open(first)
    assert opened.context == first


async def test_opened_token_goes_directly_to_real_sdk_without_separate_context(
    db, provider, canary, capfd
):
    from aweb_secrets.custody.onepassword import OnePasswordSDK
    from tests.custody.test_onepassword import reference

    custody = Custody(provider, db)
    context = await stage(db, custody, value_bytes(canary))
    opened = await custody.backend_credential_preview.open(context)
    with pytest.raises(CustodyUnavailable) as refused:
        await OnePasswordSDK().read(reference(), credential=opened)
    captured = capfd.readouterr()
    output = str(refused.value) + repr(refused.value) + captured.out + captured.err
    assert canary.decode() not in output
    assert refused.value.code == "custody_unavailable"
