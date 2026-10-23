"""Inert reference metadata on PG, projected from actual SDK Item models.

This tests persistence, not successful external-vault access (HO6 remains owed).
"""

import json
from dataclasses import replace

import pytest

from aweb_secrets.custody import Custody, CustodyUnavailable
from aweb_secrets.custody.onepassword import project_item
from aweb_secrets.secret import SecretRecord
from tests.custody.conftest import initial_record, value_bytes
from tests.custody.test_backend_tokens import stage as stage_token
from tests.custody.test_onepassword import field, reference, sdk_item
from tests.custody.test_store import INSTALLATION, TEAM
from tests.custody.test_store import db as _db

db = _db


def candidate(**changes):
    after = {**initial_record("sec_secret1").after, "backend": "onepassword", **changes}
    return SecretRecord.from_after(after)


def observation(credential, canary, *, ref=None):
    return project_item(
        ref or reference(),
        sdk_item([field("credential", canary.decode())]),
        credential_context=credential,
    )


async def stage_ref(db, custody, credential, canary, *, record=None, observed=None):
    record = record or candidate()
    async with db.transaction() as tx:
        return await custody.stage_onepassword_reference(
            tx,
            installation_id=INSTALLATION,
            team_id=TEAM,
            secret_id=record.secret_id,
            observed=observed or observation(credential, canary),
            initial=record,
        )


async def test_reference_staging_keeps_only_exact_metadata_and_no_active_secret(
    db, provider, canary
):
    custody = Custody(provider, db)
    credential = await stage_token(db, custody, value_bytes(canary))
    staged = await stage_ref(db, custody, credential, canary)
    assert staged.context.secret_id == "sec_secret1"
    assert staged.after == {
        "v": 1,
        "secret_id": "sec_secret1",
        "version": 1,
        "credential_version": 1,
        "vault_id": "a" * 26,
        "item_id": "b" * 26,
        "fields": {"value": "credential"},
        "item_version": 7,
    }
    assert staged.version_ref.startswith("sv_") and len(staged.version_ref) == 35
    row = await db.fetch_one("SELECT * FROM {{tables.onepassword_versions}}")
    for value in row.values():
        if canary in str(value).encode():
            raise AssertionError("item value present in metadata")
    assert await db.fetch_value("SELECT count(*) FROM {{tables.secrets}}") == 0
    assert (
        await db.fetch_value(
            "SELECT count(*) FROM {{tables.sealed_versions}} WHERE secret_id='sec_secret1'"
        )
        == 0
    )
    with pytest.raises(CustodyUnavailable):
        await custody.opener.open(staged.context)
    async with db.transaction() as tx:
        assert await custody.onepassword_binding_matches(
            tx, staged.context, candidate(), staged.after
        )
        altered = {**staged.after, "item_id": "c" * 26}
        for foreign in [
            replace(staged.context, installation_id="other"),
            replace(staged.context, team_id="other"),
            replace(staged.context, secret_id="sec_other1"),
            replace(staged.context, version=True),
        ]:
            assert not await custody.onepassword_binding_matches(
                tx, foreign, candidate(), staged.after
            )
        assert not await custody.onepassword_binding_matches(
            tx, staged.context, candidate(), altered
        )


async def test_remote_version_repetition_never_reuses_local_authority_or_handle(
    db, provider, canary
):
    custody = Custody(provider, db)
    token = await stage_token(db, custody, value_bytes(canary))
    first = await stage_ref(db, custody, token, canary)
    async with db.transaction() as tx:
        await custody.destroy(tx, first.context)
        assert not await custody.onepassword_binding_matches(
            tx, first.context, candidate(), first.after
        )
        history = await tx.fetch_one(
            "SELECT binding,version_ref,destroyed_at FROM {{tables.onepassword_versions}}"
        )
        assert history["binding"] is None
        assert history["version_ref"] == first.version_ref
        assert history["destroyed_at"] is not None
    second = await stage_ref(db, custody, token, canary)
    assert second.after["item_version"] == first.after["item_version"] == 7
    assert second.context.version == 2
    assert second.version_ref != first.version_ref
    assert (
        await db.fetch_value(
            "SELECT last_version FROM {{tables.custody_secrets}} WHERE secret_id='sec_secret1'"
        )
        == 2
    )


@pytest.mark.parametrize("part", ["installation_id", "team_id", "secret_id", "version"])
async def test_wrong_or_destroyed_token_context_cannot_pin_a_reference(db, provider, canary, part):
    custody = Custody(provider, db)
    token = await stage_token(db, custody, value_bytes(canary))
    altered = replace(token, **{part: 2 if part == "version" else "other"})
    with pytest.raises(CustodyUnavailable):
        await stage_ref(db, custody, token, canary, observed=observation(altered, canary))
    assert await db.fetch_value("SELECT count(*) FROM {{tables.onepassword_versions}}") == 0


async def test_kind_or_initial_shape_mismatch_cannot_allocate(db, provider, canary):
    custody = Custody(provider, db)
    token = await stage_token(db, custody, value_bytes(canary))
    with pytest.raises(CustodyUnavailable):
        await stage_ref(db, custody, token, canary, record=candidate(kind="basic"))
    first = await stage_ref(db, custody, token, canary)
    reshaped = candidate(kind="header", kind_params={"name": "Authorization", "prefix": "Bearer "})
    read = observation(token, canary, ref=reference("header"))
    with pytest.raises(CustodyUnavailable):
        await stage_ref(db, custody, token, canary, record=reshaped, observed=read)
    assert (
        await db.fetch_value(
            "SELECT last_version FROM {{tables.custody_secrets}} WHERE secret_id='sec_secret1'"
        )
        == first.context.version
    )


async def test_staging_rolls_back_and_cannot_reinterpret_mutated_projection(db, provider, canary):
    custody = Custody(provider, db)
    token = await stage_token(db, custody, value_bytes(canary))

    class Abandon(Exception):
        pass

    with pytest.raises(Abandon):
        async with db.transaction() as tx:
            await custody.stage_onepassword_reference(
                tx,
                installation_id=INSTALLATION,
                team_id=TEAM,
                secret_id="sec_secret1",
                observed=observation(token, canary),
                initial=candidate(),
            )
            raise Abandon
    assert await db.fetch_value("SELECT count(*) FROM {{tables.onepassword_versions}}") == 0
    staged = await stage_ref(db, custody, token, canary)
    after = staged.after
    after["fields"]["value"] = "other"
    assert staged.after["fields"] == {"value": "credential"}
    async with db.transaction() as tx:
        assert not await custody.onepassword_binding_matches(tx, staged.context, candidate(), after)
        immutable_shape = json.loads(
            await tx.fetch_value(
                "SELECT immutable_shape FROM {{tables.custody_secrets}} WHERE secret_id='sec_secret1'"
            )
        )
    assert immutable_shape["backend"] == "onepassword"


async def test_locked_parent_kind_wins_over_an_initial_candidate(db, provider, canary):
    from aweb_secrets import records

    custody = Custody(provider, db)
    token = await stage_token(db, custody, value_bytes(canary))
    async with db.transaction() as tx:
        await records.create_secret(tx, INSTALLATION, TEAM, candidate(kind="basic"))
    with pytest.raises(CustodyUnavailable):
        await stage_ref(db, custody, token, canary, record=candidate())
    assert await db.fetch_value("SELECT count(*) FROM {{tables.onepassword_versions}}") == 0


async def test_existing_reference_stage_holds_parent_before_custody(db, provider, canary):
    import asyncio

    import asyncpg

    from aweb_secrets import records

    custody = Custody(provider, db)
    token = await stage_token(db, custody, value_bytes(canary))
    async with db.transaction() as tx:
        await records.create_secret(tx, INSTALLATION, TEAM, candidate())
    read = observation(token, canary)
    async with db.transaction() as tx:
        pid = await tx.fetch_value("SELECT pg_backend_pid()")
        staged = await custody.stage_onepassword_reference(
            tx,
            installation_id=INSTALLATION,
            team_id=TEAM,
            secret_id="sec_secret1",
            observed=read,
        )

        async def probe():
            with pytest.raises(asyncpg.LockNotAvailableError):
                async with db.transaction() as observer:
                    assert await observer.fetch_value("SELECT pg_backend_pid()") != pid
                    await observer.fetch_one(
                        "SELECT secret_id FROM {{tables.secrets}} WHERE secret_id='sec_secret1' FOR UPDATE NOWAIT"
                    )

        await asyncio.wait_for(asyncio.create_task(probe()), 5)
    async with db.transaction() as tx:
        stored = await records.secret_by_ref(tx, INSTALLATION, TEAM, candidate().ref)
        assert stored.active_version is None
        assert await custody.ever_sealed(
            tx, installation_id=INSTALLATION, team_id=TEAM, secret_id=staged.context.secret_id
        )


async def test_disabled_reference_or_destroyed_token_refuses_new_staging(db, provider, canary):
    custody = Custody(provider, db)
    token = await stage_token(db, custody, value_bytes(canary))
    first = await stage_ref(db, custody, token, canary)
    async with db.transaction() as tx:
        await custody.disable(
            tx, installation_id=INSTALLATION, team_id=TEAM, secret_id=first.context.secret_id
        )
    with pytest.raises(CustodyUnavailable):
        await stage_ref(db, custody, token, canary)
    async with db.transaction() as tx:
        assert not await custody.onepassword_binding_matches(
            tx, first.context, candidate(), first.after
        )
        await custody.destroy(tx, token)
    with pytest.raises(CustodyUnavailable):
        await stage_ref(db, custody, token, canary)


async def test_unscoped_or_unvalidated_observation_allocates_nothing(db, provider, canary):
    from aweb_secrets.custody import Plaintext
    from aweb_secrets.custody.values import ValueInvalid

    custody = Custody(provider, db)
    token = await stage_token(db, custody, value_bytes(canary))
    read = observation(token, canary)
    with pytest.raises(CustodyUnavailable):
        await stage_ref(db, custody, token, canary, observed=replace(read, credential_context=None))
    with pytest.raises(ValueInvalid):
        await stage_ref(db, custody, token, canary, observed=replace(read, value=Plaintext(b"{}")))
    assert await db.fetch_value("SELECT count(*) FROM {{tables.onepassword_versions}}") == 0


async def test_selected_optional_field_must_have_been_observed(db, provider, canary):
    custody = Custody(provider, db)
    token = await stage_token(db, custody, value_bytes(canary))
    fields = {"access_key_id": "id", "secret_access_key": "credential"}
    read = project_item(
        reference("aws-sigv4", fields),
        sdk_item([field("id", "fixture"), field("credential", canary.decode())]),
        credential_context=token,
    )
    # Reject mismatched server composition too: selecting an optional field
    # which wasn't in the read is not proof that the field exists.
    read = replace(read, reference=reference("aws-sigv4", {**fields, "session_token": "session"}))
    with pytest.raises(CustodyUnavailable):
        await stage_ref(
            db,
            custody,
            token,
            canary,
            record=candidate(
                kind="aws-sigv4", kind_params={"region": "us-east-1", "service": "s3"}
            ),
            observed=read,
        )
    assert await db.fetch_value("SELECT count(*) FROM {{tables.onepassword_versions}}") == 0
