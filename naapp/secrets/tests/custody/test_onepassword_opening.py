"""Active binding/fence predicates on real PG; successful vault reads await HO6.

Pointer fixtures isolate read-side authority checks, not owner confirmation.
Item projections use actual SDK models; no SDK success is simulated.
"""

import json
from dataclasses import replace

import pytest

from aweb_secrets import records
from aweb_secrets.custody import Custody, CustodyUnavailable, SealContext
from aweb_secrets.custody.onepassword import SecretVersionChanged
from aweb_secrets.custody.opening import (
    BackendObservation,
    OnePasswordOpener,
    UseSecretOpener,
    active_binding,
)
from tests.custody.conftest import initial_record, value_bytes
from tests.custody.test_backend_tokens import stage as stage_token
from tests.custody.test_onepassword_staging import candidate, stage_ref
from tests.custody.test_store import INSTALLATION, TEAM
from tests.custody.test_store import db as _db

db = _db


async def active_fixture(db, provider, canary):
    custody = Custody(provider, db)
    token = await stage_token(db, custody, value_bytes(canary))
    record = candidate()
    staged = await stage_ref(db, custody, token, canary, record=record)
    async with db.transaction() as tx:
        await records.create_secret(tx, INSTALLATION, TEAM, record)
        await records.set_active_version(
            tx, INSTALLATION, TEAM, record.secret_id, staged.context.version
        )
        await tx.execute(
            "UPDATE {{tables.onepassword_credentials}} SET active_version=$1", token.version
        )
    return custody, record, token, staged


async def test_exact_active_binding_has_no_value_and_final_check_does_not_write(
    db, provider, canary
):
    custody, record, token, staged = await active_fixture(db, provider, canary)
    binding = await active_binding(db, staged.context)
    assert binding.context == staged.context
    assert binding.credential_context == token
    assert binding.version_ref == staged.version_ref
    assert binding.item_version == staged.after["item_version"]
    assert binding.reference.as_config() == {
        k: staged.after[k] for k in ("vault_id", "item_id", "fields")
    }
    assert canary.decode() not in repr(binding)
    observation = BackendObservation(binding, binding.item_version)
    opener = OnePasswordOpener(db, credential_opener=custody.backend_credential_opener)
    async with db.transaction() as tx:
        await tx.execute("SET TRANSACTION READ ONLY")
        await opener.check_observation(tx, staged.context, observation)
    assert await db.fetch_value("SELECT count(*) FROM {{tables.onepassword_versions}}") == 1


@pytest.mark.parametrize(
    "change",
    [
        {"installation_id": "foreign"},
        {"team_id": "foreign"},
        {"secret_id": "sec_other1"},
        {"version": 2},
        {"version": True},
    ],
)
async def test_active_binding_is_scoped_and_exact(db, provider, canary, change):
    _, _, _, staged = await active_fixture(db, provider, canary)
    with pytest.raises(CustodyUnavailable):
        await active_binding(db, replace(staged.context, **change))


@pytest.mark.parametrize(
    "state",
    [
        "token_inert",
        "reference_inert",
        "token_disabled",
        "secret_disabled",
        "custody_disabled",
        "token_destroyed",
        "reference_destroyed",
        "shape",
        "kind",
    ],
)
async def test_dead_or_incompatible_authority_never_opens(db, provider, canary, state):
    custody, record, token, staged = await active_fixture(db, provider, canary)
    async with db.transaction() as tx:
        if state == "token_inert":
            await tx.execute("UPDATE {{tables.onepassword_credentials}} SET active_version=NULL")
        elif state == "reference_inert":
            await tx.execute("UPDATE {{tables.secrets}} SET active_version=NULL")
        elif state == "secret_disabled":
            await tx.execute("UPDATE {{tables.secrets}} SET state='disabled'")
        elif state in {"token_disabled", "custody_disabled"}:
            await custody.disable(
                tx,
                installation_id=INSTALLATION,
                team_id=TEAM,
                secret_id=token.secret_id if state == "token_disabled" else record.secret_id,
            )
        elif state in {"token_destroyed", "reference_destroyed"}:
            await custody.destroy(tx, token if state == "token_destroyed" else staged.context)
        elif state == "shape":
            await tx.execute(
                "UPDATE {{tables.custody_secrets}} SET immutable_shape='{}'::jsonb"
                " WHERE secret_id=$1",
                record.secret_id,
            )
        elif state == "kind":
            changed = {**record.after, "kind": "basic"}
            await tx.execute("UPDATE {{tables.secrets}} SET record=$1", json.dumps(changed))
    with pytest.raises(CustodyUnavailable):
        await active_binding(db, staged.context)


async def test_changed_remote_version_is_read_only_refusal_not_activation(db, provider, canary):
    custody, _, _, staged = await active_fixture(db, provider, canary)
    binding = await active_binding(db, staged.context)
    observation = BackendObservation(binding, binding.item_version + 1)
    opener = OnePasswordOpener(db, credential_opener=custody.backend_credential_opener)
    async with db.transaction() as tx:
        await tx.execute("SET TRANSACTION READ ONLY")
        with pytest.raises(SecretVersionChanged) as refused:
            await opener.check_observation(tx, staged.context, observation)
        assert refused.value.code == "secret_version_changed"
    assert (
        await db.fetch_value("SELECT active_version FROM {{tables.secrets}}")
        == staged.context.version
    )
    assert await db.fetch_value("SELECT count(*) FROM {{tables.onepassword_versions}}") == 1


@pytest.mark.parametrize("change", ["token", "reference", "placement"])
async def test_stale_observation_cannot_pass_current_epoch_check(db, provider, canary, change):
    custody, record, token, staged = await active_fixture(db, provider, canary)
    binding = await active_binding(db, staged.context)
    observation = BackendObservation(binding, binding.item_version)
    if change == "token":
        new = await stage_token(db, custody, value_bytes(canary[::-1]))
        await db.execute(
            "UPDATE {{tables.onepassword_credentials}} SET active_version=$1", new.version
        )
    elif change == "reference":
        new = await stage_ref(db, custody, token, canary)
        await db.execute("UPDATE {{tables.secrets}} SET active_version=$1", new.context.version)
    else:
        altered = replace(binding, shape_json='{"other":"shape"}')
        observation = replace(observation, binding=altered)
    opener = OnePasswordOpener(db, credential_opener=custody.backend_credential_opener)
    async with db.transaction() as tx:
        with pytest.raises(CustodyUnavailable):
            await opener.check_observation(tx, staged.context, observation)


async def test_live_backend_uses_real_sdk_and_does_not_fall_back_to_native(
    db, provider, canary, capfd
):
    custody, _, _, staged = await active_fixture(db, provider, canary)
    opener = OnePasswordOpener(db, credential_opener=custody.backend_credential_opener)
    for method in (opener.observe, opener.open):
        with pytest.raises(CustodyUnavailable):
            await method(staged.context)
    output = capfd.readouterr()
    assert canary.decode() not in output.out + output.err
    assert (
        await db.fetch_value(
            "SELECT count(*) FROM {{tables.sealed_versions}} WHERE secret_id=$1",
            staged.context.secret_id,
        )
        == 0
    )


async def test_common_opener_keeps_native_plaintext_api_and_no_remote_observation(
    db, provider, canary
):
    custody = Custody(provider, db)
    record = initial_record("sec_native1")
    async with db.transaction() as tx:
        await records.create_secret(tx, INSTALLATION, TEAM, record)
        version = await custody.sealer.ingest(
            tx,
            installation_id=INSTALLATION,
            team_id=TEAM,
            secret_id=record.secret_id,
            value=value_bytes(canary),
        )
        await records.set_active_version(tx, INSTALLATION, TEAM, record.secret_id, version)
    context = SealContext(INSTALLATION, TEAM, record.secret_id, version)
    opener = UseSecretOpener(
        db, native=custody.opener, credential_opener=custody.backend_credential_opener
    )
    assert await opener.observe(context) is None
    async with db.transaction() as tx:
        await tx.execute("SET TRANSACTION READ ONLY")
        await opener.check_observation(tx, context, None)
    opened = await opener.open(context)
    if opened.reveal() != value_bytes(canary):
        raise AssertionError("native value differs")
    for wrong in [replace(context, team_id="foreign"), replace(context, version=version + 1)]:
        with pytest.raises(CustodyUnavailable):
            await opener.open(wrong)
    async with db.transaction() as tx:
        await custody.disable(
            tx, installation_id=INSTALLATION, team_id=TEAM, secret_id=record.secret_id
        )
    async with db.transaction() as tx:
        with pytest.raises(CustodyUnavailable):
            await opener.check_observation(tx, context, None)


async def test_common_opener_requires_observation_and_never_opens_inert_reference(
    db, provider, canary
):
    custody, _, _, staged = await active_fixture(db, provider, canary)
    opener = UseSecretOpener(
        db, native=custody.opener, credential_opener=custody.backend_credential_opener
    )
    async with db.transaction() as tx:
        with pytest.raises(CustodyUnavailable):
            await opener.check_observation(tx, staged.context, None)
    await db.execute("UPDATE {{tables.secrets}} SET active_version=NULL")
    for method in [opener.open, opener.observe]:
        with pytest.raises(CustodyUnavailable):
            await method(staged.context)


async def test_final_comparison_takes_no_row_locks(db, provider, canary):
    custody, _, _, staged = await active_fixture(db, provider, canary)
    binding = await active_binding(db, staged.context)
    opener = OnePasswordOpener(db, credential_opener=custody.backend_credential_opener)
    async with db.transaction() as tx:
        await opener.check_observation(
            tx, staged.context, BackendObservation(binding, binding.item_version)
        )
        async with db.transaction() as other:
            assert await tx.fetch_value("SELECT pg_backend_pid()") != await other.fetch_value(
                "SELECT pg_backend_pid()"
            )
            for table in [
                "secrets",
                "custody_secrets",
                "onepassword_credentials",
                "onepassword_versions",
                "sealed_versions",
            ]:
                await other.fetch_all("SELECT * FROM {{tables." + table + "}} FOR UPDATE NOWAIT")
