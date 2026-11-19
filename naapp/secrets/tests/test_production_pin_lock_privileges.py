"""The private production role can lock real runner pins but cannot change them."""

from uuid import UUID, uuid4

import asyncpg
import pytest

from aweb_secrets.erasure import check_erasure_store, map_erasure_failure
from aweb_secrets.run_pin_store import prepare_dispatches, read
from aweb_secrets.schema import service_schema_fingerprint
from tests.test_production_bootstrap import root as root
from tests.test_production_dispatch import admitted_run
from tests.test_production_runner_dispatch import runner_headers

_LOCK_PIN = (
    "SELECT dispatch_id FROM {{tables.run_redaction_pins}} WHERE dispatch_id=$1 FOR UPDATE NOWAIT"
)


async def assert_pin_locked(db, dispatch_id, *, holder_pid):
    with pytest.raises(asyncpg.LockNotAvailableError):
        async with db.transaction() as contender:
            assert await contender.fetch_value("SELECT pg_backend_pid()") != holder_pid
            await contender.fetch_value(_LOCK_PIN, dispatch_id)


async def test_private_production_role_locks_claimed_pin_without_mutation_authority(
    root, onepassword_values
):
    app, client, configured, member, installed, *_ = root
    db = app.runtime.db()
    assert await db.fetch_value(
        "SELECT NOT r.rolsuper AND current_user=s.application_role"
        " AND NOT pg_has_role(current_user,'secrets_erasure_owner','MEMBER')"
        " FROM pg_roles r CROSS JOIN secrets_erasure.store s WHERE r.rolname=current_user"
    )
    request = await admitted_run(root, onepassword_values=onepassword_values)
    claim_path = "/runner/v1/claim"
    claimed = await client.post(
        configured.public_origin + claim_path,
        content=b"{}",
        headers=runner_headers(request, configured.public_origin, claim_path),
    )
    assert claimed.status_code == 200
    dispatch_id = UUID(claimed.json()["assignment"]["dispatch_id"])
    identity = {
        "installation_id": installed["installation_id"],
        "team_id": member.team_id,
        "dispatch_id": dispatch_id,
    }
    pin_table = f'"{db.schema or "public"}".run_redaction_pins'
    assert not await db.fetch_value(
        "SELECT has_table_privilege(current_user,$1::text,'UPDATE')", pin_table
    )
    assert await db.fetch_value(
        "SELECT has_column_privilege(current_user,$1::text,'dispatch_id','UPDATE')", pin_table
    )
    await check_erasure_store(db, expected_schema_digest=service_schema_fingerprint())

    # Each public operation must retain the real row lock independently.
    async with db.transaction() as tx:
        await prepare_dispatches(tx, [dispatch_id])
        await assert_pin_locked(
            db, dispatch_id, holder_pid=await tx.fetch_value("SELECT pg_backend_pid()")
        )
    async with db.transaction() as tx:
        [pin] = await read(tx, **identity, hold=True)
        assert pin["dispatch_id"] == dispatch_id
        await assert_pin_locked(
            db, dispatch_id, holder_pid=await tx.fetch_value("SELECT pg_backend_pid()")
        )
    async with db.transaction() as tx:
        assert await tx.fetch_value(_LOCK_PIN, dispatch_id) == dispatch_id

    # 007_run_redaction_pins.sql's BEFORE UPDATE trigger refuses even a no-op.
    # The one column grant permits locking, never changing the retained pin.
    for replacement in (dispatch_id, uuid4()):
        with pytest.raises(asyncpg.RaiseError) as immutable:
            async with db.transaction() as tx:
                await tx.execute(
                    "UPDATE {{tables.run_redaction_pins}} SET dispatch_id=$2 WHERE dispatch_id=$1",
                    dispatch_id,
                    replacement,
                )
        assert immutable.value.sqlstate == "P0001"
    with pytest.raises(asyncpg.InsufficientPrivilegeError) as denied:
        async with db.transaction() as tx:
            await tx.execute(
                "UPDATE {{tables.run_redaction_pins}} SET secret_id=secret_id WHERE dispatch_id=$1",
                dispatch_id,
            )
    assert denied.value.sqlstate == "42501"
    assert map_erasure_failure(denied.value) is None
    async with db.transaction() as tx:
        [after] = await read(tx, **identity, hold=True)
        assert (after["dispatch_id"], after["secret_id"], after["version"]) == (
            pin["dispatch_id"],
            pin["secret_id"],
            pin["version"],
        )
    await check_erasure_store(db, expected_schema_digest=service_schema_fingerprint())
