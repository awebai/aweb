"""secrets' records on real PostgreSQL: secrets, policies, grants and grant templates."""

from __future__ import annotations

from collections.abc import AsyncIterator

import asyncpg
import pytest
from aweb_naapp.egress import InternalDestinations
from awid.did import did_from_public_key, stable_id_from_public_key
from nacl.signing import SigningKey
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager

from aweb_secrets import records
from aweb_secrets.app import MIGRATIONS_PATH, MODULE_NAME
from aweb_secrets.destination import DestinationRecord
from aweb_secrets.grant import GrantRecord, GrantTemplate
from aweb_secrets.policy import Policy
from aweb_secrets.revisions import apply_revision_migrations, bump_config_revision, config_revision
from aweb_secrets.secret import SecretRecord

INSTALLATION = "inst_5d2a9c31"
OTHER_INSTALLATION = "inst_9e1b07f4"
TEAM = "backend:acme.com"
_KEY = bytes(SigningKey(b"\x01" * 32).verify_key)
DID_AW = stable_id_from_public_key(_KEY)
DID_KEY = did_from_public_key(bytes(SigningKey(b"\x02" * 32).verify_key))

SECRET = SecretRecord.from_after(
    {
        "v": 1,
        "secret_id": "sec_19ab42",
        "ref": "payments-live",
        "description": "Live payments API key",
        "kind": "bearer",
        "kind_params": {},
        "sensitivity": "standard",
        "approve_only": False,
        "backend": "native",
    }
)
POLICY = Policy.from_body(
    {
        "approval": "none",
        "approvers": [],
        "approval_ttl_s": 900,
        "rate": [],
        "windows": None,
        "operations": [],
        "open_request": True,
        "request": {"max_bytes": 65536},
        "result": {"max_bytes": 65536},
        "requires_attestation": None,
        "distinct_approver": "not_required",
    }
)
OPERATION = {"operation_id": "refund", "digest": "a" * 64}


def _grant(grant_id: str, subject: dict, **changes) -> GrantRecord:
    after = {
        "v": 1,
        "grant_id": grant_id,
        "secret_id": SECRET.secret_id,
        "subject": subject,
        "capability": "use",
        "operations": [],
        "open_request": True,
        "jobs": [],
        "policy_digest": POLICY.digest,
    }
    after.update(changes)
    return GrantRecord.from_after(after)


@pytest.fixture
async def db(test_db_factory) -> AsyncIterator[AsyncDatabaseManager]:
    database = await test_db_factory.create_db(suffix="secrets_records")
    await AsyncMigrationManager(
        database, migrations_path=str(MIGRATIONS_PATH), module_name=MODULE_NAME
    ).apply_pending_migrations()
    await apply_revision_migrations(database)
    yield database


async def _setup(db: AsyncDatabaseManager) -> None:
    async with db.transaction() as tx:
        await records.create_secret(tx, INSTALLATION, TEAM, SECRET)
        await records.create_policy(tx, INSTALLATION, POLICY)


async def test_a_secret_is_found_by_its_ref_in_its_installation(db) -> None:
    await _setup(db)
    async with db.transaction() as tx:
        stored = await records.secret_by_ref(tx, INSTALLATION, TEAM, "payments-live")
        assert stored is not None
        assert (stored.record, stored.state, stored.active_version) == (SECRET, "active", None)
        assert await records.secret_by_ref(tx, OTHER_INSTALLATION, TEAM, "payments-live") is None
        assert (
            await records.secret_by_ref(tx, INSTALLATION, "other:acme.com", "payments-live") is None
        )


async def test_a_ref_names_one_secret_per_installation(db) -> None:
    await _setup(db)
    twin = SecretRecord.from_after({**SECRET.after, "secret_id": "sec_twin01"})
    with pytest.raises(asyncpg.UniqueViolationError):
        async with db.transaction() as tx:
            await records.create_secret(tx, INSTALLATION, TEAM, twin)
    async with db.transaction() as tx:
        await records.create_secret(tx, OTHER_INSTALLATION, TEAM, twin)


async def test_updating_a_secret_keeps_its_state_and_version(db) -> None:
    await _setup(db)
    changed = SecretRecord.from_after({**SECRET.after, "description": "Rotated live key"})
    async with db.transaction() as tx:
        await records.update_secret(tx, INSTALLATION, TEAM, changed)
        stored = await records.secret_by_ref(tx, INSTALLATION, TEAM, "payments-live")
    assert stored is not None and stored.record == changed


async def test_a_secret_update_cannot_move_it_to_another_installation(db) -> None:
    await _setup(db)
    with pytest.raises(records.RecordMissing):
        async with db.transaction() as tx:
            await records.update_secret(tx, OTHER_INSTALLATION, TEAM, SECRET)


async def test_a_policy_is_read_back_by_digest_and_never_changes(db) -> None:
    await _setup(db)
    async with db.transaction() as tx:
        await records.create_policy(tx, INSTALLATION, POLICY)
        assert await records.policy(tx, INSTALLATION, POLICY.digest) == POLICY
        assert await records.policy(tx, OTHER_INSTALLATION, POLICY.digest) is None
    with pytest.raises(asyncpg.RaiseError):
        async with db.transaction() as tx:
            await tx.execute("UPDATE {{tables.policies}} SET body = '{}'::jsonb")


async def test_grants_are_found_for_their_principal_or_role(db) -> None:
    await _setup(db)
    to_member = _grant("grt_member01", {"principal": DID_AW})
    to_role = _grant("grt_role0001", {"role": "secrets.role.deployers"})
    to_other = _grant("grt_other001", {"principal": DID_KEY})
    async with db.transaction() as tx:
        for grant in (to_member, to_role, to_other):
            await records.create_grant(tx, INSTALLATION, TEAM, grant)
        found = await records.active_grants(
            tx,
            INSTALLATION,
            SECRET.secret_id,
            principal_did=DID_AW,
            roles=["secrets.role.deployers"],
        )
        assert sorted(g.grant_id for g in found) == ["grt_member01", "grt_role0001"]
        assert await records.active_grants(
            tx, INSTALLATION, SECRET.secret_id, principal_did=DID_AW, roles=[]
        ) == [to_member]


async def test_a_revoked_grant_is_never_found_again(db) -> None:
    await _setup(db)
    grant = _grant("grt_member01", {"principal": DID_AW})
    async with db.transaction() as tx:
        await records.create_grant(tx, INSTALLATION, TEAM, grant)
        await records.revoke_grant(tx, INSTALLATION, grant.grant_id)
        assert (
            await records.active_grants(
                tx, INSTALLATION, SECRET.secret_id, principal_did=DID_AW, roles=[]
            )
            == []
        )


async def test_a_grant_never_changes_except_by_revocation(db) -> None:
    await _setup(db)
    async with db.transaction() as tx:
        await records.create_grant(
            tx, INSTALLATION, TEAM, _grant("grt_member01", {"principal": DID_AW})
        )
    with pytest.raises(asyncpg.RaiseError):
        async with db.transaction() as tx:
            await tx.execute("UPDATE {{tables.grants}} SET open_request = FALSE")
    with pytest.raises(asyncpg.RaiseError):
        async with db.transaction() as tx:
            await records.revoke_grant(tx, INSTALLATION, "grt_member01")
            await tx.execute("UPDATE {{tables.grants}} SET revoked_at = NULL")


async def test_a_grant_needs_its_secret_and_policy_in_the_same_installation(db) -> None:
    await _setup(db)
    grant = _grant("grt_member01", {"principal": DID_AW})
    with pytest.raises(asyncpg.ForeignKeyViolationError):
        async with db.transaction() as tx:
            await records.create_grant(tx, OTHER_INSTALLATION, TEAM, grant)
    unknown_policy = _grant("grt_member02", {"principal": DID_AW}, policy_digest="d" * 64)
    with pytest.raises(asyncpg.ForeignKeyViolationError):
        async with db.transaction() as tx:
            await records.create_grant(tx, INSTALLATION, TEAM, unknown_policy)


async def test_a_grant_keeps_its_operation_digests(db) -> None:
    await _setup(db)
    grant = _grant(
        "grt_member01", {"principal": DID_AW}, operations=[OPERATION], open_request=False
    )
    async with db.transaction() as tx:
        await records.create_grant(tx, INSTALLATION, TEAM, grant)
        (found,) = await records.active_grants(
            tx, INSTALLATION, SECRET.secret_id, principal_did=DID_AW, roles=[]
        )
    assert found.covers_operation("refund", "a" * 64)
    assert not found.covers_operation("refund", "b" * 64)


async def test_a_grant_template_is_created_and_updated_in_place(db) -> None:
    template = GrantTemplate.from_after(
        {
            "v": 1,
            "grant_template_id": "gtp_sts-derived",
            "subject": {"role": "secrets.role.deployers"},
            "capability": "use",
            "operations": [],
            "open_request": True,
            "jobs": [],
            "policy_digest": POLICY.digest,
        }
    )
    changed = GrantTemplate.from_after({**template.after, "subject": {"principal": DID_AW}})
    await _setup(db)
    async with db.transaction() as tx:
        await records.set_grant_template(tx, INSTALLATION, template)
        await records.set_grant_template(tx, INSTALLATION, changed)
        assert await records.grant_template(tx, INSTALLATION, "gtp_sts-derived") == changed
        assert await records.grant_template(tx, OTHER_INSTALLATION, "gtp_sts-derived") is None


async def test_records_roll_back_with_the_callers_transaction(db) -> None:
    with pytest.raises(RuntimeError):
        async with db.transaction() as tx:
            await records.create_secret(tx, INSTALLATION, TEAM, SECRET)
            raise RuntimeError("the change set failed")
    async with db.transaction() as tx:
        assert await records.secret_by_ref(tx, INSTALLATION, TEAM, "payments-live") is None


async def test_revoking_a_grant_moves_the_installation_to_its_next_revision(db) -> None:
    await _setup(db)
    async with db.transaction() as tx:
        await records.create_grant(
            tx, INSTALLATION, TEAM, _grant("grt_member01", {"principal": DID_AW})
        )
        drafted_at = await bump_config_revision(tx, INSTALLATION)
    async with db.transaction() as tx:
        await records.revoke_grant(tx, INSTALLATION, "grt_member01")
    assert await config_revision(db, INSTALLATION) == drafted_at + 1
    assert await config_revision(db, OTHER_INSTALLATION) == 0


async def test_revoking_a_revoked_grant_leaves_the_revision_alone(db) -> None:
    await _setup(db)
    async with db.transaction() as tx:
        await records.create_grant(
            tx, INSTALLATION, TEAM, _grant("grt_member01", {"principal": DID_AW})
        )
        await records.revoke_grant(tx, INSTALLATION, "grt_member01")
    revoked_at = await config_revision(db, INSTALLATION)
    async with db.transaction() as tx:
        await records.revoke_grant(tx, INSTALLATION, "grt_member01")
        await records.revoke_grant(tx, INSTALLATION, "grt_unknown01")
    assert await config_revision(db, INSTALLATION) == revoked_at


async def test_a_revocation_rolled_back_leaves_the_revision_alone(db) -> None:
    await _setup(db)
    async with db.transaction() as tx:
        await records.create_grant(
            tx, INSTALLATION, TEAM, _grant("grt_member01", {"principal": DID_AW})
        )
    with pytest.raises(RuntimeError):
        async with db.transaction() as tx:
            await records.revoke_grant(tx, INSTALLATION, "grt_member01")
            raise RuntimeError("the narrowing act failed later")
    assert await config_revision(db, INSTALLATION) == 0


def _destination(destination_id: str = "dst_charges01", **changes) -> DestinationRecord:
    after = {
        "v": 1,
        "destination_id": destination_id,
        "secret_id": SECRET.secret_id,
        "scheme": "https",
        "host": "api.payments.example",
        "port": 443,
        "path": "/v1/charges/**",
        "methods": ["GET", "POST"],
        "query_rules": {},
        "header_allow": [],
        "network": "public",
        "cidr": None,
    }
    after.update(changes)
    return DestinationRecord.from_after(after, internal_destinations=InternalDestinations.ALLOWED)


async def test_a_secrets_destinations_are_listed_in_its_installation(db) -> None:
    await _setup(db)
    charges = _destination()
    refunds = _destination("dst_refunds01", path="/v1/refunds/**")
    async with db.transaction() as tx:
        await records.create_destination(tx, INSTALLATION, TEAM, refunds)
        await records.create_destination(tx, INSTALLATION, TEAM, charges)
        listed = await records.destinations(tx, INSTALLATION, SECRET.secret_id)
        assert [d.after for d in listed] == [charges.after, refunds.after]
        assert await records.destinations(tx, OTHER_INSTALLATION, SECRET.secret_id) == []


async def test_a_destination_needs_its_secret_in_the_same_installation(db) -> None:
    await _setup(db)
    with pytest.raises(asyncpg.ForeignKeyViolationError):
        async with db.transaction() as tx:
            await records.create_destination(tx, OTHER_INSTALLATION, TEAM, _destination())


async def test_a_destination_never_changes(db) -> None:
    await _setup(db)
    async with db.transaction() as tx:
        await records.create_destination(tx, INSTALLATION, TEAM, _destination())
    with pytest.raises(asyncpg.RaiseError):
        async with db.transaction() as tx:
            await tx.execute("UPDATE {{tables.destinations}} SET record = '{}'::jsonb")


async def test_removing_a_destination_is_a_narrowing_act(db) -> None:
    await _setup(db)
    async with db.transaction() as tx:
        await records.create_destination(tx, INSTALLATION, TEAM, _destination())
    before = await config_revision(db, INSTALLATION)
    async with db.transaction() as tx:
        await records.remove_destination(tx, INSTALLATION, "dst_charges01")
        assert await records.destinations(tx, INSTALLATION, SECRET.secret_id) == []
    assert await config_revision(db, INSTALLATION) == before + 1
    async with db.transaction() as tx:
        await records.remove_destination(tx, INSTALLATION, "dst_charges01")
    assert await config_revision(db, INSTALLATION) == before + 1
