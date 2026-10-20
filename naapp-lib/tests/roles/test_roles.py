"""Role assignments keyed by stable principal, on real PostgreSQL."""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import replace

import asyncpg
import pytest
from pgdbm import AsyncDatabaseManager

from aweb_naapp.roles import (
    PrincipalKey,
    TargetUnresolved,
    apply_roles_migrations,
    assign,
    has_role,
    is_role_name,
    members_of,
    principal_key,
    resolve_one,
    roles_of,
    unassign,
)
from aweb_naapp.runtime.team_auth import Principal

TEAM = "aweb:example.com"
OTHER_TEAM = "acme:example.org"
DID_AW = "did:aw:2Wq7mXn4kP9rT1vY5zA8bC3dE6"
OWNER = "secrets.owner"

MEMBER = Principal(
    team_id=TEAM,
    did_key="did:key:z6MkfirstKey",
    did_aw=DID_AW,
    address="example.com/alice",
    alias="alice",
    certificate_id="cert-1",
    team_did_key="did:key:z6MkteamKey",
)
LOCAL = Principal(
    team_id=TEAM,
    did_key="did:key:z6MklocalKey",
    did_aw=None,
    address=None,
    alias="worker",
    certificate_id="cert-local-1",
    team_did_key="did:key:z6MkteamKey",
)


@pytest.fixture
async def db(test_db_factory) -> AsyncIterator[AsyncDatabaseManager]:
    database = await test_db_factory.create_db(suffix="naapp_roles")
    await apply_roles_migrations(database)
    yield database


async def _assign(db: AsyncDatabaseManager, principal: Principal, role: str) -> None:
    async with db.transaction() as tx:
        await assign(tx, principal_key(principal), role)


async def _resolve(db: AsyncDatabaseManager, team_id: str, role: str) -> PrincipalKey:
    async with db.transaction() as tx:
        return await resolve_one(tx, team_id, role)


async def test_a_reissued_certificate_under_the_same_did_aw_keeps_its_assignments(
    db: AsyncDatabaseManager,
) -> None:
    await _assign(db, MEMBER, OWNER)
    rotated = replace(MEMBER, did_key="did:key:z6MkrotatedKey", certificate_id="cert-2")
    assert await has_role(db, principal_key(rotated), OWNER)
    assert await roles_of(db, principal_key(rotated)) == [OWNER]


async def test_the_same_did_aw_on_another_team_gets_nothing(db: AsyncDatabaseManager) -> None:
    await _assign(db, MEMBER, OWNER)
    elsewhere = replace(MEMBER, team_id=OTHER_TEAM, certificate_id="cert-other")
    assert not await has_role(db, principal_key(elsewhere), OWNER)
    assert await roles_of(db, principal_key(elsewhere)) == []
    assert await members_of(db, OTHER_TEAM, OWNER) == []


async def test_a_new_local_key_is_a_new_principal(db: AsyncDatabaseManager) -> None:
    await _assign(db, LOCAL, OWNER)
    new_key = replace(LOCAL, did_key="did:key:z6MknewLocalKey", certificate_id="cert-local-2")
    assert principal_key(new_key) != principal_key(LOCAL)
    assert not await has_role(db, principal_key(new_key), OWNER)


async def test_a_certificate_without_did_aw_is_keyed_by_did_key(db: AsyncDatabaseManager) -> None:
    assert principal_key(LOCAL) == PrincipalKey(team_id=TEAM, principal_did=LOCAL.did_key)
    await _assign(db, LOCAL, OWNER)
    reissued = replace(LOCAL, certificate_id="cert-local-2", alias="worker-2")
    assert await has_role(db, principal_key(reissued), OWNER)


async def test_a_certificate_with_did_aw_is_keyed_by_did_aw_not_by_its_key(
    db: AsyncDatabaseManager,
) -> None:
    assert principal_key(MEMBER) == PrincipalKey(team_id=TEAM, principal_did=DID_AW)
    await _assign(db, MEMBER, OWNER)
    same_key_without_did_aw = replace(MEMBER, did_aw=None)
    assert not await has_role(db, principal_key(same_key_without_did_aw), OWNER)


async def test_registry_verification_never_changes_the_principal(
    db: AsyncDatabaseManager,
) -> None:
    verified = replace(MEMBER, did_aw_registry_verified=True)
    assert principal_key(verified) == principal_key(MEMBER)
    await _assign(db, MEMBER, OWNER)
    assert await has_role(db, principal_key(verified), OWNER)


async def test_members_of_lists_each_principal_holding_the_role_once(
    db: AsyncDatabaseManager,
) -> None:
    await _assign(db, MEMBER, OWNER)
    await _assign(db, MEMBER, OWNER)
    await _assign(db, LOCAL, OWNER)
    await _assign(db, LOCAL, "secrets.approver.policy-1")
    assert await members_of(db, TEAM, OWNER) == sorted(
        [principal_key(MEMBER), principal_key(LOCAL)], key=lambda key: key.principal_did
    )


async def test_a_role_held_by_one_principal_resolves_to_it(db: AsyncDatabaseManager) -> None:
    await _assign(db, MEMBER, OWNER)
    await _assign(db, LOCAL, "logs.reader")
    assert await _resolve(db, TEAM, OWNER) == principal_key(MEMBER)


async def test_a_role_held_by_nobody_is_unresolved(db: AsyncDatabaseManager) -> None:
    await _assign(db, MEMBER, OWNER)
    with pytest.raises(TargetUnresolved) as refused:
        await _resolve(db, OTHER_TEAM, OWNER)
    assert (refused.value.status, refused.value.code) == (422, "target_unresolved")


async def test_a_role_held_by_several_principals_is_unresolved(db: AsyncDatabaseManager) -> None:
    await _assign(db, MEMBER, OWNER)
    await _assign(db, LOCAL, OWNER)
    with pytest.raises(TargetUnresolved) as refused:
        await _resolve(db, TEAM, OWNER)
    assert (refused.value.status, refused.value.code) == (422, "target_unresolved")


async def test_an_unresolved_role_names_no_member(db: AsyncDatabaseManager) -> None:
    await _assign(db, MEMBER, OWNER)
    await _assign(db, LOCAL, OWNER)
    with pytest.raises(TargetUnresolved) as refused:
        await _resolve(db, TEAM, OWNER)
    shown = str(refused.value) + repr(refused.value.args)
    assert MEMBER.did_aw not in shown and LOCAL.did_key not in shown


async def test_a_resolved_assignment_cannot_be_removed_before_the_resolving_transaction_ends(
    db: AsyncDatabaseManager,
) -> None:
    await _assign(db, MEMBER, OWNER)
    async with db.transaction() as resolving:
        assert await resolve_one(resolving, TEAM, OWNER) == principal_key(MEMBER)
        with pytest.raises(asyncpg.LockNotAvailableError):
            async with db.transaction() as removing:
                await removing.execute("SET LOCAL lock_timeout = '100ms'")
                await unassign(removing, principal_key(MEMBER), OWNER)
    async with db.transaction() as removing:
        await unassign(removing, principal_key(MEMBER), OWNER)
    assert not await has_role(db, principal_key(MEMBER), OWNER)


async def test_a_did_key_assignment_does_not_follow_the_member_once_it_carries_a_did_aw(
    db: AsyncDatabaseManager,
) -> None:
    await _assign(db, LOCAL, OWNER)
    with_did_aw = replace(LOCAL, did_aw=DID_AW, certificate_id="cert-local-2")
    assert not await has_role(db, principal_key(with_did_aw), OWNER)


async def test_unassign_removes_only_that_role(db: AsyncDatabaseManager) -> None:
    await _assign(db, MEMBER, OWNER)
    await _assign(db, MEMBER, "logs.reader")
    async with db.transaction() as tx:
        await unassign(tx, principal_key(MEMBER), OWNER)
    assert await roles_of(db, principal_key(MEMBER)) == ["logs.reader"]


async def test_an_assignment_rolls_back_with_the_callers_transaction(
    db: AsyncDatabaseManager,
) -> None:
    with pytest.raises(RuntimeError):
        async with db.transaction() as tx:
            await assign(tx, principal_key(MEMBER), OWNER)
            raise RuntimeError("the caller's change set failed")
    assert not await has_role(db, principal_key(MEMBER), OWNER)


@pytest.mark.parametrize(
    "role", ["secrets.owner", "secrets.approver.policy-1", "logs.reader", "pages.editor_2"]
)
async def test_app_named_roles_are_accepted(db: AsyncDatabaseManager, role: str) -> None:
    await _assign(db, MEMBER, role)
    assert await has_role(db, principal_key(MEMBER), role)


@pytest.mark.parametrize(
    "role",
    [
        "owner",
        "",
        "secrets.",
        ".owner",
        "secrets..owner",
        "Secrets.Owner",
        "secrets:use",
        "secrets.approver.sha256:" + "a" * 64,
        "secrets." + "a" * 121,
    ],
)
async def test_a_role_without_an_app_name_is_refused(db: AsyncDatabaseManager, role: str) -> None:
    async with db.transaction() as tx:
        with pytest.raises(ValueError):
            await assign(tx, principal_key(MEMBER), role)
    with pytest.raises(ValueError):
        await has_role(db, principal_key(MEMBER), role)


def test_the_role_name_grammar_is_public() -> None:
    assert is_role_name("secrets.approver." + "a" * 64)
    assert is_role_name("secrets." + "a" * 120)
    assert not is_role_name("secrets." + "a" * 121)
    assert not is_role_name("owner")


def test_a_principal_needs_a_did_aw_or_did_key() -> None:
    with pytest.raises(ValueError):
        principal_key(replace(LOCAL, did_key="z6MkbareKey"))
    with pytest.raises(ValueError):
        principal_key(replace(MEMBER, did_aw="did:web:example.com"))
    with pytest.raises(ValueError):
        principal_key(replace(MEMBER, team_id=""))
