"""Hook bindings: pending rows per install generation, superseded by a new
generation and revoked by uninstall (audit-substrate.md §A3).

Real Postgres through the migrated aweb schema. Activation is the owner act's
(K2) and is not exercised here; rows are made active only through the
constraints a real activation must satisfy.
"""

from __future__ import annotations

import hashlib

import asyncpg
import pytest
import pytest_asyncio
from pgdbm.errors import QueryError

from aweb.app_registry import install_app
from aweb.hook_bindings import (
    PRODUCTION,
    REGISTRATION,
    HookBindingDeclaration,
    list_app_bindings,
    revoke_uninstalled_bindings,
    write_pending_bindings,
)
from aweb.service_errors import ValidationError
from tests.test_app_events_http import _seed_team_and_agent

TEAM = "backend:acme.com"
OTHER_TEAM = "frontend:acme.com"
ORIGIN = "https://logs.example"

RECORD = HookBindingDeclaration(
    kind=REGISTRATION, catalog_id="aweb.hooks", catalog_version=1, hook="post-secret-use-hook",
    tool="ingest", method="POST", path="/hooks/ingest", scopes=("logs:write", "logs:append"),
)
EMIT = HookBindingDeclaration(
    kind=PRODUCTION, catalog_id="aweb.hooks", catalog_version=1, hook="post-governance-hook",
    reads=("search", "export"),
)


def _digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


async def _install(db, *, team_id: str = TEAM, app_id: str = "logs", digest: str) -> None:
    await install_app(
        db, team_id=team_id, app_id=app_id, origin=ORIGIN, app_version="1.0.0",
        manifest_version=1, digest=digest, granted_scopes=[],
    )


async def _write(db, *, team_id=TEAM, app_id="logs", digest, installation_id="inst-1", generation=1,
                 declarations=(RECORD, EMIT)):
    async with db.transaction() as tx:
        return await write_pending_bindings(
            tx, team_id=team_id, app_id=app_id, origin=ORIGIN, digest=digest,
            installation_id=installation_id, generation=generation, declarations=list(declarations),
        )


def _check_refused():
    """The schema's CHECK constraint, not some other failure, refused the write."""
    return pytest.raises(QueryError, check=lambda exc: isinstance(exc.__cause__, asyncpg.CheckViolationError))


async def _make_active(db, binding_id) -> None:
    await db.execute(
        """
        UPDATE {{tables.app_hook_bindings}}
        SET state = 'active', activated_at = NOW(), active_from = NOW() + INTERVAL '60 seconds',
            activation_act_sha256 = $2
        WHERE binding_id = $1
        """,
        binding_id, "ab" * 32,
    )


@pytest_asyncio.fixture
async def db(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    await _seed_team_and_agent(db, team_id=TEAM)
    await _seed_team_and_agent(db, team_id=OTHER_TEAM)
    return db


@pytest.mark.asyncio
async def test_an_install_writes_one_pending_binding_per_declaration(db):
    digest = _digest("v1")
    await _install(db, digest=digest)

    written = await _write(db, digest=digest)

    assert [(b.kind, b.hook, b.state) for b in written] == [
        (REGISTRATION, "post-secret-use-hook", "pending"),
        (PRODUCTION, "post-governance-hook", "pending"),
    ]
    registration, production = written
    assert (registration.tool, registration.method, registration.path) == ("ingest", "POST", "/hooks/ingest")
    assert registration.scopes == ("logs:append", "logs:write")
    assert registration.reads == ()
    assert (production.tool, production.method, production.path, production.scopes) == (None, None, None, ())
    assert production.reads == ("export", "search")
    for binding in written:
        assert (binding.installation_id, binding.generation, binding.digest) == ("inst-1", 1, digest)
        assert binding.activated_at is binding.active_from is binding.revoked_at is binding.ended_by is None
    assert await list_app_bindings(db, team_id=TEAM, app_id="logs") == written


@pytest.mark.asyncio
async def test_rewriting_the_same_generation_keeps_its_bindings(db):
    digest = _digest("v1")
    await _install(db, digest=digest)
    first = await _write(db, digest=digest)
    await _make_active(db, first[0].binding_id)

    again = await _write(db, digest=digest)

    assert [b.binding_id for b in again] == [b.binding_id for b in first]
    assert [b.state for b in await list_app_bindings(db, team_id=TEAM, app_id="logs")] == ["active", "pending"]


@pytest.mark.asyncio
async def test_a_new_generation_supersedes_every_earlier_binding_and_inherits_no_activation(db):
    old, new = _digest("v1"), _digest("v2")
    await _install(db, digest=old)
    first = await _write(db, digest=old)
    await _make_active(db, first[0].binding_id)
    await _install(db, digest=new)

    second = await _write(db, digest=new, generation=2)

    rows = {b.binding_id: b for b in await list_app_bindings(db, team_id=TEAM, app_id="logs")}
    for binding in first:
        ended = rows[binding.binding_id]
        assert (ended.state, ended.ended_by) == ("superseded", "generation")
        assert ended.revoked_at is not None
    assert {b.binding_id for b in second}.isdisjoint({b.binding_id for b in first})
    assert [(b.state, b.generation, b.digest) for b in second] == [("pending", 2, new), ("pending", 2, new)]


@pytest.mark.asyncio
async def test_uninstall_revokes_the_live_bindings_and_leaves_ended_ones(db):
    old, new = _digest("v1"), _digest("v2")
    await _install(db, digest=old)
    first = await _write(db, digest=old)
    await _install(db, digest=new)
    second = await _write(db, digest=new, generation=2)
    await _make_active(db, second[0].binding_id)

    async with db.transaction() as tx:
        assert await revoke_uninstalled_bindings(tx, team_id=TEAM, app_id="logs") == 2

    rows = {b.binding_id: b for b in await list_app_bindings(db, team_id=TEAM, app_id="logs")}
    assert {(rows[b.binding_id].state, rows[b.binding_id].ended_by) for b in second} == {("revoked", "uninstall")}
    assert {(rows[b.binding_id].state, rows[b.binding_id].ended_by) for b in first} == {("superseded", "generation")}


async def _assert_fresh_pending(db, written, ended, *, digest, ended_state, ended_by):
    rows = {b.binding_id: b for b in await list_app_bindings(db, team_id=TEAM, app_id="logs")}
    assert len(written) == 2
    assert {b.binding_id for b in written}.isdisjoint({b.binding_id for b in ended})
    assert [(b.state, b.digest) for b in written] == [("pending", digest), ("pending", digest)]
    assert {(rows[b.binding_id].state, rows[b.binding_id].ended_by) for b in ended} == {(ended_state, ended_by)}
    assert len(rows) == 4


@pytest.mark.asyncio
async def test_before_installation_identity_a_new_digest_gets_fresh_pending_bindings(db):
    old, new = _digest("v1"), _digest("v2")
    await _install(db, digest=old)
    first = await _write(db, digest=old, installation_id=None, generation=None)
    await _install(db, digest=new)

    second = await _write(db, digest=new, installation_id=None, generation=None)

    await _assert_fresh_pending(db, second, first, digest=new, ended_state="superseded", ended_by="generation")


@pytest.mark.asyncio
async def test_a_reinstall_after_uninstall_gets_fresh_pending_bindings(db):
    digest = _digest("v1")
    await _install(db, digest=digest)
    first = await _write(db, digest=digest, installation_id=None, generation=None)
    async with db.transaction() as tx:
        await revoke_uninstalled_bindings(tx, team_id=TEAM, app_id="logs")

    second = await _write(db, digest=digest, installation_id=None, generation=None)

    await _assert_fresh_pending(db, second, first, digest=digest, ended_state="revoked", ended_by="uninstall")


@pytest.mark.asyncio
async def test_another_team_and_another_app_are_untouched(db):
    digest = _digest("v1")
    await _install(db, digest=digest)
    await _install(db, team_id=OTHER_TEAM, digest=digest)
    await _install(db, app_id="secrets", digest=digest)
    other_team = await _write(db, team_id=OTHER_TEAM, digest=digest)
    other_app = await _write(db, app_id="secrets", digest=digest, installation_id=None, generation=None)
    await _write(db, digest=digest, installation_id=None, generation=None)
    await _install(db, digest=_digest("v2"))
    await _write(db, digest=_digest("v2"), generation=2)

    async with db.transaction() as tx:
        await revoke_uninstalled_bindings(tx, team_id=TEAM, app_id="logs")

    assert await list_app_bindings(db, team_id=OTHER_TEAM, app_id="logs") == other_team
    assert await list_app_bindings(db, team_id=TEAM, app_id="secrets") == other_app


@pytest.mark.asyncio
async def test_bindings_before_installation_identity_exist_once_and_cannot_activate(db):
    digest = _digest("v1")
    await _install(db, digest=digest)
    written = await _write(db, digest=digest, installation_id=None, generation=None)
    again = await _write(db, digest=digest, installation_id=None, generation=None)
    assert [b.binding_id for b in again] == [b.binding_id for b in written]

    with _check_refused():
        await _make_active(db, written[0].binding_id)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "declaration, message",
    [
        (HookBindingDeclaration(kind=REGISTRATION, catalog_id="aweb.hooks", catalog_version=1, hook="h",
                                tool="ingest", method="POST", path="/i", scopes=("a", "a")), "scopes"),
        (HookBindingDeclaration(kind=PRODUCTION, catalog_id="aweb.hooks", catalog_version=1, hook="h",
                                reads=("x", "x")), "reads"),
        (HookBindingDeclaration(kind=REGISTRATION, catalog_id="aweb.hooks", catalog_version=1, hook="h"), "tool"),
        (HookBindingDeclaration(kind=PRODUCTION, catalog_id="aweb.hooks", catalog_version=1, hook="h",
                                tool="ingest", method="POST", path="/i"), "tool"),
        (HookBindingDeclaration(kind=PRODUCTION, catalog_id="aweb.hooks", catalog_version=1, hook="h",
                                scopes=("a",)), "scopes"),
        (HookBindingDeclaration(kind=REGISTRATION, catalog_id="aweb.hooks", catalog_version=1, hook="h",
                                tool="ingest", method="POST", path="/i", reads=("x",)), "reads"),
        (HookBindingDeclaration(kind="consumer", catalog_id="aweb.hooks", catalog_version=1, hook="h"), "kind"),
    ],
)
async def test_a_malformed_declaration_is_refused_and_nothing_is_written(db, declaration, message):
    digest = _digest("v1")
    await _install(db, digest=digest)

    with pytest.raises(ValidationError, match=message):
        await _write(db, digest=digest, declarations=[RECORD, declaration])

    assert await list_app_bindings(db, team_id=TEAM, app_id="logs") == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "target, assignment",
    [
        ("registration", "state = 'revoked'"),
        ("registration", "state = 'superseded', revoked_at = NOW()"),
        ("production", "tool = 'ingest'"),
        ("production", "scopes = ARRAY['a']"),
        ("registration", "reads = ARRAY['x']"),
        ("registration", "state = 'active', activated_at = NOW(), active_from = NOW() + INTERVAL '60 seconds'"),
        ("registration", "state = 'active', activated_at = NOW(), active_from = NOW(), activation_act_sha256 = '"
         + "ab" * 32 + "'"),
        ("registration", "activation_act_sha256 = 'not-hex'"),
        ("registration", "state = 'active', activated_at = NOW(), activation_act_sha256 = '" + "ab" * 32 + "'"),
        ("registration", "ended_by = 'uninstall'"),
    ],
)
async def test_the_schema_refuses_rows_the_store_would_never_write(db, target, assignment):
    digest = _digest("v1")
    await _install(db, digest=digest)
    registration, production = await _write(db, digest=digest)
    binding = registration if target == "registration" else production

    with _check_refused():
        await db.execute(
            "UPDATE {{tables.app_hook_bindings}} SET " + assignment + " WHERE binding_id = $1", binding.binding_id,
        )
