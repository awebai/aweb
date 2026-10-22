"""Confirmed runner records return registration material only to their owner console."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from aweb_naapp.console import ConsoleSession
from aweb_naapp.hooks.strictjson import encode_base64url
from aweb_naapp.roles import unassign
from aweb_naapp_testing.owner_acts import INSTALLATION_ID
from awid.did import did_from_public_key
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from nacl.signing import SigningKey

from aweb_secrets.change import ChangeRefused
from aweb_secrets.console_results import confirmation_receipt, owner_confirmation_result
from aweb_secrets.owners import OWNER_ROLE
from aweb_secrets.runners import (
    active_runner,
    apply_runner_migrations,
    deregister_runner,
    mint_runner_id,
    register_runner,
)
from tests.test_change_sets import (
    ALICE,
    BOB,
    CAROL,
    World,
    by_member,
    change_set,
    decide,
    draft,
    enrol_owner,
)
from tests.test_change_sets import world as _world

world = _world


@pytest.fixture
async def runner_world(world: World) -> World:
    await apply_runner_migrations(world.db)
    return world


def runner_item(runner_id: str, op: str = "create"):
    return {
        "kind": "runner",
        "op": op,
        "ref": runner_id,
        "after": {
            "v": 1,
            "runner_id": runner_id,
            "label": "Build runner",
            "allowed_jobs": ["build"],
        },
    }


async def session_for(world: World, scope: str, contact: str) -> ConsoleSession:
    options = await world.passkeys.login_options(scope)
    verified = await world.passkeys.verify_login(scope, world.devices[contact].get(dict(options)))
    return ConsoleSession(
        subject=verified.subject,
        scope=scope,
        evidence_ref=verified.evidence_ref,
        expires_at=datetime.now(UTC) + timedelta(minutes=15),
        token_sha256=secrets.token_bytes(32),
    )


async def confirm_in(world: World, tx, change):
    return await world.change_sets.confirm(
        tx,
        change["change_id"],
        operation_id=f"apply-{change['change_id']}",
        fence=world.fence,
        admitted=world.admitted,
    )


async def test_a_runner_draft_is_inert_and_code_is_scoped_to_committed_owner_console(runner_world):
    w = runner_world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    bob_scope = await enrol_owner(w, BOB, "bob@acme.com")
    alice = await session_for(w, scope, "alice@acme.com")
    bob = await session_for(w, bob_scope, "bob@acme.com")
    runner_id = mint_runner_id()
    change = change_set(drafter=by_member(CAROL), changes=[runner_item(runner_id)])
    pending = await draft(w, change)
    assert not await w.db.fetch_value("SELECT count(*) FROM {{tables.runners}}")
    await decide(w, pending, "alice@acme.com")
    async with w.db.transaction() as tx:
        result = await confirm_in(w, tx, change)
        with pytest.raises(ChangeRefused):
            await owner_confirmation_result(w.db, w.directory, result, alice)
    code = result.runner_registrations[0].registration_code
    assert code not in repr(result)
    assert code not in repr(result.runner_registrations[0])
    assert confirmation_receipt(result) == {"change_id": change["change_id"], "revision": 1}
    with pytest.raises(ChangeRefused):
        await owner_confirmation_result(w.db, w.directory, result, bob)
    for stale in (
        replace(alice, subject=bob.subject),
        replace(alice, expires_at=datetime.now(UTC) - timedelta(seconds=1)),
    ):
        with pytest.raises(ChangeRefused):
            await owner_confirmation_result(w.db, w.directory, result, stale)
    shown = await owner_confirmation_result(w.db, w.directory, result, alice)
    assert shown["runner_registrations"] == [
        {
            "runner_id": runner_id,
            "registration_code": code,
            "reenabled": False,
            "keys_replaced": False,
            "registration_required": True,
        }
    ]
    assert (
        await w.db.fetch_value("SELECT code_hash FROM {{tables.runners}}")
        == hashlib.sha256(code.encode()).digest()
    )


async def test_a_rolled_back_confirmation_cannot_disclose_a_code(runner_world):
    w = runner_world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    alice = await session_for(w, scope, "alice@acme.com")
    runner_id = mint_runner_id()
    change = change_set(drafter=by_member(CAROL), changes=[runner_item(runner_id)])
    await decide(w, await draft(w, change), "alice@acme.com")

    class Abandoned(Exception):
        pass

    with pytest.raises(Abandoned):
        async with w.db.transaction() as tx:
            result = await confirm_in(w, tx, change)
            raise Abandoned
    with pytest.raises(ChangeRefused):
        await owner_confirmation_result(w.db, w.directory, result, alice)
    assert not await w.db.fetch_value("SELECT count(*) FROM {{tables.runners}}")


async def test_runner_replacement_reenables_and_discloses_key_rotation(runner_world):
    w = runner_world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    alice = await session_for(w, scope, "alice@acme.com")
    runner_id = mint_runner_id()
    create = change_set(drafter=by_member(CAROL), changes=[runner_item(runner_id)])
    await decide(w, await draft(w, create), "alice@acme.com")
    async with w.db.transaction() as tx:
        first = await confirm_in(w, tx, create)
    old_code = first.runner_registrations[0].registration_code
    signing_key = did_from_public_key(bytes(SigningKey.generate().verify_key))
    encryption_key = encode_base64url(X25519PrivateKey.generate().public_key().public_bytes_raw())
    async with w.db.transaction() as tx:
        await register_runner(
            tx, code=old_code, signing_key=signing_key, encryption_key=encryption_key
        )
        await deregister_runner(tx, INSTALLATION_ID, runner_id, now=datetime.now(UTC))
    update = change_set(
        drafter=by_member(CAROL), changes=[runner_item(runner_id, "update")], base_revision=1
    )
    await decide(w, await draft(w, update), "alice@acme.com")
    async with w.db.transaction() as tx:
        rotated = await confirm_in(w, tx, update)
    code = rotated.runner_registrations[0].registration_code
    assert code != old_code
    shown = await owner_confirmation_result(w.db, w.directory, rotated, alice)
    assert shown["runner_registrations"][0] == {
        "runner_id": runner_id,
        "registration_code": code,
        "reenabled": True,
        "keys_replaced": True,
        "registration_required": True,
    }
    async with w.db.transaction() as tx:
        assert await active_runner(tx, runner_id) is None
        await register_runner(tx, code=code, signing_key=signing_key, encryption_key=encryption_key)
        assert await active_runner(tx, runner_id) is not None


async def test_a_revoked_owner_cannot_read_registration_material(runner_world):
    w = runner_world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    alice = await session_for(w, scope, "alice@acme.com")
    change = change_set(drafter=by_member(CAROL), changes=[runner_item(mint_runner_id())])
    await decide(w, await draft(w, change), "alice@acme.com")
    async with w.db.transaction() as tx:
        result = await confirm_in(w, tx, change)
    async with w.db.transaction() as tx:
        await unassign(tx, ALICE, OWNER_ROLE)
    with pytest.raises(ChangeRefused):
        await owner_confirmation_result(w.db, w.directory, result, alice)
