"""Persisted producer commitments survive retries, rotation and database rollback."""

import secrets
from dataclasses import replace
from datetime import timedelta
from uuid import uuid4

import asyncpg
import pytest
from aweb_naapp.dispatch import Dispatches, apply_dispatch_migrations
from aweb_naapp.hooks.commitment import (
    CommitmentContext,
    CommitmentError,
    Purpose,
    RequestBytes,
    load_commitment_key,
)
from aweb_naapp.runtime.approvals import canonical_request
from aweb_naapp.runtime.approvals.request import DOMAIN_PREFIX

from aweb_secrets.use_context import (
    UseCommitter,
    apply_use_context_migrations,
    note_dispatch_started,
    store_use_context,
    use_context,
)
from tests.test_admission import ALICE, NOW, _admit, _install
from tests.test_admission import db as db
from tests.test_admission import fence as fence


def _committer(directory):
    directory.mkdir(parents=True)
    request, params = directory / "request", directory / "params"
    for path in (request, params):
        path.write_text(secrets.token_hex(32) + "\n")
        path.chmod(0o600)
    return UseCommitter.from_files(request, params)


def _context(admission=None):
    if admission is None:
        return CommitmentContext("secrets", "backend:acme.com", "inst_5d2a9c31", 3, "request")
    installed = admission.installation
    return CommitmentContext(
        installed.app_id,
        installed.team_id,
        installed.installation_id,
        installed.generation,
        "request",
    )


def _attempt(committer, context, *, body=None):
    return committer.commit(
        context,
        RequestBytes(
            "POST",
            b"/secrets/stripe/request",
            (b"application/json",),
            secrets.token_bytes(32) if body is None else body,
        ),
        parameters={"amount": 17, "note": "caf\u00e9"},
    )


def test_params_reuse_integer_only_canonical_json_without_b2_framing(tmp_path):
    committer = _committer(tmp_path / "keys")
    context = _context()
    parameters = {"note": "caf\u00e9", "amount": 17}
    committed = committer.commit(context, None, parameters=parameters)
    canonical = canonical_request(parameters)[len(DOMAIN_PREFIX) :]
    assert canonical == '{"amount":17,"note":"caf\u00e9"}'.encode()
    assert committed.params_mac == load_commitment_key(
        Purpose.SECRET_PARAMS, tmp_path / "keys" / "params"
    ).params(context, canonical)
    assert committed.request_mac is None
    assert committer.commit(context, None, parameters=None).params_mac is None


@pytest.mark.parametrize("parameters", [{"x": 1.5}, {"x": 2**53}, {"x": "\ud800"}])
def test_bad_optional_params_never_suppress_the_request_commitment(tmp_path, parameters):
    committer = _committer(tmp_path / "keys")
    committed = committer.commit(
        _context(),
        RequestBytes("POST", b"/secrets/stripe/request", (), b"{}"),
        parameters=parameters,
    )
    assert committed.request_mac is not None
    assert committed.params_mac is None


def test_two_purposes_cannot_use_the_same_key_file_or_symlink(tmp_path):
    key = tmp_path / "key"
    key.write_text(secrets.token_hex(32))
    key.chmod(0o600)
    alias = tmp_path / "alias"
    alias.symlink_to(key)
    for path in (key, alias):
        with pytest.raises(CommitmentError):
            UseCommitter.from_files(key, path)


async def _prepare(db, fence):
    await _install(db)
    await apply_dispatch_migrations(db)
    await apply_use_context_migrations(db)
    return await _admit(db, fence, ALICE)


async def test_first_received_transition_reads_context_and_rotation_cannot_overwrite_it(
    db, fence, tmp_path
):
    admitted = await _prepare(db, fence)
    body = secrets.token_bytes(32)
    first = _attempt(_committer(tmp_path / "first"), _context(admitted), body=body)
    rotated = _attempt(_committer(tmp_path / "rotated"), _context(admitted), body=body)
    assert first.request_mac != rotated.request_mac
    dispatch_id = uuid4()

    async def transition(tx, event):
        stored = await use_context(tx, event.dispatch_id)
        assert stored.intent_id == admitted.intent_id
        assert stored.commitments == first

    machine = Dispatches(
        on_transition=transition,
        max_dispatch=timedelta(seconds=30),
        sweep_margin=timedelta(seconds=5),
    )
    async with db.transaction() as tx:
        await store_use_context(tx, admission=admitted, dispatch_id=dispatch_id, commitments=first)
        await machine.create(tx, dispatch_id=dispatch_id, subject="subject", action="operation")
    async with db.transaction() as tx:
        replayed = await store_use_context(
            tx,
            admission=replace(admitted, replayed=True),
            dispatch_id=dispatch_id,
            commitments=rotated,
        )
    assert replayed.commitments == first
    assert replayed.dispatch_id == dispatch_id


async def test_context_and_first_dispatch_start_are_immutable(db, fence, tmp_path):
    admitted = await _prepare(db, fence)
    committed = _attempt(_committer(tmp_path / "keys"), _context(admitted))
    dispatch_id = uuid4()
    async with db.transaction() as tx:
        await store_use_context(
            tx, admission=admitted, dispatch_id=dispatch_id, commitments=committed
        )
        await tx.execute(
            "INSERT INTO {{tables.dispatches}} (dispatch_id,subject,action,state) VALUES ($1,'subject','operation','received')",
            dispatch_id,
        )
        assert (await note_dispatch_started(tx, dispatch_id, NOW)).dispatch_started_at == NOW
        assert (
            await note_dispatch_started(tx, dispatch_id, NOW + timedelta(seconds=20))
        ).dispatch_started_at == NOW
    for change in (
        "request_mac='" + "0" * 64 + "'",
        "dispatch_started_at=dispatch_started_at+interval '1 second'",
    ):
        with pytest.raises(asyncpg.RaiseError):
            async with db.transaction() as tx:
                await tx.execute(
                    "UPDATE {{tables.use_contexts}} SET " + change + " WHERE dispatch_id=$1",
                    dispatch_id,
                )
    async with db.transaction() as tx:
        stored = await use_context(tx, dispatch_id)
    assert stored.commitments == committed
    assert stored.dispatch_started_at == NOW


async def test_no_context_can_commit_without_its_dispatch_and_scope_binding(db, fence, tmp_path):
    admitted = await _prepare(db, fence)
    committed = _attempt(_committer(tmp_path / "keys"), _context(admitted))
    with pytest.raises(asyncpg.ForeignKeyViolationError):
        async with db.transaction() as tx:
            await store_use_context(
                tx, admission=admitted, dispatch_id=uuid4(), commitments=committed
            )
    assert await db.fetch_value("SELECT count(*) FROM {{tables.use_contexts}}") == 0
    wrong = replace(committed, context=replace(committed.context, generation=99))
    with pytest.raises(ValueError):
        async with db.transaction() as tx:
            await store_use_context(tx, admission=admitted, dispatch_id=uuid4(), commitments=wrong)
    assert await db.fetch_value("SELECT count(*) FROM {{tables.use_contexts}}") == 0
