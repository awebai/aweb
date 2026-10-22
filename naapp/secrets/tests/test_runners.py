"""Runner registration codes, keys and deregistration on real PostgreSQL."""

from __future__ import annotations

import asyncio
import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from aweb_naapp.hooks.strictjson import encode_base64url
from awid.did import did_from_public_key
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from nacl.signing import SigningKey

from aweb_secrets.runner_protocol import RunnerRefused
from aweb_secrets.runners import (
    RunnerRecord,
    active_runner,
    apply_runner_migrations,
    create_runner,
    deregister_runner,
    mint_runner_id,
    register_runner,
)

NOW = datetime(2026, 10, 21, tzinfo=UTC)


@pytest.fixture
async def db(test_db_factory):
    database = await test_db_factory.create_db(suffix="runners")
    await apply_runner_migrations(database)
    return database


def record():
    return RunnerRecord.from_after(
        {
            "v": 1,
            "runner_id": mint_runner_id(),
            "label": "Backup runner",
            "allowed_jobs": ["nightly-backup"],
        }
    )


def keys():
    return (
        did_from_public_key(bytes(SigningKey.generate().verify_key)),
        encode_base64url(X25519PrivateKey.generate().public_key().public_bytes_raw()),
    )


async def setup_runner(db):
    r = record()
    async with db.transaction() as tx:
        code = await create_runner(tx, "install-one", "team:acme.test", r, now=NOW)
    return r, code


async def redeem(db, code, *, now=NOW, pair=None):
    signing, encryption = pair or keys()
    async with db.transaction() as tx:
        return await register_runner(
            tx, code=code, signing_key=signing, encryption_key=encryption, clock=lambda: now
        )


async def test_code_is_hash_only_single_use_and_keys_are_bound(db):
    r, code = await setup_runner(db)
    row = await db.fetch_one(
        "SELECT code_hash FROM {{tables.runners}} WHERE runner_id=$1", r.runner_id
    )
    assert bytes(row["code_hash"]) == hashlib.sha256(code.encode()).digest()
    pair = keys()
    assert (await redeem(db, code, pair=pair)).runner_id == r.runner_id
    async with db.transaction() as tx:
        stored = await active_runner(tx, r.runner_id)
        assert (stored.signing_key, stored.encryption_key) == pair
    with pytest.raises(RunnerRefused) as refused:
        await redeem(db, code)
    assert refused.value.code == "registration_code_invalid"


async def test_registration_code_expires_at_ten_minutes_but_not_before(db):
    _, code = await setup_runner(db)
    with pytest.raises(RunnerRefused) as refused:
        await redeem(db, code, now=NOW + timedelta(minutes=10))
    assert refused.value.code == "registration_code_invalid"
    await redeem(db, code, now=NOW + timedelta(minutes=10, microseconds=-1))


async def test_concurrent_registration_has_one_winner(db):
    _, code = await setup_runner(db)
    result = await asyncio.gather(*(redeem(db, code) for _ in range(3)), return_exceptions=True)
    assert sum(not isinstance(x, Exception) for x in result) == 1
    assert all(
        x.code == "registration_code_invalid" for x in result if isinstance(x, RunnerRefused)
    )


async def test_invalid_encryption_key_leaves_code_usable(db):
    _, code = await setup_runner(db)
    signing, _ = keys()
    with pytest.raises(RunnerRefused) as refused:
        await redeem(db, code, pair=(signing, encode_base64url(bytes(32))))
    assert refused.value.code == "runner_keys_invalid"
    await redeem(db, code)


async def test_deregistration_invalidates_key_and_unused_code_with_installation_scope(db):
    r, code = await setup_runner(db)
    await redeem(db, code)
    async with db.transaction() as tx:
        assert not await deregister_runner(tx, "install-two", r.runner_id, now=NOW)
        assert await active_runner(tx, r.runner_id) is not None
        assert await deregister_runner(tx, "install-one", r.runner_id, now=NOW)
        assert await active_runner(tx, r.runner_id) is None
    other, unused_code = await setup_runner(db)
    async with db.transaction() as tx:
        await deregister_runner(tx, "install-one", other.runner_id, now=NOW)
    with pytest.raises(RunnerRefused):
        await redeem(db, unused_code)


async def test_rotation_invalidates_old_keys_and_code_then_binds_new_keys(db):
    from aweb_secrets.runners import replace_runner

    r, code = await setup_runner(db)
    await redeem(db, code)
    async with db.transaction() as tx:
        new_code = await replace_runner(tx, "install-one", "team:acme.test", r, now=NOW)
        assert await active_runner(tx, r.runner_id) is None
    with pytest.raises(RunnerRefused):
        await redeem(db, code)
    new_keys = keys()
    assert (await redeem(db, new_code, pair=new_keys)).signing_key == new_keys[0]


async def test_runner_effect_and_nonce_commit_or_rollback_together(db):
    import hashlib
    import secrets

    from aweb_naapp.nonces import apply_nonce_migrations

    from aweb_secrets.runner_protocol import canonical, format_time
    from aweb_secrets.runners import authenticate_in

    await apply_nonce_migrations(db)
    r, code = await setup_runner(db)
    key = SigningKey.generate()
    pair = (did_from_public_key(bytes(key.verify_key)), keys()[1])
    await redeem(db, code, pair=pair)
    payload = {
        "v": 1,
        "type": "aweb.secrets.runner-request",
        "origin": "https://secrets.example",
        "runner_id": r.runner_id,
        "kid": pair[0],
        "method": "POST",
        "path": "/runner/v1/claim",
        "body_sha256": hashlib.sha256(b"{}").hexdigest(),
        "timestamp": format_time(NOW),
        "nonce": encode_base64url(secrets.token_bytes(16)),
    }
    raw = canonical(payload)
    header = (
        encode_base64url(raw)
        + "."
        + encode_base64url(key.sign(b"aweb.secrets.runner-request/1\n" + raw).signature)
    )

    async def verify(tx):
        return await authenticate_in(
            tx,
            installation_id="install-one",
            header=header,
            origin=payload["origin"],
            method="POST",
            path=payload["path"],
            body=b"{}",
            clock=lambda: NOW,
        )

    with pytest.raises(RuntimeError):
        async with db.transaction() as tx:
            await verify(tx)
            raise RuntimeError("failed effect")
    async with db.transaction() as tx:
        assert (await verify(tx)).runner_id == r.runner_id
    with pytest.raises(RunnerRefused) as refused:
        async with db.transaction() as tx:
            await verify(tx)
    assert refused.value.code == "runner_request_replayed"


async def test_seal_credential_uses_current_runner_key_and_dispatch_context(db):
    import secrets

    from aweb_naapp.crypto import open_sealed
    from aweb_naapp.hooks.strictjson import decode_base64url
    from cryptography.exceptions import InvalidTag

    from aweb_secrets.runners import seal_credential

    r, code = await setup_runner(db)
    private = X25519PrivateKey.generate()
    pair = (keys()[0], encode_base64url(private.public_key().public_bytes_raw()))
    await redeem(db, code, pair=pair)
    value = secrets.token_bytes(48)
    dispatch_id = "dsp_" + secrets.token_urlsafe(16)
    async with db.transaction() as tx:
        sealed = await seal_credential(
            tx,
            installation_id="install-one",
            runner_id=r.runner_id,
            dispatch_id=dispatch_id,
            value=value,
        )
    raw = decode_base64url(sealed, "sealed")
    assert open_sealed(private.private_bytes_raw(), raw, info=dispatch_id.encode()) == value
    with pytest.raises(InvalidTag):
        open_sealed(private.private_bytes_raw(), raw, info=b"another dispatch")
    async with db.transaction() as tx:
        await deregister_runner(tx, "install-one", r.runner_id, now=NOW)
    with pytest.raises(RunnerRefused) as refused:
        async with db.transaction() as tx:
            await seal_credential(
                tx,
                installation_id="install-one",
                runner_id=r.runner_id,
                dispatch_id=dispatch_id,
                value=value,
            )
    assert refused.value.code == "runner_unknown"


def test_runner_change_shape_binds_ref_and_refuses_fields_outside_record():
    from aweb_secrets.change import ChangeRefused, validate_change
    from tests.test_change_records import _change

    r = record()
    item = {"kind": "runner", "op": "create", "ref": r.runner_id, "after": dict(r.after)}
    draft = _change(item)
    validate_change(draft)
    draft["changes"][0]["ref"] = mint_runner_id()
    with pytest.raises(ChangeRefused):
        validate_change(draft)
