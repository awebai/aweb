"""Describing, disabling and destroying sealed secrets, and custody health, on real PostgreSQL."""

from __future__ import annotations

import logging
import socket
from collections.abc import AsyncIterator

import boto3
import pytest
from botocore import UNSIGNED
from botocore.config import Config
from pgdbm import AsyncDatabaseManager

from aweb_secrets.custody import (
    AwsKmsProvider,
    Custody,
    CustodyUnavailable,
    LocalKeyFileProvider,
    SealContext,
    apply_custody_migrations,
)
from tests.custody.conftest import initial_record, record_tables, value_bytes

INSTALLATION = "installation-1"
TEAM = "team-1"


@pytest.fixture
async def db(test_db_factory) -> AsyncIterator[AsyncDatabaseManager]:
    database = await test_db_factory.create_db(suffix="secrets_custody_lifecycle")
    await record_tables(database)
    await apply_custody_migrations(database)
    yield database


@pytest.fixture
def custody(db: AsyncDatabaseManager, provider: LocalKeyFileProvider) -> Custody:
    return Custody(provider, db)


async def _ingest(
    custody: Custody, db: AsyncDatabaseManager, secret_id: str, value: bytes, team_id: str = TEAM
) -> int:
    async with db.transaction() as tx:
        return await custody.sealer.ingest(
            tx,
            **_secret(secret_id, team_id),
            value=value_bytes(value),
            initial=initial_record(secret_id),
        )


def _context(secret_id: str, version: int, team_id: str = TEAM) -> SealContext:
    return SealContext(
        installation_id=INSTALLATION, team_id=team_id, secret_id=secret_id, version=version
    )


def _secret(secret_id: str, team_id: str = TEAM) -> dict[str, str]:
    return {"installation_id": INSTALLATION, "team_id": team_id, "secret_id": secret_id}


async def test_describe_names_the_latest_version_and_never_the_value(
    custody: Custody, db: AsyncDatabaseManager, canary: bytes
) -> None:
    await _ingest(custody, db, "sec_secret1", b"first")
    await _ingest(custody, db, "sec_secret1", canary)
    description = await custody.describe(**_secret("sec_secret1"))
    assert description.version == 2
    assert description.state == "active"
    assert canary.decode() not in repr(description)


async def test_describe_of_an_unknown_secret_is_none(custody: Custody) -> None:
    assert await custody.describe(**_secret("sec_secret1")) is None


async def test_a_disabled_secret_does_not_open(
    custody: Custody, db: AsyncDatabaseManager, canary: bytes
) -> None:
    version = await _ingest(custody, db, "sec_secret1", canary)
    async with db.transaction() as tx:
        await custody.disable(tx, **_secret("sec_secret1"))
    with pytest.raises(CustodyUnavailable):
        await custody.opener.open(_context("sec_secret1", version))
    description = await custody.describe(**_secret("sec_secret1"))
    assert description is not None and description.state == "disabled"


async def test_disabling_one_secret_leaves_another_usable(
    custody: Custody, db: AsyncDatabaseManager, canary: bytes
) -> None:
    await _ingest(custody, db, "sec_secret1", b"a")
    version = await _ingest(custody, db, "sec_secret2", canary)
    async with db.transaction() as tx:
        await custody.disable(tx, **_secret("sec_secret1"))
    assert (await custody.opener.open(_context("sec_secret2", version))).reveal() == value_bytes(
        canary
    )


async def test_a_disabled_secret_takes_no_new_value(
    custody: Custody, db: AsyncDatabaseManager
) -> None:
    await _ingest(custody, db, "sec_secret1", b"a")
    async with db.transaction() as tx:
        await custody.disable(tx, **_secret("sec_secret1"))
    with pytest.raises(CustodyUnavailable):
        await _ingest(custody, db, "sec_secret1", b"b")


async def test_a_destroyed_version_cannot_be_opened(
    custody: Custody, db: AsyncDatabaseManager, canary: bytes
) -> None:
    version = await _ingest(custody, db, "sec_secret1", canary)
    async with db.transaction() as tx:
        await custody.destroy(tx, _context("sec_secret1", version))
    with pytest.raises(CustodyUnavailable):
        await custody.opener.open(_context("sec_secret1", version))


async def test_destroying_a_version_keeps_the_others(
    custody: Custody, db: AsyncDatabaseManager, canary: bytes
) -> None:
    first = await _ingest(custody, db, "sec_secret1", b"old")
    second = await _ingest(custody, db, "sec_secret1", canary)
    async with db.transaction() as tx:
        await custody.destroy(tx, _context("sec_secret1", first))
    assert (await custody.opener.open(_context("sec_secret1", second))).reveal() == value_bytes(
        canary
    )


async def test_a_destroyed_version_number_is_never_reused(
    custody: Custody, db: AsyncDatabaseManager
) -> None:
    first = await _ingest(custody, db, "sec_secret1", b"old")
    async with db.transaction() as tx:
        await custody.destroy(tx, _context("sec_secret1", first))
    assert await _ingest(custody, db, "sec_secret1", b"new") == first + 1


async def test_a_replacement_destroys_the_old_version_in_the_same_transaction(
    custody: Custody, db: AsyncDatabaseManager, canary: bytes
) -> None:
    old = await _ingest(custody, db, "sec_secret1", b"old")
    async with db.transaction() as tx:
        new = await custody.sealer.ingest(
            tx,
            installation_id=INSTALLATION,
            team_id=TEAM,
            secret_id="sec_secret1",
            value=value_bytes(canary),
            initial=initial_record("sec_secret1"),
        )
        await custody.destroy(tx, _context("sec_secret1", old))
    with pytest.raises(CustodyUnavailable):
        await custody.opener.open(_context("sec_secret1", old))
    assert (await custody.opener.open(_context("sec_secret1", new))).reveal() == value_bytes(canary)


async def test_the_same_secret_id_under_two_teams_is_independent(
    custody: Custody, db: AsyncDatabaseManager, canary: bytes
) -> None:
    assert await _ingest(custody, db, "sec_secret1", b"team one", team_id="team-1") == 1
    assert await _ingest(custody, db, "sec_secret1", canary, team_id="team-2") == 1
    async with db.transaction() as tx:
        await custody.disable(tx, **_secret("sec_secret1", "team-1"))
        await custody.destroy(tx, _context("sec_secret1", 1, "team-1"))
    opened = await custody.opener.open(_context("sec_secret1", 1, "team-2"))
    assert opened.reveal() == value_bytes(canary)
    described = await custody.describe(**_secret("sec_secret1", "team-2"))
    assert described is not None and (described.version, described.state) == (1, "active")
    assert await _ingest(custody, db, "sec_secret1", b"next", team_id="team-2") == 2


async def test_health_is_ok_with_a_working_key(custody: Custody) -> None:
    assert (await custody.health()).ok


async def test_health_is_degraded_when_kms_is_unreachable(db: AsyncDatabaseManager) -> None:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    client = boto3.client(
        "kms",
        region_name="eu-west-1",
        endpoint_url=f"http://127.0.0.1:{port}",
        config=Config(signature_version=UNSIGNED, retries={"max_attempts": 1}, connect_timeout=1),
    )
    health = await Custody(AwsKmsProvider(key_id="alias/secrets-test", client=client), db).health()
    assert not health.ok
    assert health.reason


async def test_no_path_leaks_the_value_into_logs_output_or_errors(
    custody: Custody,
    db: AsyncDatabaseManager,
    canary: bytes,
    caplog: pytest.LogCaptureFixture,
    capfd: pytest.CaptureFixture[str],
) -> None:
    caplog.set_level(logging.DEBUG)
    errors: list[str] = []
    version = await _ingest(custody, db, "sec_secret1", canary)
    opened = await custody.opener.open(_context("sec_secret1", version))
    assert opened.reveal() == value_bytes(canary)
    logging.getLogger("test").info("opened %s %r", opened, opened)
    for wrong in (_context("sec_secret2", version), _context("sec_secret1", version + 1)):
        with pytest.raises(CustodyUnavailable) as refused:
            await custody.opener.open(wrong)
        errors += [str(refused.value), repr(refused.value)]
    async with db.transaction() as tx:
        await custody.disable(tx, **_secret("sec_secret1"))
    with pytest.raises(CustodyUnavailable) as refused:
        await custody.opener.open(_context("sec_secret1", version))
    errors += [str(refused.value), repr(refused.value)]
    errors.append(repr(await custody.describe(**_secret("sec_secret1"))))
    captured = capfd.readouterr()
    everything = "\n".join([caplog.text, captured.out, captured.err, *errors])
    assert canary.decode() not in everything
