"""App-local runners and hashed one-use registration codes (§9.2).

Record creation/updates are internal writers called by the passkey-confirmed
change-set path. Their random code is returned only to the console; neither
the record nor an agent tool carries it. Public registration exchanges the
code for binding public keys and clears the hash in the same transaction.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from aweb_naapp.hooks.strictjson import Refused as EncodingRefused
from aweb_naapp.hooks.strictjson import decode_base64url
from awid.did import public_key_from_did
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager, TransactionManager

from aweb_secrets.policy import IDENTIFIER
from aweb_secrets.runner_protocol import RUNNER_ID, RunnerRefused, canonical

FIELDS = frozenset({"v", "runner_id", "label", "allowed_jobs"})


def mint_runner_id() -> str:
    return "rnr_" + secrets.token_urlsafe(16)


@dataclass(frozen=True)
class RunnerRecord:
    runner_id: str
    after: Mapping[str, Any]

    @classmethod
    def from_after(cls, after: Mapping[str, Any]) -> RunnerRecord:
        try:
            canonical(dict(after))
            if set(after) != FIELDS or type(after["v"]) is not int or after["v"] != 1:
                raise ValueError("shape")
            if not isinstance(after["runner_id"], str) or not RUNNER_ID.fullmatch(
                after["runner_id"]
            ):
                raise ValueError("id")
            if not isinstance(after["label"], str) or not 1 <= len(after["label"]) <= 256:
                raise ValueError("label")
            jobs = after["allowed_jobs"]
            if not isinstance(jobs, list) or not all(
                isinstance(j, str) and IDENTIFIER.fullmatch(j) for j in jobs
            ):
                raise ValueError("jobs")
            if jobs != sorted(set(jobs)):
                raise ValueError("jobs order")
        except (ValueError, TypeError, KeyError):
            raise RunnerRefused("runner_invalid") from None
        return cls(after["runner_id"], json.loads(canonical(dict(after))))


@dataclass(frozen=True)
class RegisteredRunner:
    record: RunnerRecord
    installation_id: str
    team_id: str
    signing_key: str
    encryption_key: str

    @property
    def runner_id(self) -> str:
        return self.record.runner_id


async def apply_runner_migrations(db: AsyncDatabaseManager) -> None:
    await AsyncMigrationManager(
        db,
        migrations_path=str(Path(__file__).parent / "runner_migrations"),
        module_name="aweb_secrets_runners",
    ).apply_pending_migrations()


async def create_runner(
    tx: TransactionManager,
    installation_id: str,
    team_id: str,
    record: RunnerRecord,
    *,
    now: datetime,
) -> str:
    """Store a passkey-confirmed runner; return its console-only registration code."""
    code = secrets.token_urlsafe(32)
    await tx.execute(
        "INSERT INTO {{tables.runners}} "
        "(runner_id, installation_id, team_id, record, code_hash, code_expires_at) "
        "VALUES ($1, $2, $3, $4, $5, $6)",
        record.runner_id,
        installation_id,
        team_id,
        json.dumps(dict(record.after)),
        hashlib.sha256(code.encode()).digest(),
        now + timedelta(minutes=10),
    )
    return code


async def replace_runner(
    tx: TransactionManager,
    installation_id: str,
    team_id: str,
    record: RunnerRecord,
    *,
    now: datetime,
) -> str:
    """Apply owner-confirmed edits/rotation, clearing old keys and issuing one new code."""
    code = secrets.token_urlsafe(32)
    row = await tx.fetch_value(
        "UPDATE {{tables.runners}} SET record=$4, signing_key=NULL, encryption_key=NULL, "
        "code_hash=$5, code_expires_at=$6, deregistered_at=NULL "
        "WHERE runner_id=$1 AND installation_id=$2 AND team_id=$3 RETURNING runner_id",
        record.runner_id,
        installation_id,
        team_id,
        json.dumps(dict(record.after)),
        hashlib.sha256(code.encode()).digest(),
        now + timedelta(minutes=10),
    )
    if row is None:
        raise RunnerRefused("runner_unknown")
    return code


async def register_runner(
    tx: TransactionManager,
    *,
    code: str,
    signing_key: str,
    encryption_key: str,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> RegisteredRunner:
    try:
        if not isinstance(signing_key, str) or not isinstance(encryption_key, str):
            raise ValueError("public keys must be strings")
        public_key_from_did(signing_key)
        key = decode_base64url(encryption_key, "encryption key")
        # Parsing a 32-byte key alone admits low-order keys. A real exchange
        # refuses them before a registration code can be consumed.
        X25519PrivateKey.generate().exchange(X25519PublicKey.from_public_bytes(key))
    except (ValueError, TypeError, EncodingRefused):
        raise RunnerRefused("runner_keys_invalid") from None
    try:
        if (
            not isinstance(code, str)
            or len(code) != 43
            or len(decode_base64url(code, "registration code")) != 32
        ):
            raise ValueError("registration code format")
    except (ValueError, EncodingRefused):
        raise RunnerRefused("registration_code_invalid") from None
    row = await tx.fetch_one(
        "SELECT * FROM {{tables.runners}} WHERE code_hash=$1 FOR UPDATE",
        hashlib.sha256(code.encode()).digest(),
    )
    if row is None or row["deregistered_at"] is not None or clock() >= row["code_expires_at"]:
        raise RunnerRefused("registration_code_invalid")
    await tx.execute(
        "UPDATE {{tables.runners}} SET signing_key=$2, encryption_key=$3, "
        "code_hash=NULL, code_expires_at=NULL WHERE runner_id=$1",
        row["runner_id"],
        signing_key,
        encryption_key,
    )
    return RegisteredRunner(
        RunnerRecord.from_after(json.loads(row["record"])),
        row["installation_id"],
        row["team_id"],
        signing_key,
        encryption_key,
    )


async def active_runner(tx: TransactionManager, runner_id: str) -> RegisteredRunner | None:
    """Hold the key against rotation/deregistration until the request's effect commits."""
    row = await tx.fetch_one(
        "SELECT * FROM {{tables.runners}} WHERE runner_id=$1 "
        "AND deregistered_at IS NULL AND signing_key IS NOT NULL FOR SHARE",
        runner_id,
    )
    if row is None:
        return None
    return RegisteredRunner(
        RunnerRecord.from_after(json.loads(row["record"])),
        row["installation_id"],
        row["team_id"],
        row["signing_key"],
        row["encryption_key"],
    )


async def deregister_runner(
    tx: TransactionManager,
    installation_id: str,
    runner_id: str,
    *,
    now: datetime,
) -> bool:
    """Invalidate keys and unused code in S14's fenced transaction.

    S14 then cancels/notifies assignments through S13's sole dispatch/outbox
    path in this same transaction. No audit availability gates containment.
    """
    row = await tx.fetch_value(
        "UPDATE {{tables.runners}} SET deregistered_at=$3, signing_key=NULL, "
        "encryption_key=NULL, code_hash=NULL, code_expires_at=NULL "
        "WHERE runner_id=$1 AND installation_id=$2 AND deregistered_at IS NULL RETURNING runner_id",
        runner_id,
        installation_id,
        now,
    )
    return row is not None


async def runner_scope(
    db: AsyncDatabaseManager,
    runner_id: str,
) -> tuple[str, str] | None:
    """Unlocked directory lookup for the caller's installation refresh/fence.

    This is routing information, never authority. After fencing that
    installation, authenticate_in re-reads and holds the active runner.
    """
    row = await db.fetch_one(
        "SELECT installation_id, team_id FROM {{tables.runners}} WHERE runner_id=$1",
        runner_id,
    )
    return None if row is None else (row["installation_id"], row["team_id"])


async def authenticate_in(
    tx: TransactionManager,
    *,
    installation_id: str,
    header: str,
    origin: str,
    method: str,
    path: str,
    body: bytes,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> RegisteredRunner:
    """Verify/consume in the caller's fenced effect transaction, even for no-op polls.

    The caller takes the installation fence before calling. It must commit
    only after its effect succeeds; a refusal rolls back the whole transaction.
    """
    from aweb_secrets.runner_protocol import consume_request, parse_request, verify_request

    parsed = parse_request(header)
    runner = await active_runner(tx, parsed.runner_id)
    registered = (
        runner.signing_key if runner and runner.installation_id == installation_id else None
    )
    verified = verify_request(
        parsed,
        registered_kid=registered,
        origin=origin,
        method=method,
        path=path,
        body=body,
        now=clock(),
    )
    await consume_request(tx, verified, clock=clock)
    assert runner is not None
    return runner


async def seal_credential(
    tx: TransactionManager,
    *,
    installation_id: str,
    runner_id: str,
    dispatch_id: str,
    value: bytes,
) -> str:
    """Seal to the CURRENT registered encryption key under the claim lock.

    S13 owns opening custody; this function only seals the material it hands
    over. The caller cannot select an ad hoc recipient key or HPKE context.
    """
    from aweb_naapp.crypto import seal
    from aweb_naapp.hooks.strictjson import encode_base64url

    from aweb_secrets.runner_protocol import DISPATCH_ID

    if not DISPATCH_ID.fullmatch(dispatch_id):
        raise ValueError("invalid dispatch id")
    runner = await active_runner(tx, runner_id)
    if runner is None or runner.installation_id != installation_id:
        raise RunnerRefused("runner_unknown")
    return encode_base64url(
        seal(
            decode_base64url(runner.encryption_key, "encryption key"),
            value,
            info=dispatch_id.encode("utf-8"),
        )
    )
