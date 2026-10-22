"""Initial authenticated inbound commitments, persisted once with a logical use.

This is audit metadata, separate from S8's idempotency hash and B2's approval
hash. No inbound body or parameter value is stored here. The shared K4 helper
owns all framing, purpose domains, HMACs and key loading.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from aweb_naapp.hooks.commitment import (
    CommitmentContext,
    CommitmentError,
    CommitmentKey,
    Purpose,
    RequestBytes,
    load_commitment_key,
)
from aweb_naapp.runtime.approvals import RequestNotCanonical, canonical_request
from aweb_naapp.runtime.approvals.request import DOMAIN_PREFIX
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager
from pgdbm.core import TransactionManager

from aweb_secrets.admission import Admission


async def apply_use_context_migrations(db: AsyncDatabaseManager) -> None:
    """After app records and shared dispatch migrations, before serving uses."""
    await AsyncMigrationManager(
        db,
        migrations_path=str(Path(__file__).parent / "dispatch_migrations"),
        module_name="aweb_secrets_dispatch",
    ).apply_pending_migrations()


@dataclass(frozen=True)
class UseCommitments:
    context: CommitmentContext
    request_mac: str | None
    params_mac: str | None


@dataclass(frozen=True)
class StoredUseContext:
    intent_id: str
    dispatch_id: UUID
    commitments: UseCommitments
    dispatch_started_at: datetime | None


class UseCommitter:
    """One producer's independently provisioned request and parameter keys.

    Rotation replaces the configured key files and destroys old key material;
    existing uses/outbox bytes keep their persisted commitments. Provision
    independent random keys, never signing or response-commitment keys.
    """

    def __init__(self, request_key: CommitmentKey, params_key: CommitmentKey) -> None:
        if (
            request_key.purpose is not Purpose.SECRET_REQUEST
            or params_key.purpose is not Purpose.SECRET_PARAMS
        ):
            raise CommitmentError("secret use commitments require their dedicated key purposes")
        self._request_key = request_key
        self._params_key = params_key

    @classmethod
    def from_files(cls, request_file: Path, params_file: Path) -> UseCommitter:
        if request_file.samefile(params_file):
            raise CommitmentError("secret request and parameter keys require separate files")
        return cls(
            load_commitment_key(Purpose.SECRET_REQUEST, request_file),
            load_commitment_key(Purpose.SECRET_PARAMS, params_file),
        )

    def commit(
        self,
        context: CommitmentContext,
        request: RequestBytes | None,
        *,
        parameters: Mapping[str, Any] | None,
    ) -> UseCommitments:
        """Commit complete inbound bytes and caller-validated typed parameters.

        Open requests pass parameters=None. A refusal with missing complete
        bytes or uncanonical parameters omits only that commitment, never its
        required audit event. This function grants no admission authority.
        """
        canonical_params = None
        if parameters is not None:
            try:
                # Reuse B2's integer-only UTF-8 JSON codec, without its domain
                # prefix or policy/request wrapper. K4 supplies the audit domain.
                canonical_params = canonical_request(parameters)[len(DOMAIN_PREFIX) :]
            except (RequestNotCanonical, UnicodeError, RecursionError):
                pass
        return UseCommitments(
            context,
            None if request is None else self._request_key.request(context, request),
            self._params_key.params(context, canonical_params),
        )


def _stored(row: Mapping[str, Any]) -> StoredUseContext:
    return StoredUseContext(
        row["intent_id"],
        row["dispatch_id"],
        UseCommitments(
            CommitmentContext(
                row["app_id"],
                row["team_id"],
                row["installation_id"],
                row["install_generation"],
                row["tool"],
            ),
            row["request_mac"],
            row["params_mac"],
        ),
        row["dispatch_started_at"],
    )


async def store_use_context(
    tx: TransactionManager,
    *,
    admission: Admission,
    dispatch_id: UUID,
    commitments: UseCommitments,
) -> StoredUseContext:
    """Insert before S3.create, in the same tx; replay never overwrites MACs.

    S8 has already checked idempotency. A new conflicting request uses its own
    attempted commitments only for its refusal, never replacing this row.
    """
    context, installation = commitments.context, admission.installation
    if (context.app_id, context.team_id, context.installation_id, context.generation) != (
        installation.app_id,
        installation.team_id,
        installation.installation_id,
        installation.generation,
    ) or commitments.request_mac is None:
        raise ValueError("an admitted use requires its authoritative request commitment")
    await tx.execute(
        """
        INSERT INTO {{tables.use_contexts}} (
            intent_id, dispatch_id, app_id, installation_id, team_id, install_generation,
            tool, request_mac, params_mac
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (intent_id) DO NOTHING
        """,
        admission.intent_id,
        dispatch_id,
        context.app_id,
        context.installation_id,
        context.team_id,
        context.generation,
        context.tool,
        commitments.request_mac,
        commitments.params_mac,
    )
    row = await tx.fetch_one(
        "SELECT * FROM {{tables.use_contexts}} WHERE intent_id=$1 AND installation_id=$2 AND team_id=$3",
        admission.intent_id,
        context.installation_id,
        context.team_id,
    )
    if row is None or row["dispatch_id"] != dispatch_id:
        raise ValueError("a logical use keeps its first dispatch binding")
    return _stored(row)


async def use_context(
    tx: TransactionManager,
    dispatch_id: UUID,
) -> StoredUseContext:
    """For internal dispatch transitions after their authority fence, not lookup admission."""
    row = await tx.fetch_one(
        "SELECT * FROM {{tables.use_contexts}} WHERE dispatch_id=$1", dispatch_id
    )
    if row is None:
        raise LookupError("dispatch has no admitted use context")
    return _stored(row)


async def note_dispatch_started(
    tx: TransactionManager,
    dispatch_id: UUID,
    occurred_at: datetime,
) -> StoredUseContext:
    """S3's dispatching callback records its first database transition timestamp.

    A retry or reconciliation never restarts the relative expiry clock.
    """
    row = await tx.fetch_one(
        "UPDATE {{tables.use_contexts}} SET dispatch_started_at=COALESCE(dispatch_started_at,$2)"
        " WHERE dispatch_id=$1 RETURNING *",
        dispatch_id,
        occurred_at,
    )
    if row is None:
        raise LookupError("dispatch has no admitted use context")
    return _stored(row)
