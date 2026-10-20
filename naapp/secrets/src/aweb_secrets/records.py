"""secrets' records in its database: secrets, policies, grants and grant templates.

Every write runs in the caller's transaction, so a confirmed change set commits
all of its records or none. Every read is scoped by installation, so a record of
one installation is never found from another, and a reinstalled team (a new
installation ID) finds none of the old grants.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass

from pgdbm.core import TransactionManager

from aweb_secrets.grant import GrantRecord, GrantTemplate
from aweb_secrets.policy import Policy
from aweb_secrets.secret import SecretRecord


class RecordMissing(LookupError):
    """The record to change does not exist in this installation."""


@dataclass(frozen=True)
class StoredSecret:
    record: SecretRecord
    state: str
    active_version: int | None


async def create_secret(
    tx: TransactionManager, installation_id: str, team_id: str, record: SecretRecord
) -> None:
    await tx.execute(
        """
        INSERT INTO {{tables.secrets}} (secret_id, installation_id, team_id, ref, record)
        VALUES ($1, $2, $3, $4, $5)
        """,
        record.secret_id,
        installation_id,
        team_id,
        record.ref,
        json.dumps(record.after),
    )


async def update_secret(
    tx: TransactionManager, installation_id: str, team_id: str, record: SecretRecord
) -> None:
    """Replace a secret's record; its state and active version are untouched."""
    updated = await tx.fetch_value(
        """
        UPDATE {{tables.secrets}} SET ref = $4, record = $5, updated_at = NOW()
        WHERE secret_id = $1 AND installation_id = $2 AND team_id = $3
        RETURNING secret_id
        """,
        record.secret_id,
        installation_id,
        team_id,
        record.ref,
        json.dumps(record.after),
    )
    if updated is None:
        raise RecordMissing("no such secret in this installation")


async def secret_by_ref(
    tx: TransactionManager, installation_id: str, team_id: str, ref: str
) -> StoredSecret | None:
    """The secret named ``ref``, locked against change until the transaction ends."""
    row = await tx.fetch_one(
        """
        SELECT record, state, active_version FROM {{tables.secrets}}
        WHERE installation_id = $1 AND team_id = $2 AND ref = $3
        FOR SHARE
        """,
        installation_id,
        team_id,
        ref,
    )
    if row is None:
        return None
    return StoredSecret(
        record=SecretRecord.from_after(json.loads(row["record"])),
        state=row["state"],
        active_version=row["active_version"],
    )


async def set_active_version(
    tx: TransactionManager, installation_id: str, team_id: str, secret_id: str, version: int
) -> None:
    """Point a secret at the custody version the broker opens, when its change set is confirmed."""
    updated = await tx.fetch_value(
        """
        UPDATE {{tables.secrets}} SET active_version = $4, updated_at = NOW()
        WHERE installation_id = $1 AND team_id = $2 AND secret_id = $3
        RETURNING secret_id
        """,
        installation_id,
        team_id,
        secret_id,
        version,
    )
    if updated is None:
        raise RecordMissing("no such secret in this installation")


async def create_policy(tx: TransactionManager, installation_id: str, policy: Policy) -> None:
    """Store ``policy``; storing the same digest again is the same policy and changes nothing."""
    await tx.execute(
        """
        INSERT INTO {{tables.policies}} (installation_id, digest, body) VALUES ($1, $2, $3)
        ON CONFLICT (installation_id, digest) DO NOTHING
        """,
        installation_id,
        policy.digest,
        json.dumps(dict(policy.body)),
    )


async def policy(tx: TransactionManager, installation_id: str, digest: str) -> Policy | None:
    body = await tx.fetch_value(
        "SELECT body FROM {{tables.policies}} WHERE installation_id = $1 AND digest = $2",
        installation_id,
        digest,
    )
    return None if body is None else Policy.from_body(json.loads(body))


async def create_grant(
    tx: TransactionManager, installation_id: str, team_id: str, grant: GrantRecord
) -> None:
    await tx.execute(
        """
        INSERT INTO {{tables.grants}} (
            grant_id, installation_id, team_id, secret_id, subject_principal, subject_role,
            capability, open_request, policy_digest, record
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        """,
        grant.grant_id,
        installation_id,
        team_id,
        grant.secret_id,
        grant.subject_principal,
        grant.subject_role,
        grant.capability,
        grant.open_request,
        grant.policy_digest,
        json.dumps(grant.after),
    )
    for operation_id, digest in grant.operations:
        await tx.execute(
            "INSERT INTO {{tables.grant_operations}} (grant_id, operation_id, digest) VALUES ($1, $2, $3)",
            grant.grant_id,
            operation_id,
            digest,
        )
    for job_id, digest in grant.jobs:
        await tx.execute(
            "INSERT INTO {{tables.grant_jobs}} (grant_id, job_id, digest) VALUES ($1, $2, $3)",
            grant.grant_id,
            job_id,
            digest,
        )


async def revoke_grant(tx: TransactionManager, installation_id: str, grant_id: str) -> None:
    """Revoke a grant at once; revoking a revoked grant changes nothing."""
    await tx.execute(
        """
        UPDATE {{tables.grants}} SET revoked_at = NOW()
        WHERE installation_id = $1 AND grant_id = $2 AND revoked_at IS NULL
        """,
        installation_id,
        grant_id,
    )


async def active_grants(
    tx: TransactionManager,
    installation_id: str,
    secret_id: str,
    *,
    principal_did: str,
    roles: Sequence[str],
) -> list[GrantRecord]:
    """The unrevoked grants on a secret to this principal or to any of its roles.

    The grants are locked until the transaction ends, so a revocation that
    commits first is seen and one that commits later waits.
    """
    rows = await tx.fetch_all(
        """
        SELECT record FROM {{tables.grants}}
        WHERE installation_id = $1 AND secret_id = $2 AND revoked_at IS NULL
          AND (subject_principal = $3 OR subject_role = ANY($4::text[]))
        ORDER BY grant_id
        FOR SHARE
        """,
        installation_id,
        secret_id,
        principal_did,
        list(roles),
    )
    return [GrantRecord.from_after(json.loads(row["record"])) for row in rows]


async def set_grant_template(
    tx: TransactionManager, installation_id: str, template: GrantTemplate
) -> None:
    await tx.execute(
        """
        INSERT INTO {{tables.grant_templates}} (installation_id, grant_template_id, record)
        VALUES ($1, $2, $3)
        ON CONFLICT (installation_id, grant_template_id)
        DO UPDATE SET record = EXCLUDED.record, updated_at = NOW()
        """,
        installation_id,
        template.grant_template_id,
        json.dumps(template.after),
    )


async def grant_template(
    tx: TransactionManager, installation_id: str, grant_template_id: str
) -> GrantTemplate | None:
    record = await tx.fetch_value(
        """
        SELECT record FROM {{tables.grant_templates}}
        WHERE installation_id = $1 AND grant_template_id = $2
        """,
        installation_id,
        grant_template_id,
    )
    return None if record is None else GrantTemplate.from_after(json.loads(record))
