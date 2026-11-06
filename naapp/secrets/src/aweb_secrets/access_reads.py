"""Internal confirmed-access metadata, never a request admission or send permit.

The owner console supplies selected-agent membership and this reader in ONE
REPEATABLE READ transaction, after its existing authority holds. It keeps those
holds and final live checks; a snapshot read cannot reauthorize a session.
The revision labels configuration only, not role membership. Refresh after
narrowing uses a new transaction. Raw records/templates are internal inputs to
the console's metadata projection and the app's shared coverage predicates.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass

from aweb_naapp.runtime.installation import AdmittedInstallation
from pgdbm.core import TransactionManager

from aweb_secrets import derived_lineage, jobs, records
from aweb_secrets.grant import GrantRecord
from aweb_secrets.operation import OperationTemplate
from aweb_secrets.policy import Policy
from aweb_secrets.revisions import config_revision
from aweb_secrets.run_plan import RunPlanRefused
from aweb_secrets.run_selection import discover_sources
from aweb_secrets.secret import SecretRecord


@dataclass(frozen=True)
class ConfiguredSubjects:
    direct_principals: tuple[str, ...]
    roles: tuple[str, ...]


@dataclass(frozen=True)
class OperationAccessPin:
    operation_id: str
    granted_digest: str
    current: OperationTemplate | None


@dataclass(frozen=True)
class JobAccessPin:
    job_id: str
    granted_digest: str
    current: jobs.JobDefinition | None
    source_ids: tuple[str, ...] | None
    source_refusal: str | None


@dataclass(frozen=True)
class GrantAccessCandidate:
    secret: records.StoredSecret
    grant: GrantRecord
    policy: Policy | None
    operations: tuple[OperationAccessPin, ...]
    jobs: tuple[JobAccessPin, ...]


@dataclass(frozen=True)
class ConfirmedAccess:
    revision: int
    candidates: tuple[GrantAccessCandidate, ...]


async def configured_subjects(
    tx: TransactionManager,
    installation: AdmittedInstallation,
    *,
    secret_id: str | None = None,
) -> ConfiguredSubjects:
    """Enumerate configured subjects, not the team roster or an authority set.

    The caller expands granted roles through the shared membership reader and
    passes each selected agent's actual roles to :func:`confirmed_access`.
    """
    rows = await tx.fetch_all(
        """
        SELECT DISTINCT g.subject_principal, g.subject_role FROM {{tables.grants}} g
        JOIN {{tables.secrets}} s USING (installation_id, team_id, secret_id)
        WHERE g.installation_id=$1 AND g.team_id=$2 AND g.revoked_at IS NULL
          AND ($3::text IS NULL OR g.secret_id=$3)
        """,
        installation.installation_id,
        installation.team_id,
        secret_id,
    )
    return ConfiguredSubjects(
        direct_principals=tuple(
            sorted({r["subject_principal"] for r in rows if r["subject_principal"] is not None})
        ),
        roles=tuple(sorted({r["subject_role"] for r in rows if r["subject_role"] is not None})),
    )


async def _job_pin(
    tx: TransactionManager, installation: AdmittedInstallation, job_id: str, digest: str
) -> JobAccessPin:
    current = await jobs.current_job(tx, installation.installation_id, job_id, lock=False)
    sources = None
    refusal = None
    if current is not None:
        try:
            sources = tuple(await discover_sources(tx, installation, current, selected_ref=None))
        except RunPlanRefused as error:
            refusal = error.code
    return JobAccessPin(job_id, digest, current, sources, refusal)


async def confirmed_access(
    tx: TransactionManager,
    installation: AdmittedInstallation,
    *,
    principal_did: str,
    roles: Sequence[str],
    secret_id: str | None = None,
) -> ConfirmedAccess:
    """Read confirmed candidates and CURRENT pins in the caller's snapshot.

    Selection is the SAME active_grants selector used by admission. A grant's
    actual subject preserves direct/role provenance; missing CURRENT/policy
    remains explicit. Fixed slot sources describe requirements, never authority
    for an entire run. No custody value, draft, rate bucket or intent is read.
    """
    revision = await config_revision(tx, installation.installation_id)
    secrets = await tx.fetch_all(
        "SELECT record,state,active_version FROM {{tables.secrets}} "
        "WHERE installation_id=$1 AND team_id=$2 AND ($3::text IS NULL OR secret_id=$3) "
        "ORDER BY secret_id",
        installation.installation_id,
        installation.team_id,
        secret_id,
    )
    candidates = []
    for row in secrets:
        secret = records.StoredSecret(
            SecretRecord.from_after(json.loads(row["record"])), row["state"], row["active_version"]
        )
        grants = await records.active_grants(
            tx,
            installation.installation_id,
            secret.record.secret_id,
            principal_did=principal_did,
            roles=roles,
            lock=False,
        )
        for grant in grants:
            policy = await records.policy(tx, installation.installation_id, grant.policy_digest)
            operations = []
            for operation_id, digest in grant.operations:
                current = await derived_lineage.current_operation_snapshot(
                    tx,
                    installation.installation_id,
                    installation.team_id,
                    secret.record.secret_id,
                    operation_id,
                )
                operations.append(OperationAccessPin(operation_id, digest, current))
            job_pins = []
            for job_id, digest in grant.jobs:
                job_pins.append(await _job_pin(tx, installation, job_id, digest))
            candidates.append(
                GrantAccessCandidate(secret, grant, policy, tuple(operations), tuple(job_pins))
            )
    return ConfirmedAccess(revision, tuple(candidates))
