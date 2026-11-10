"""Caller-scoped destruction of passkey material during installation retirement.

Scope discovery and installation/role authority belong to the app. The caller
holds its installation fence and any role locks before this helper. It never
refreshes authority, takes an upstream lock, or treats history as a live grant.
"""

from collections.abc import Collection
from dataclasses import dataclass

from pgdbm.core import TransactionManager

from aweb_naapp.runtime.installation import AdmittedInstallation


@dataclass(frozen=True, kw_only=True)
class RetiringInstallation:
    """Retirement identity, without inventing an obsolete generation or grant."""

    app_id: str
    team_id: str
    installation_id: str


@dataclass(frozen=True)
class RetiredSubjects:
    """Value-free scope and destruction counts for the caller's audit receipt."""

    installation: RetiringInstallation
    destroyed: dict[str, int]


async def retire_subjects(
    tx: TransactionManager,
    *,
    installation: AdmittedInstallation | RetiringInstallation,
    scopes: Collection[str],
) -> RetiredSubjects:
    """Supersede and purge caller-supplied scopes in the caller's transaction.

    Parent FOR UPDATE drains assertion/challenge writers, which take parent
    SHARE before credential or child writes. Subsequent DELETE statements at
    READ COMMITTED see their completed evidence. Marking parents superseded
    also refuses issuers that wait until after this transaction commits.

    The app must collect scopes before deleting its discovery records or roles;
    this function neither discovers ownership nor purges app role assignments.
    """
    identity = RetiringInstallation(
        app_id=installation.app_id,
        team_id=installation.team_id,
        installation_id=installation.installation_id,
    )
    if (
        any(
            not isinstance(value, str) or not value
            for value in (identity.app_id, identity.team_id, identity.installation_id)
        )
        or isinstance(scopes, (str, bytes))
        or any(not isinstance(scope, str) or not scope for scope in scopes)
    ):
        raise ValueError("retirement requires installation identity and exact scopes")
    scope_names = sorted(set(scopes))
    subjects = await tx.fetch_all(
        "SELECT subject FROM {{tables.passkey_approvers}} WHERE scope=ANY($1::text[])"
        " ORDER BY scope,subject FOR UPDATE",
        scope_names,
    )
    subject_ids = [subject["subject"] for subject in subjects]
    await tx.execute(
        "UPDATE {{tables.passkey_approvers}}"
        " SET superseded_at=COALESCE(superseded_at,clock_timestamp())"
        " WHERE subject=ANY($1::text[])",
        subject_ids,
    )
    destroyed = {}
    # Assertions' restricted proof sidecars cascade. Summary/audit and original
    # owner-act authorizations remain separate from live credentials.
    for table in (
        "passkey_assertions",
        "passkey_credentials",
        "passkey_challenges",
        "passkey_enrolments",
        "passkey_contact_proofs",
    ):
        removed = await tx.fetch_all(
            f"DELETE FROM {{{{tables.{table}}}}} WHERE subject=ANY($1::text[]) RETURNING 1",
            subject_ids,
        )
        destroyed[table] = len(removed)
    removed = await tx.fetch_all(
        "DELETE FROM {{tables.console_sessions}} WHERE scope=ANY($1::text[]) RETURNING 1",
        scope_names,
    )
    destroyed["console_sessions"] = len(removed)
    return RetiredSubjects(identity, destroyed)
