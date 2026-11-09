"""What secrets tells the shared credential recorder: the catalog role of an
owner or approver scope, and how owner approvals of change sets govern
credentials."""

from collections.abc import Awaitable, Callable

from aweb_naapp.runtime.approvals import Approval
from aweb_naapp.runtime.installation import AdmittedInstallation
from pgdbm.core import TransactionManager

from aweb_secrets.change_sets import POLICY_PREFIX
from aweb_secrets.owners import OWNER_ROLE

# The module ID secrets has always applied the shared credential migrations under.
CREDENTIAL_AUDIT_MIGRATIONS = "aweb_secrets_credential_audit"


async def credential_role(
    tx: TransactionManager, *, scope: str, admitted: AdmittedInstallation
) -> str | None:
    """``secrets.owner`` for an owner scope of this installation,
    ``secrets.approver.<ref>`` for an approver scope, otherwise None."""
    if await _is_owner_scope(tx, scope, admitted):
        return OWNER_ROLE
    ref = await tx.fetch_value(
        "SELECT approver_ref FROM {{tables.approvers}} WHERE scope=$1 AND installation_id=$2 AND team_id=$3",
        scope,
        admitted.installation_id,
        admitted.team_id,
    )
    return None if ref is None else "secrets.approver." + ref


class ChangeApprovals:
    """Owner approvals of secrets change sets, read through the plain B2
    reader on the original transaction."""

    policy_prefix = POLICY_PREFIX

    def __init__(
        self, approval: Callable[[TransactionManager, str], Awaitable[Approval | None]]
    ) -> None:
        self._approval = approval

    async def approval(self, tx: TransactionManager, approval_id: str) -> Approval | None:
        return await self._approval(tx, approval_id)

    async def is_authority_scope(
        self, tx: TransactionManager, *, scope: str, admitted: AdmittedInstallation
    ) -> bool:
        return await _is_owner_scope(tx, scope, admitted)


async def _is_owner_scope(
    tx: TransactionManager, scope: str, admitted: AdmittedInstallation
) -> bool:
    return bool(
        await tx.fetch_value(
            "SELECT 1 FROM {{tables.owner_principals}} WHERE scope=$1 AND installation_id=$2 AND team_id=$3",
            scope,
            admitted.installation_id,
            admitted.team_id,
        )
    )
