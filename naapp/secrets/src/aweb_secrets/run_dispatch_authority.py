"""Whole-run B3/B2 publication preparation in the original caller transaction.

The existing planner owns current job/source/grant authority. This adapter adds
current deciders, their coverage and one shared B3 whole-pair handle before B2.
Final reads acquire no locks and never substitute LOGIN for retained APPROVE.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from aweb_naapp.roles import PrincipalKey, has_role, hold_role, principal_key, roles_of
from aweb_naapp.runtime.approvals import Approval
from aweb_naapp.runtime.approvals.dispatch_fence import DispatchAuthorityState
from aweb_naapp.runtime.authorization import Grant
from aweb_naapp.runtime.passkeys import Passkeys
from pgdbm.core import TransactionManager

from aweb_secrets.approvers import approvers_for_secrets
from aweb_secrets.containment_state import require_enabled
from aweb_secrets.grant import is_secrets_role
from aweb_secrets.owners import OWNER_ROLE, is_owner_scope
from aweb_secrets.run_approvals import current_run_policy
from aweb_secrets.run_context import OriginalRun
from aweb_secrets.run_plan import PreparedRun
from aweb_secrets.run_planner import RunPlanner
from aweb_secrets.use_audit import UseAuditUnavailable

if TYPE_CHECKING:
    from aweb_naapp.runtime.passkeys import PreparedCurrentApprovers


class RunDispatchAuthority:
    def __init__(
        self, *, original: OriginalRun, planner: RunPlanner, grant: Grant, passkeys: Passkeys
    ) -> None:
        self._original, self._planner, self._grant, self._passkeys = (
            original,
            planner,
            grant,
            passkeys,
        )
        self.installation_fence = planner.fence.for_installation(original.installation)
        self._tx: TransactionManager | None = None
        self._ids: tuple[str, ...] = ()
        self._owners: dict[str, PrincipalKey] = {}
        self._slot_for: dict[str, int] = {}
        self._policy_for: dict[str, str] = {}
        self._current: PreparedCurrentApprovers | None = None
        self._prepared: PreparedRun | None = None

    @property
    def prepared(self) -> PreparedRun:
        if self._prepared is None:
            raise UseAuditUnavailable()
        return self._prepared

    async def prepare(self, tx: TransactionManager, approvals: Sequence[Approval]) -> None:
        ids = tuple(sorted(approval.approval_id for approval in approvals))
        if self._tx is not None:
            if self._tx is not tx or ids != self._ids:
                raise UseAuditUnavailable()
            return
        # Planner.prepare_frozen also admits F6. Hold its UPDATE mode first,
        # rather than taking a SHARE fence and then upgrading it concurrently.
        scope = await self._planner.fence.admit(tx, self._grant)
        if scope != self._original.installation:
            raise UseAuditUnavailable()
        await self.installation_fence.prepare(tx)
        await require_enabled(tx, scope.installation_id, scope.team_id)
        rows = await tx.fetch_all(
            "SELECT ordinal,approval_id,policy_ref FROM {{tables.run_slot_approvals}}"
            " WHERE installation_id=$1 AND team_id=$2 AND run_id=$3 AND approval_id IS NOT NULL"
            " ORDER BY approval_id",
            scope.installation_id,
            scope.team_id,
            self._original.run_id,
        )
        if ids != tuple(row["approval_id"] for row in rows):
            raise UseAuditUnavailable()
        slots = {row["approval_id"]: row["ordinal"] for row in rows}
        policies = {row["approval_id"]: row["policy_ref"] for row in rows}
        for approval in approvals:
            if (
                approval.policy_ref != policies[approval.approval_id]
                or approval.requested_by != principal_key(self._original.principal).principal_did
            ):
                raise UseAuditUnavailable()
        owners = {}
        for approval in approvals:
            decider = approval.decided_by
            if decider is not None and is_owner_scope(decider.scope):
                who = await tx.fetch_value(
                    "SELECT principal_did FROM {{tables.owner_principals}}"
                    " WHERE scope=$1 AND installation_id=$2 AND team_id=$3",
                    decider.scope,
                    scope.installation_id,
                    scope.team_id,
                )
                if who is not None:
                    owners[decider.scope] = PrincipalKey(scope.team_id, who)
        key = principal_key(self._original.principal)
        roles = {
            (key.principal_did, role) for role in await roles_of(tx, key) if is_secrets_role(role)
        }
        roles.update((owner.principal_did, OWNER_ROLE) for owner in owners.values())
        held = set()
        for principal_did, role in sorted(roles):
            if await hold_role(tx, PrincipalKey(scope.team_id, principal_did), role):
                held.add((principal_did, role))
        owners = {
            name: owner
            for name, owner in owners.items()
            if (owner.principal_did, OWNER_ROLE) in held
        }
        prepared = await self._planner.prepare_frozen(
            tx,
            grant=self._grant,
            principal=self._original.principal,
            plan=self._original.plan,
            attestation=self._original.attestation,
        )
        secret_ids = sorted(
            {secret_id for slot in prepared.slots for secret_id in slot.ancestry_ids}
        )
        await approvers_for_secrets(
            tx,
            installation_id=scope.installation_id,
            team_id=scope.team_id,
            secret_ids=secret_ids,
        )
        await approvers_for_secrets(
            tx,
            installation_id=scope.installation_id,
            team_id=scope.team_id,
            secret_ids=secret_ids,
            lock=False,
        )
        for approval in approvals:
            await current_run_policy(tx, approval.policy_ref)
        for owner in owners.values():
            await has_role(tx, owner, OWNER_ROLE)
        current = await self._passkeys.prepare_current_approvers(
            tx,
            [
                (a.decided_by.scope, a.decided_by.subject)
                for a in approvals
                if a.decided_by is not None
            ],
        )
        self._owners, self._slot_for, self._policy_for = owners, slots, policies
        self._current, self._prepared, self._tx, self._ids = current, prepared, tx, ids

    async def read(self, tx: TransactionManager, approval: Approval) -> DispatchAuthorityState:
        if (
            self._tx is not tx
            or self._current is None
            or approval.approval_id not in self._ids
            or approval.policy_ref != self._policy_for[approval.approval_id]
        ):
            raise UseAuditUnavailable()
        policy = await current_run_policy(tx, approval.policy_ref)
        decider = approval.decided_by
        current = False
        if decider is not None:
            if is_owner_scope(decider.scope):
                owner = self._owners.get(decider.scope)
                eligible = owner is not None and await has_role(tx, owner, OWNER_ROLE)
            else:
                scope = self.prepared.installation
                slot = self.prepared.slots[self._slot_for[approval.approval_id]]
                covering = await approvers_for_secrets(
                    tx,
                    installation_id=scope.installation_id,
                    team_id=scope.team_id,
                    secret_ids=slot.ancestry_ids,
                    lock=False,
                )
                eligible = any(record.scope == decider.scope for record in covering)
            if eligible:
                current = await self._passkeys.check_current_approver(
                    tx, self._current, scope=decider.scope, subject=decider.subject
                )
        return DispatchAuthorityState(policy=policy, decider_current=current)
