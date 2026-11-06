"""Broker B2 publication authority in the original caller transaction.

App role/forest/grant/coverage holds precede the shared B3 preparation, which
precedes B2. The final read uses those holds and B3's current-approver checker;
it never substitutes login evidence for the original retained APPROVE proof.
Construct one adapter for each publication transaction.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from aweb_naapp.roles import PrincipalKey, has_role, hold_role, principal_key, roles_of
from aweb_naapp.runtime.approvals import Approval
from aweb_naapp.runtime.approvals.dispatch_fence import DispatchAuthorityState
from aweb_naapp.runtime.passkeys import Passkeys
from aweb_naapp.runtime.team_auth import Principal
from pgdbm.core import TransactionManager

from aweb_secrets import derived_lineage
from aweb_secrets.admission import Admission, AdmissionRefused
from aweb_secrets.approvers import approvers_for_secrets
from aweb_secrets.grant import is_secrets_role
from aweb_secrets.owners import OWNER_ROLE, is_owner_scope
from aweb_secrets.use_approvals import _action_policy, use_policy_ref
from aweb_secrets.use_audit import UseAuditUnavailable

if TYPE_CHECKING:
    from aweb_naapp.runtime.passkeys import PreparedCurrentApprovers


class UseDispatchAuthority:
    def __init__(self, *, principal: Principal, admission: Admission, passkeys: Passkeys) -> None:
        self._principal, self._admission, self._passkeys = principal, admission, passkeys
        self._tx: TransactionManager | None = None
        self._approval_ids: tuple[str, ...] = ()
        self._current: PreparedCurrentApprovers | None = None
        self._secret_ids: tuple[str, ...] = ()
        self._owners: dict[str, PrincipalKey] = {}
        self._policy_ref: str | None = None

    async def prepare(self, tx: TransactionManager, approvals: Sequence[Approval]) -> None:
        ids = tuple(sorted(a.approval_id for a in approvals))
        if self._tx is not None:
            if self._tx is not tx or ids != self._approval_ids:
                raise UseAuditUnavailable()
            # B2 repeats this call after consumption. Taking any app/B3
            # preparation lock here would invert the complete-union order.
            return
        if len(approvals) != 1:
            raise UseAuditUnavailable()
        scope = self._admission.installation
        intent = await tx.fetch_one(
            "SELECT i.*,u.approval_id FROM {{tables.intents}} i"
            " JOIN {{tables.use_approvals}} u USING(intent_id,installation_id,team_id)"
            " WHERE i.intent_id=$1 AND i.installation_id=$2 AND i.team_id=$3",
            self._admission.intent_id,
            scope.installation_id,
            scope.team_id,
        )
        key = principal_key(self._principal)
        if (
            intent is None
            or intent["approval_id"] != approvals[0].approval_id
            or intent["principal_did"] != key.principal_did
            or key.team_id != scope.team_id
            or intent["install_generation"] != scope.generation
            or intent["grant_id"] != self._admission.grant_id
            or intent["policy_digest"] != self._admission.policy_digest
        ):
            raise UseAuditUnavailable()
        policy_ref = use_policy_ref(
            scope.installation_id, scope.team_id, intent["grant_id"], intent["policy_digest"]
        )
        approval = approvals[0]
        if approval.policy_ref != policy_ref or approval.requested_by != key.principal_did:
            raise UseAuditUnavailable()

        # Resolve immutable owner mappings before taking the complete sorted
        # role union. Owners need their current secrets.owner assignment.
        owners: dict[str, PrincipalKey] = {}
        decider = approval.decided_by
        if decider is not None and is_owner_scope(decider.scope):
            row = await tx.fetch_one(
                "SELECT principal_did FROM {{tables.owner_principals}}"
                " WHERE scope=$1 AND installation_id=$2 AND team_id=$3",
                decider.scope,
                scope.installation_id,
                scope.team_id,
            )
            if row is not None:
                owners[decider.scope] = PrincipalKey(scope.team_id, row["principal_did"])
        roles = {
            (key.principal_did, role) for role in await roles_of(tx, key) if is_secrets_role(role)
        }
        roles.update((owner.principal_did, OWNER_ROLE) for owner in owners.values())
        held = set()
        for principal_did, role in sorted(roles):
            if await hold_role(tx, PrincipalKey(scope.team_id, principal_did), role):
                held.add((principal_did, role))
        owners = {
            owner_scope: owner
            for owner_scope, owner in owners.items()
            if (owner.principal_did, OWNER_ROLE) in held
        }
        try:
            paths = await derived_lineage.lock_forest(
                tx, scope.installation_id, scope.team_id, [intent["secret_id"]]
            )
            await derived_lineage.lock_forest_grants(
                tx, paths, candidate_grant_ids=[intent["grant_id"]]
            )
        except derived_lineage.LineageRefused as refused:
            raise AdmissionRefused(refused.code) from None
        secret_ids = tuple(node.secret.record.secret_id for node in paths[0])
        await approvers_for_secrets(
            tx,
            installation_id=scope.installation_id,
            team_id=scope.team_id,
            secret_ids=secret_ids,
        )
        # Warm every relation read used by read() before the B2 phase.
        await approvers_for_secrets(
            tx,
            installation_id=scope.installation_id,
            team_id=scope.team_id,
            secret_ids=secret_ids,
            lock=False,
        )
        await _action_policy(tx, policy_ref)
        for owner in owners.values():
            await has_role(tx, owner, OWNER_ROLE)
        current = await self._passkeys.prepare_current_approvers(
            tx, [] if decider is None else [(decider.scope, decider.subject)]
        )
        self._secret_ids = secret_ids
        self._owners, self._policy_ref, self._current = owners, policy_ref, current
        self._approval_ids, self._tx = ids, tx

    async def read(self, tx: TransactionManager, approval: Approval) -> DispatchAuthorityState:
        if (
            self._tx is not tx
            or self._current is None
            or approval.approval_id not in self._approval_ids
            or approval.policy_ref != self._policy_ref
        ):
            raise UseAuditUnavailable()
        policy = await _action_policy(tx, approval.policy_ref)
        decider = approval.decided_by
        current = False
        if decider is not None:
            if is_owner_scope(decider.scope):
                owner = self._owners.get(decider.scope)
                eligible = owner is not None and await has_role(tx, owner, OWNER_ROLE)
            else:
                scope = self._admission.installation
                covering = await approvers_for_secrets(
                    tx,
                    installation_id=scope.installation_id,
                    team_id=scope.team_id,
                    secret_ids=self._secret_ids,
                    lock=False,
                )
                eligible = any(record.scope == decider.scope for record in covering)
            # The shared B3 check samples live time after its last awaited
            # authority read and validates its own original-tx/savepoint guard.
            if eligible:
                current = await self._passkeys.check_current_approver(
                    tx, self._current, scope=decider.scope, subject=decider.subject
                )
        return DispatchAuthorityState(policy=policy, decider_current=current)
