"""Owner-only B2 policies and covered requests for manual settlement controls.

This provider adds no owner fallback, passkey ceremony or settlement authority.
The console prepares its current owner/S4/F6 before mint, decide and settle.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict
from datetime import timedelta
from typing import Any
from uuid import UUID

from aweb_naapp.runtime.approvals import ActionPolicy, Approver, Assurance
from pgdbm import AsyncDatabaseManager

from aweb_secrets.owners import OwnerDirectory, owner_scope
from aweb_secrets.reconciliation_types import ReconciliationOriginal, ReconciliationOutcome

CONTROL_TYPE = "aweb.secrets.reconciliation-control"
POLICY_PREFIX = "secrets.reconcile"
POLICY_VERSION = 1
CONTROL_TTL = timedelta(minutes=5)


def reconciliation_request(
    original: ReconciliationOriginal,
    *,
    control_id: UUID,
    outcome: ReconciliationOutcome,
    owner_scope: str,
    owner_subject: str,
) -> dict[str, Any]:
    frozen = asdict(original)
    frozen["dispatch_id"] = str(original.dispatch_id)
    frozen["resources"] = [asdict(resource) for resource in original.resources]
    request = {
        "v": 1,
        "type": CONTROL_TYPE,
        "control_id": str(control_id),
        "original": frozen,
        "outcome": outcome,
        "owner": {"scope": owner_scope, "subject": owner_subject},
    }
    reconciliation_policy_ref(request)
    return request


def reconciliation_policy_ref(request: Mapping[str, Any]) -> str:
    """Closed envelope; association recording rechecks every original field."""
    try:
        if (
            set(request) != {"v", "type", "control_id", "original", "outcome", "owner"}
            or type(request["v"]) is not int
            or request["v"] != 1
            or request["type"] != CONTROL_TYPE
            or request["outcome"] not in {"completed", "failed", "unknown-closed"}
            or str(UUID(request["control_id"])) != request["control_id"]
            or set(request["owner"]) != {"scope", "subject"}
        ):
            raise ValueError
        scope, owner = request["original"]["installation"], request["owner"]
        if set(scope) != {"app_id", "installation_id", "team_id", "generation"}:
            raise ValueError
        if type(scope["generation"]) is not int or scope["generation"] < 1:
            raise ValueError
        parts = (
            scope["app_id"],
            scope["installation_id"],
            scope["team_id"],
            str(scope["generation"]),
            owner["scope"],
            owner["subject"],
        )
        if any(not isinstance(part, str) or not part or "|" in part for part in parts):
            raise ValueError
        return "|".join((POLICY_PREFIX, *parts))
    except (KeyError, TypeError, AttributeError, ValueError):
        raise ValueError("invalid reconciliation control request") from None


class ReconciliationPolicies:
    def __init__(self, db: AsyncDatabaseManager, *, owners: OwnerDirectory) -> None:
        self._db, self._owners = db, owners

    async def current(self, policy_ref: str) -> ActionPolicy | None:
        parts = policy_ref.split("|")
        if len(parts) != 7 or parts[0] != POLICY_PREFIX:
            return None
        _, app_id, installation_id, team_id, generation, scope, subject = parts
        if not app_id or not generation.isdecimal() or int(generation) < 1:
            return None
        owner = await self._owners.owner_of(self._db, scope)
        if (
            owner is None
            or owner.team_id != team_id
            or owner_scope(installation_id, team_id, owner.principal_did) != scope
            or not await self._owners.is_current(scope, subject)
        ):
            return None
        return ActionPolicy(
            policy_ref=policy_ref,
            version=POLICY_VERSION,
            min_assurance=Assurance.PASSKEY,
            ttl=CONTROL_TTL,
            approver_scopes=(scope,),
            allow_requester_approval=True,
        )


class ReconciliationApprovers:
    def __init__(self, *, owners: OwnerDirectory) -> None:
        self._owners = owners

    async def candidates(self, policy: ActionPolicy, request: Mapping[str, Any]) -> list[Approver]:
        try:
            if (
                reconciliation_policy_ref(request) != policy.policy_ref
                or policy.version != POLICY_VERSION
                or policy.min_assurance is not Assurance.PASSKEY
                or policy.approver_scopes != (request["owner"]["scope"],)
            ):
                return []
        except ValueError:
            return []
        return [
            candidate
            for candidate in await self._owners.candidates(policy, request)
            if (candidate.scope, candidate.subject)
            == (request["owner"]["scope"], request["owner"]["subject"])
        ]
