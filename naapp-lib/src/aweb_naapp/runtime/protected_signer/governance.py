"""Typed team-governance values and exact-revision transitions.

These pure values confer no authority and perform no writes. A consumer must
admit the exact act, current human/owner and controller authority in its effect
transaction, hold its record through commit, and record the effect and audit
atomically. A stable ID's syntax is not evidence that its own kind is human.
"""

from dataclasses import dataclass, replace
from typing import Any

from awid.did import validate_stable_id

from aweb_naapp.hooks.owner_act import TEAM_GOVERNANCE_ACTS, validate_owner_act_subject
from aweb_naapp.hooks.strictjson import MAX_SAFE_INTEGER, Refused

from .catalog import operation_spec
from .types import SignerRefused


def checked_subject(operation: str, subject: dict[str, Any]) -> dict[str, Any]:
    if operation not in TEAM_GOVERNANCE_ACTS:
        raise SignerRefused("operation_refused")
    try:
        value = validate_owner_act_subject(operation, subject)
        for name in ("old_owners", "new_owners"):
            for principal in value.get(name, ()):
                if validate_stable_id(principal) != principal:
                    raise ValueError()
    except (Refused, TypeError, ValueError):
        raise SignerRefused("request_invalid") from None
    for name in ("old_permissions", "new_permissions"):
        for entry in value.get(name, ()):
            operation_name, variant = entry.split("/", 1)
            if operation_spec(operation_name, variant).key_role != "team_controller":
                raise SignerRefused("scope_refused")
    return value


@dataclass(frozen=True)
class GovernanceState:
    """One immutable team snapshot: both sets share a revision.

    Permissions name exact catalog operation/variant pairs of this controller.
    They never grant an identity a role or waive live-floor/admission checks.
    """

    team_id: str
    revision: int
    owners: tuple[str, ...]
    permissions: tuple[str, ...]

    def __post_init__(self):
        owners = checked_subject(
            "team.owner.change",
            {
                "team_id": self.team_id,
                "expected_revision": self.revision,
                "old_owners": list(self.owners),
                "new_owners": list(self.owners),
            },
        )["new_owners"]
        permissions = checked_subject(
            "team.controller-permissions.change",
            {
                "team_id": self.team_id,
                "expected_revision": self.revision,
                "old_permissions": list(self.permissions),
                "new_permissions": list(self.permissions),
            },
        )["new_permissions"]
        if not owners:
            raise SignerRefused("last_owner_protected")
        object.__setattr__(self, "owners", tuple(owners))
        object.__setattr__(self, "permissions", tuple(permissions))

    def transition(self, operation: str, subject: dict[str, Any]) -> "GovernanceState":
        value = checked_subject(operation, subject)
        if value["team_id"] != self.team_id:
            raise SignerRefused("scope_refused")
        if value["expected_revision"] != self.revision:
            raise SignerRefused("stale_binding")
        if self.revision == MAX_SAFE_INTEGER:
            raise SignerRefused("operation_refused")
        if operation == "team.owner.change":
            if tuple(value["old_owners"]) != self.owners:
                raise SignerRefused("operation_mismatch")
            return replace(self, revision=self.revision + 1, owners=tuple(value["new_owners"]))
        if tuple(value["old_permissions"]) != self.permissions:
            raise SignerRefused("operation_mismatch")
        return replace(
            self, revision=self.revision + 1, permissions=tuple(value["new_permissions"])
        )
