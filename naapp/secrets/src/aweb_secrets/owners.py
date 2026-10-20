"""secrets' owners and approvers as B3 scopes (decisions 40 and 41).

B3 keeps one approver per scope, and a scope is unique across the database.
So each owner has its own scope, named from the installation and the owner's
stable principal (S5's principal_did), and each approver its own, named from
the installation and the approver's reference. Hashing keeps the name inside
the role token of an ``aweb.owner-act/1`` subject; the request that designates
an owner carries the principal, and the app recomputes the scope from it.

An owner scope's approver is designated only by a team owner act. Any other
scope's approver may be designated by an owner's approval of a change set.
"""

from __future__ import annotations

import hashlib
import re

OWNER_ROLE = "secrets.owner"
_OWNER_SCOPE = re.compile(r"secrets\.owner\.[0-9a-f]{40}")


def _segment(installation_id: str, name: str) -> str:
    return hashlib.sha256(f"{installation_id}\n{name}".encode()).hexdigest()[:40]


def owner_scope(installation_id: str, principal_did: str) -> str:
    """The B3 scope of ``principal_did`` as an owner of the installation."""
    return f"secrets.owner.{_segment(installation_id, principal_did)}"


def approver_scope(installation_id: str, approver_ref: str) -> str:
    """The B3 scope of the installation's approver ``approver_ref``."""
    return f"secrets.approver.{_segment(installation_id, approver_ref)}"


def is_owner_scope(scope: str) -> bool:
    return _OWNER_SCOPE.fullmatch(scope) is not None
