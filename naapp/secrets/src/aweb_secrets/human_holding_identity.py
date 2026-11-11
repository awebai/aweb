"""Durable, value-free identity of an app-projected owner holding.

The v1 bytes are fixed by test_human_holding_identity's public-metadata vector.
Changing a field, domain or encoding requires a new version. Shared stores the
opaque string; it neither serializes the app records nor treats this public
digest as authority. The original target and prepared guard remain unchanged.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from aweb_naapp.hooks.strictjson import Refused, canonical

from aweb_secrets.human_holders import OwnerSessionTarget
from aweb_secrets.owners import owner_scope

_DOMAIN = b"aweb.secrets.owner-holding/1\n"
_PREFIX = "aweb.secrets.owner-holding/1:"


def owner_holding_identity(target: OwnerSessionTarget) -> str:
    """Identify existing holding metadata, without reading or granting authority.

    Role re-grant's assignment stamp, installation generation and the B3
    association are bound. Credential-only replacement keeps that association
    fixed. Legacy recovery replaces the B3 subject and therefore changes this
    identity too. Shared must check exact LOGIN retirement/cooling-off first,
    preserving renewing 401 rather than misclassifying it as holding loss.

    LOGIN evidence, credentials, member signing keys, session/ephemeral keys
    and per-request freshness are deliberately absent. Their checks remain
    shared's responsibility; this digest extends none of them.
    """
    if not isinstance(target, OwnerSessionTarget):
        raise ValueError("owner holding identity requires an app target")
    admitted, scope, stamp = target.admitted, target.public_scope, target._role_assigned_at
    if (
        scope.installation_id != admitted.installation_id
        or type(admitted.generation) is not int
        or admitted.generation < 1
        or not isinstance(stamp, datetime)
        or stamp.utcoffset() is None
        or target.b3_scope
        != owner_scope(admitted.installation_id, admitted.team_id, scope.principal)
    ):
        raise ValueError("owner holding identity requires consistent app metadata")
    fields = {
        "app_id": admitted.app_id,
        "team_id": admitted.team_id,
        "installation_id": admitted.installation_id,
        "generation": str(admitted.generation),
        "principal": scope.principal,
        "role": scope.role,
        "b3_scope": target.b3_scope,
        "subject": target.subject,
        "role_assigned_at": stamp.astimezone(UTC).isoformat(timespec="microseconds"),
    }
    if any(not isinstance(value, str) or not value for value in fields.values()):
        raise ValueError("owner holding identity requires nonempty metadata")
    try:
        encoded = canonical(fields)
    except Refused:
        raise ValueError("owner holding identity metadata is not canonical") from None
    return _PREFIX + hashlib.sha256(_DOMAIN + encoded).hexdigest()
