"""Canonical inbound policy values for aweb and embedding hosts.

Defaults belong to the provisioning caller. Delivery must reject absent policy
instead of using this convenience normalizer's provisioning default.
"""
from __future__ import annotations

INBOUND_MODE_OPEN = "open"
INBOUND_MODE_TEAM_AND_CONTACTS = "team_and_contacts"
INBOUND_MODE_CONTACTS_ONLY = "contacts_only"
INBOUND_MODES = frozenset({
    INBOUND_MODE_OPEN, INBOUND_MODE_TEAM_AND_CONTACTS, INBOUND_MODE_CONTACTS_ONLY,
})


def normalize_inbound_mode(value: str | None, *, default: str = INBOUND_MODE_OPEN) -> str:
    """Normalize a wire value, using the caller's default for missing/blank input.

    CLI hyphenated spellings are translated by the CLI before sending. Unknown
    wire values raise ValueError; contacts_only always keeps its strict meaning.
    """
    mode = (value or "").strip().lower() or default
    if mode not in INBOUND_MODES:
        raise ValueError("inbound_mode must be one of open, team_and_contacts, contacts_only")
    return mode


async def effective_inbound_mode(
    db, did_aw: str, *, for_share: bool = False, for_update: bool = False,
    default: str | None = None,
) -> str:
    """Read the identity policy across every non-deleted membership.

    db may be a database manager or a caller transaction. for_share is for a
    transaction that must keep the policy stable through delivery. for_update
    locks before a caller checks mutation authority and invokes the writer,
    avoiding SHARE-to-UPDATE lock upgrades between parallel setters. Status is
    deliberately irrelevant: retiring a membership cannot widen policy.
    A provisioning default applies only when this identity has no live rows.
    """
    from aweb.service_errors import ForbiddenError

    if for_share and for_update:
        raise ValueError("for_share and for_update are mutually exclusive")
    if not did_aw or not did_aw.startswith("did:aw:"):
        raise ForbiddenError("Recipient inbound_mode migration required")
    rows = await db.fetch_all(
        """
        SELECT agent_id, inbound_mode FROM {{tables.agents}}
        WHERE did_aw = $1 AND deleted_at IS NULL
        ORDER BY agent_id
        """ + (" FOR UPDATE" if for_update else " FOR SHARE" if for_share else ""),
        did_aw,
    )
    if not rows:
        if default is not None:
            return normalize_inbound_mode(default, default="")
        raise ForbiddenError("Recipient inbound_mode migration required")
    modes = {str(row.get("inbound_mode") or "").strip().lower() for row in rows}
    if not modes <= INBOUND_MODES:
        raise ForbiddenError("Recipient inbound_mode migration required")
    for mode in (INBOUND_MODE_CONTACTS_ONLY, INBOUND_MODE_TEAM_AND_CONTACTS, INBOUND_MODE_OPEN):
        if mode in modes:
            return mode
    raise ForbiddenError("Recipient inbound_mode migration required")


async def set_identity_inbound_mode(tx, did_aw: str, mode: str) -> None:
    """Set every live membership inside the caller's authorized transaction.

    The caller must establish identity-level mutation authority in this same
    transaction before invoking this writer. Team ownership alone is not that
    authority. No status filter: only deleted_at removes a row from the policy.
    """
    from aweb.service_errors import NotFoundError

    mode = normalize_inbound_mode(mode, default="")
    if not did_aw or not did_aw.startswith("did:aw:"):
        raise NotFoundError("Identity not found")
    rows = await tx.fetch_all(
        """
        SELECT agent_id FROM {{tables.agents}}
        WHERE did_aw = $1 AND deleted_at IS NULL
        ORDER BY agent_id FOR UPDATE
        """,
        did_aw,
    )
    if not rows:
        raise NotFoundError("Identity not found")
    await tx.execute(
        "UPDATE {{tables.agents}} SET inbound_mode = $2 WHERE did_aw = $1 AND deleted_at IS NULL",
        did_aw, mode,
    )
