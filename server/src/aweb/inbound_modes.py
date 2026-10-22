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
