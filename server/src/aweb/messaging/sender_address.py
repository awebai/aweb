"""Sender address policy shared by HTTP and MCP messaging adapters."""
from typing import Any

from aweb.identity_address import AddressResolutionState, require_address_evidence
from aweb.messaging.alias_targets import derive_team_address


def stored_sender_address(value: str | None, fallback: str | None) -> str | None:
    """Only legacy NULL can inherit a later address from the roster."""
    return fallback if value is None else value


def sender_signature_address(auth: Any, address: str | None) -> str | None:
    """Recognize the previously verified From in the signed bytes only."""
    outcome = getattr(auth, "address_resolution", None)
    if outcome is not None and outcome.state is AddressResolutionState.WITHHELD:
        return outcome.stored_address
    return address


def sender_address(auth: Any) -> str | None:
    require_address_evidence(auth)
    outcome = getattr(auth, "address_resolution", None)
    if outcome is not None and outcome.state is AddressResolutionState.WITHHELD:
        # Persist explicit absence so recipient projections cannot restore a
        # public address from an older member row.
        return ""
    if outcome is not None and outcome.state == "unknown":
        return outcome.stored_address
    address = (auth.address or "").strip()
    if address:
        return address
    if getattr(auth, "identity_scope", None) == "global" and (auth.did_aw or "").strip():
        return None
    # Released local and scope-less adapters retain their team routing label.
    return derive_team_address(auth.team_id, auth.alias) or None
