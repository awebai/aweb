"""Sender address policy shared by HTTP and MCP messaging adapters."""
from typing import Any

from aweb.messaging.alias_targets import derive_team_address


def sender_address(auth: Any) -> str | None:
    address = (auth.address or "").strip()
    if address:
        return address
    if getattr(auth, "identity_scope", None) == "global" and (auth.did_aw or "").strip():
        return None
    # Released local and scope-less adapters retain their team routing label.
    return derive_team_address(auth.team_id, auth.alias) or None
