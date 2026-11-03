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


def signed_sender_label(auth: Any, alias: str | None = None) -> str:
    """A local signed display label selects its full team, never an address."""
    selected_alias = str(alias or getattr(auth, "alias", "") or "").strip()
    team = str(getattr(auth, "team_id", "") or "").strip()
    if not getattr(auth, "did_aw", None) and team and selected_alias:
        return f"{team}/{selected_alias}"
    return (selected_alias or str(getattr(auth, "address", "") or "").strip()
            or str(getattr(auth, "did_aw", "") or "").strip()
            or str(getattr(auth, "did_key", "") or "").strip())
