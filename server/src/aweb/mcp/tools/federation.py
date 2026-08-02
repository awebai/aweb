"""Shared MCP helpers for federated mail/chat delivery."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from aweb.config import get_settings
from aweb.identity_auth_deps import MessagingAuth
from aweb.mcp.auth import AuthContext


def mcp_messaging_auth(auth: AuthContext) -> MessagingAuth:
    return MessagingAuth(
        did_key=(auth.did_key or "").strip(),
        did_aw=(auth.did_aw or "").strip() or None,
        address=(auth.address or "").strip() or None,
        team_id=auth.team_id,
        alias=auth.alias,
        agent_id=auth.agent_id,
    )


def mcp_federation_request(
    *,
    public_origin: str | None = None,
    mail_transport: Any = None,
    chat_transport: Any = None,
):
    origin = (public_origin or "").strip() or get_settings().public_origin
    state = SimpleNamespace(
        public_origin=origin,
        federation_mail_transport=mail_transport,
        federation_chat_transport=chat_transport,
        federation_message_transport=chat_transport,
    )
    app = SimpleNamespace(state=state)
    return SimpleNamespace(app=app, headers={})


def registry_delivery_origin(resolution) -> str:
    delivery = getattr(resolution, "delivery", None)
    return str(
        getattr(resolution, "delivery_origin", None)
        or getattr(delivery, "origin", "")
        or ""
    ).strip()
