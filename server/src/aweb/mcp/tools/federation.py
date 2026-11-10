"""Shared MCP helpers for federated mail/chat delivery."""

from __future__ import annotations

from collections import OrderedDict
from typing import Any

from aweb.agent_wake import agent_wake_publisher
from aweb.identity_auth_deps import MessagingAuth
from aweb.identity_binding import identity_binding_cache
from aweb.mcp.auth import AuthContext
from aweb.federation.origins import application_public_origins
from aweb.mcp.mutations import current_mutation_callback
from aweb.messaging.runtime import MessagingRuntime, application_public_origin


def mcp_messaging_auth(auth: AuthContext) -> MessagingAuth:
    return MessagingAuth(
        did_key=(auth.did_key or "").strip(),
        did_aw=(auth.did_aw or "").strip() or None,
        address=(auth.address or "").strip() or None,
        team_id=auth.team_id,
        alias=auth.alias,
        agent_id=auth.agent_id,
        identity_scope=auth.identity_scope,
    )


def mcp_messaging_runtime(
    auth: AuthContext,
    *,
    public_origin: str | None = None,
    mail_transport: Any = None,
    chat_transport: Any = None,
) -> MessagingRuntime:
    """The serving application's messaging runtime as this MCP app sends with it.

    The origin and the federation transports are the ones the MCP app was
    created with; the registry client, wake publisher and identity binding
    cache are the serving application's.
    """
    state = getattr(getattr(auth.request, "app", None), "state", None)
    origin = (public_origin or "").strip()
    return MessagingRuntime(
        registry_client=getattr(state, "awid_registry_client", None),
        mail_transport=mail_transport,
        chat_transport=chat_transport,
        public_origin=origin or application_public_origin(state),
        public_origins=frozenset(application_public_origins(state, public_origin=origin or None)),
        on_mutation=current_mutation_callback(),
        agent_wake_publisher=agent_wake_publisher(state),
        identity_binding_cache=identity_binding_cache(state) if state is not None else OrderedDict(),
    )


def registry_delivery_origin(resolution) -> str:
    delivery = getattr(resolution, "delivery", None)
    return str(
        getattr(resolution, "delivery_origin", None)
        or getattr(delivery, "origin", "")
        or ""
    ).strip()
