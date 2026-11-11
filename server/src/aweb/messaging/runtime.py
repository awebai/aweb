"""What a mail or chat send takes from the application that serves it."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from typing import Any

from aweb.agent_wake import AgentWakePublisher, agent_wake_publisher
from aweb.config import get_public_origin
from aweb.federation.origins import application_public_origins
from aweb.federation.transport import delivery_transport
from aweb.hooks import MutationCallback
from aweb.identity_binding import identity_binding_cache


@dataclass(frozen=True)
class MessagingRuntime:
    """The serving application's registry, federation authority and transports, origins and publishers.

    Sends take it in place of a request, so every caller of a send reaches the
    same application services.
    """

    registry_client: Any
    federation_authority: Any
    mail_transport: Any
    chat_transport: Any
    public_origin: str
    public_origins: frozenset[str]
    on_mutation: MutationCallback | None
    agent_wake_publisher: AgentWakePublisher | None
    identity_binding_cache: OrderedDict


def messaging_runtime(app_state) -> MessagingRuntime:
    """The messaging runtime of the application that owns ``app_state``."""
    federation_authority = getattr(app_state, "federation_authority", None)
    return MessagingRuntime(
        registry_client=getattr(app_state, "awid_registry_client", None),
        federation_authority=federation_authority,
        mail_transport=delivery_transport(
            federation_authority,
            getattr(app_state, "federation_mail_transport", None),
        ),
        chat_transport=delivery_transport(
            federation_authority,
            getattr(app_state, "federation_chat_transport", None),
            getattr(app_state, "federation_message_transport", None),
            getattr(app_state, "federation_mail_transport", None),
        ),
        public_origin=application_public_origin(app_state),
        public_origins=frozenset(application_public_origins(app_state)),
        on_mutation=getattr(app_state, "on_mutation", None),
        agent_wake_publisher=agent_wake_publisher(app_state),
        identity_binding_cache=identity_binding_cache(app_state),
    )


def application_public_origin(app_state) -> str:
    """The origin an application names as its own when it sends to another server."""
    configured = str(getattr(app_state, "public_origin", "") or "").strip()
    if configured:
        return configured
    return get_public_origin()
