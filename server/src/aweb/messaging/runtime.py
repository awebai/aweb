"""What a mail or chat send takes from the application that serves it."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from typing import TYPE_CHECKING

import httpx
from starlette.datastructures import State

if TYPE_CHECKING:
    from awid.registry import RegistryClient
    from aweb.federation.activation import FederationAuthorityActivation

from aweb.agent_wake import AgentWakePublisher, agent_wake_publisher
from aweb.application_state import (
    RegistryClientUnavailable,
    application_registry_client,
    native_application_state,
)
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

    registry_client: RegistryClient | None
    federation_authority: FederationAuthorityActivation | None
    mail_transport: httpx.AsyncBaseTransport | None
    chat_transport: httpx.AsyncBaseTransport | None
    public_origin: str
    public_origins: frozenset[str]
    on_mutation: MutationCallback | None
    agent_wake_publisher: AgentWakePublisher | None
    identity_binding_cache: OrderedDict


def messaging_runtime(app_state: State) -> MessagingRuntime:
    """The messaging runtime of the application that owns ``app_state``.

    Registry-independent local sends retain an optional registry. Binding and
    routing owners refuse operations that require an unavailable client.
    Select before any native-state projection so a resource wins over shadows.
    """
    try:
        registry_client = application_registry_client(app_state)
    except RegistryClientUnavailable:
        registry_client = None
    app_state = native_application_state(app_state)
    federation_authority = getattr(app_state, "federation_authority", None)
    return MessagingRuntime(
        registry_client=registry_client,
        federation_authority=federation_authority,
        mail_transport=delivery_transport(
            federation_authority,
            getattr(app_state, "federation_mail_transport", None),
        ),
        chat_transport=delivery_transport(
            federation_authority,
            getattr(app_state, "federation_chat_transport", None),
            fallback_transports=(
                getattr(app_state, "federation_message_transport", None),
                getattr(app_state, "federation_mail_transport", None),
            ),
        ),
        public_origin=application_public_origin(app_state),
        public_origins=frozenset(application_public_origins(app_state)),
        on_mutation=getattr(app_state, "on_mutation", None),
        agent_wake_publisher=agent_wake_publisher(app_state),
        identity_binding_cache=identity_binding_cache(app_state),
    )


def application_public_origin(app_state: State | None) -> str:
    """The origin an application names as its own when it sends to another server."""
    if app_state is not None:
        app_state = native_application_state(app_state)
    configured = str(getattr(app_state, "public_origin", "") or "").strip()
    if configured:
        return configured
    return get_public_origin()
