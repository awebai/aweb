"""Canonical native serving state, including hosts carrying one resource ref."""

import logging

from awid.registry import RegistryClient
from starlette.datastructures import State

from aweb.service_errors import ServiceError

logger = logging.getLogger(__name__)


class RegistryClientUnavailable(ServiceError):
    """Expected missing or invalid native serving-registry configuration."""

    status_code = 503
    code = "registry_client_unavailable"
    message = (
        "Registry client is unavailable. Configure the serving registry client "
        "and start the application before retrying."
    )

    def __init__(self) -> None:
        super().__init__({"code": self.code, "message": self.message})


def application_registry_client(state: State) -> RegistryClient:
    """Borrow the exact configured registry without constructing serving resources.

    A native resource reference is authoritative even when its client is
    unavailable. When no native resources object exists, use the initialized
    application-state ``awid_registry_client`` slot that the server sets.
    This selects configuration, not readiness or request proof.
    """
    resources = getattr(state, "native_resources", None)
    client = (
        getattr(resources, "registry_client", None)
        if resources is not None
        else getattr(state, "awid_registry_client", None)
    )
    if not isinstance(client, RegistryClient):
        logger.error(
            "Native serving registry client is missing or invalid; source=%s",
            "resources"
            if resources is not None
            else "application-state awid_registry_client slot (server without a native resources object)",
        )
        raise RegistryClientUnavailable()
    return client


def native_application_state(state: State) -> State:
    """Return the state owning native services, following the single resource reference."""
    resources = getattr(state, "native_resources", None)
    return resources.api_app.state if resources is not None else state
