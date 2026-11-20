"""The same configured origin set governs federation ingress and forwarding."""
from __future__ import annotations

from collections.abc import Set

from awid.log import canonical_server_origin
from aweb.config import get_public_origin
from aweb.application_state import native_application_state


def public_origins(request=None, *, public_origin: str | None = None) -> set[str]:
    """Return the configured origins this application serves as its own."""
    return application_public_origins(
        getattr(getattr(request, "app", None), "state", None), public_origin=public_origin,
    )


def application_public_origins(state, *, public_origin: str | None = None) -> set[str]:
    """The origins an application state configures as its own, with ``public_origin`` if given."""
    state = native_application_state(state)
    origins = {
        canonical_server_origin(value)
        for value in getattr(state, "federation_public_origins", [])
        if str(value or "").strip()
    }
    for value in (getattr(state, "public_origin", None), public_origin):
        if str(value or "").strip():
            origins.add(canonical_server_origin(value))
    return origins or {canonical_server_origin(get_public_origin())}


def is_own_origin(delivery_origin: str, origins: Set[str]) -> bool:
    """Whether an origin belongs to the configured native serving application."""
    try:
        return canonical_server_origin(delivery_origin) in origins
    except ValueError:
        return False  # Existing route validation owns missing/invalid origins.
