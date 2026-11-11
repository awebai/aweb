"""The same configured origin set governs federation ingress and forwarding."""
from __future__ import annotations

from awid.log import canonical_server_origin
from aweb.config import get_public_origin


def public_origins(request=None, *, public_origin: str | None = None) -> set[str]:
    return application_public_origins(
        getattr(getattr(request, "app", None), "state", None), public_origin=public_origin,
    )


def application_public_origins(state, *, public_origin: str | None = None) -> set[str]:
    """The origins an application state configures as its own, with ``public_origin`` if given."""
    origins = {
        canonical_server_origin(value)
        for value in getattr(state, "federation_public_origins", [])
        if str(value or "").strip()
    }
    for value in (getattr(state, "public_origin", None), public_origin):
        if str(value or "").strip():
            origins.add(canonical_server_origin(value))
    return origins or {canonical_server_origin(get_public_origin())}


def is_own_origin(delivery_origin: str, origins: set[str]) -> bool:
    try:
        return canonical_server_origin(delivery_origin) in origins
    except ValueError:
        return False  # Existing route validation owns missing/invalid origins.
