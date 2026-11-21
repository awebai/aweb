"""One deployment-selected client address for federation request budgets."""

import os

from fastapi import Request
from aweb_naapp.client_identity import ClientIdentity


def request_client_address(request: Request | None) -> str:
    """Resolve the configured trusted header or peer, without trusting others.

    Strict Cross-Registry Sender Authority (docs/identity-messaging-contract.md:267-275)
    assigns proxy-header trust to
    deployment configuration. Missing HTTP context has no known client address.
    """
    if request is None:
        return "unknown"
    return (
        ClientIdentity(
            trusted_header=os.getenv("AWEB_CLIENT_ADDRESS_HEADER", "").strip() or None,
        ).of(request)
        or "unknown"
    )
