"""Request-body evidence shared by every request-signature verifier."""

import hashlib

from starlette.requests import Request


def request_body_sha256(request: Request) -> str:
    """Use the middleware hash, or hash the embedding host's cached bytes.

    Implements docs/team-auth-envelope-v2.md:51-59.

    RequestBodyCacheMiddleware supplies both values before authentication.
    Hosts that cache only bytes must bind those same bytes in every auth path.
    The empty default retains bodyless request compatibility.
    """
    digest = getattr(request.state, "body_sha256", None)
    if digest is not None:
        return digest
    return hashlib.sha256(getattr(request.state, "cached_body", b"") or b"").hexdigest()
