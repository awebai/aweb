from __future__ import annotations

from typing import Any, Callable, Awaitable

from fastapi import Request

from aweb.dns_verify import DomainAuthority, verify_domain as _real_verify_domain

DomainVerifier = Callable[[str], Awaitable[DomainAuthority]]


def get_db(request: Request) -> Any:
    """Return the database handle from `app.state`.

    `aweb` is intentionally decoupled from product-layer `DatabaseInfra`. The only
    contract required here is that the returned object supports the operations
    needed by `aweb.auth` (currently: `get_manager(name)`).
    """
    return request.app.state.db


def get_redis(request: Request) -> Any:
    """Return the Redis handle from `app.state` (if configured)."""
    return request.app.state.redis


def get_domain_verifier() -> DomainVerifier:
    """Return the DNS domain verifier. Override via app.dependency_overrides in tests."""
    return _real_verify_domain
