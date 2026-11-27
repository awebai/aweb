"""FastAPI dependencies for the awid service.

These getters perform no blocking work. Keep them asynchronous so reading app
state never waits for an unrelated synchronous dependency's worker token.
"""

from __future__ import annotations

from typing import Any

from fastapi import Request

from awid.dns_verify import DomainVerifier, verify_domain as _real_verify_domain


async def get_db(request: Request) -> Any:
    """Return the database handle from `app.state`."""
    return request.app.state.db


async def get_domain_verifier() -> DomainVerifier:
    """Return the DNS domain verifier. Override via app.dependency_overrides in tests."""
    return _real_verify_domain
