"""FastAPI dependencies for the awid service."""

from __future__ import annotations

from typing import Any

from fastapi import Request

from awid.dns_verify import DomainVerifier, verify_domain as _real_verify_domain


def get_db(request: Request) -> Any:
    """Return the database handle from `app.state`."""
    return request.app.state.db


def get_redis(request: Request) -> Any:
    """Return the Redis handle from `app.state` (if configured)."""
    return request.app.state.redis


def get_domain_verifier() -> DomainVerifier:
    """Return the DNS domain verifier. Override via app.dependency_overrides in tests."""
    return _real_verify_domain
