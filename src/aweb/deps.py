from __future__ import annotations

from typing import Any

from fastapi import Request


def get_db(request: Request) -> Any:
    """Return the database handle from `app.state`.

    `aweb` is intentionally decoupled from BeadHub's `DatabaseInfra`. The only
    contract required here is that the returned object supports the operations
    needed by `aweb.auth` (currently: `get_manager(name)`).
    """
    return request.app.state.db


def get_redis(request: Request) -> Any:
    """Return the Redis handle from `app.state` (if configured)."""
    return request.app.state.redis
