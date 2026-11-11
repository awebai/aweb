"""The embedding application's mutation callback, as MCP tools reach it.

The MCP app is mounted inside an application whose ``app.state.on_mutation``
is the same callback the REST routes fire. ``MCPAuthMiddleware`` records that
callback for the current request, so MCP tools publish the same events as the
REST routes that perform the same mutation.
"""

from __future__ import annotations

import contextvars
from typing import Any

from aweb.hooks import MutationCallback

_mutation_callback: contextvars.ContextVar[MutationCallback | None] = contextvars.ContextVar(
    "aweb_mcp_mutation_callback", default=None
)


def mutation_callback_from_scope(scope: Any) -> MutationCallback | None:
    """Return the on_mutation callback of the application serving this ASGI scope."""
    state = getattr(scope.get("app"), "state", None)
    return getattr(state, "on_mutation", None)


def set_mutation_callback(callback: MutationCallback | None) -> contextvars.Token:
    return _mutation_callback.set(callback)


def reset_mutation_callback(token: contextvars.Token) -> None:
    _mutation_callback.reset(token)


def current_mutation_callback() -> MutationCallback | None:
    return _mutation_callback.get()
