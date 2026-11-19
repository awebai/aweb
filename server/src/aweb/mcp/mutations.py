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
from aweb.application_state import native_application_state

_mutation_callback: contextvars.ContextVar[MutationCallback | None] = contextvars.ContextVar(
    "aweb_mcp_mutation_callback", default=None
)


def mutation_callback_from_scope(scope: Any) -> MutationCallback | None:
    """Return the on_mutation callback of the application serving this ASGI scope."""
    app_state = getattr(scope.get("app"), "state", None)
    if app_state is None:
        return None
    state = native_application_state(app_state)
    return getattr(state, "on_mutation", None)


def set_mutation_callback(callback: MutationCallback | None) -> contextvars.Token:
    """Install the serving callback in this MCP call context and return its reset token."""
    return _mutation_callback.set(callback)


def reset_mutation_callback(token: contextvars.Token) -> None:
    """Restore the callback context after the MCP call completes."""
    _mutation_callback.reset(token)


def current_mutation_callback() -> MutationCallback | None:
    """Read the callback associated with the current MCP call."""
    return _mutation_callback.get()
