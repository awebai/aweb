"""An app producer's registration view, read from its team's server.

:class:`TeamServerRegistrations` is the :class:`~aweb_naapp.hooks.producer.Registrations`
source of a naapp that produces hook events: it asks the team's coordination
server, through :class:`~aweb_naapp.runtime.hook_resolver.HookResolver`, where
the team's events of a hook go. The audit-critical gate and the drain both read
it. A core producer reads its own server's bindings in process instead.

A view's ``as_of`` is the time its data is no older than, as the resolver
measures it, and its ``max_age`` the window the resolver reuses that answer
for, so the gate's 60-second bound measures the data, not the time it was
asked for. Every resolution failure is no view: the gate then refuses an
audit-critical effect and the drain leaves the event pending. That includes
``hook_binding_required``, which means this app holds no active production of
the hook, not that nobody is registered.
"""

from __future__ import annotations

import logging
from datetime import timedelta

from aweb_naapp.hooks.envelope import CATALOG_ID, CATALOG_VERSION
from aweb_naapp.hooks.producer import Registration, RegistrationView
from aweb_naapp.runtime.hook_resolver import (
    HookBindingRequired,
    HookResolutionUnavailable,
    HookResolver,
)

__all__ = ["TeamServerRegistrations"]

logger = logging.getLogger(__name__)


class TeamServerRegistrations:
    """The registrations of a team's hooks, as its server lists them."""

    def __init__(self, resolver: HookResolver) -> None:
        self._resolver = resolver

    async def view(self, team_id: str, hook: str) -> RegistrationView | None:
        try:
            resolution = await self._resolver.registrations(
                team_id, CATALOG_ID, CATALOG_VERSION, hook
            )
        except HookBindingRequired:
            logger.warning("No %s view for %s: this app holds no production of it", hook, team_id)
            return None
        except HookResolutionUnavailable as unavailable:
            logger.warning("No %s view for %s: %s", hook, team_id, unavailable.code)
            return None
        return RegistrationView(
            team_id=team_id,
            hook=hook,
            as_of=resolution.as_of,
            max_age=timedelta(seconds=resolution.max_age_seconds),
            registrations=tuple(
                Registration(
                    binding_id=str(binding.binding_id),
                    origin=binding.origin,
                    method=binding.method,
                    path=binding.path,
                    active_from=binding.active_from,
                )
                for binding in resolution.items
                # A registration always has its endpoint and active_from once
                # active; one without them can be owed nothing.
                if binding.method and binding.path and binding.active_from is not None
            ),
        )
