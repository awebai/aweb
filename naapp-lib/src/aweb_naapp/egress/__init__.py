"""The shared egress guard for naapps that call external services.

It canonicalizes and matches outbound URLs, resolves names with its own
resolver and checks every address against the denied ranges, and sends
through one pinned, verified connection with redirects returned rather than
followed and no proxy from the environment.
"""

from __future__ import annotations

from .addresses import AddressPolicy, InternalDestinations
from .refused import EgressRefused

__all__ = [
    "AddressPolicy",
    "EgressRefused",
    "InternalDestinations",
]
