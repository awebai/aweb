"""The shared egress guard for naapps that call external services.

It canonicalizes and matches outbound URLs, resolves names with its own
resolver and checks every address against the denied ranges, and sends
through one pinned, verified connection with redirects returned rather than
followed and no proxy from the environment.
"""

from __future__ import annotations

from .addresses import AddressPolicy, InternalDestinations, check_internal_cidr
from .headers import HeaderRules, check_headers, check_injected
from .refused import EgressRefused
from .send import (
    Bounds,
    DnsResolver,
    Egress,
    EgressNotSent,
    EgressOutcomeUnknown,
    Resolver,
    Response,
)
from .urls import (
    PUBLIC_SUFFIX_LIST_VERSION,
    CanonicalURL,
    Destination,
    Network,
    Presence,
    QueryRule,
    canonical_url,
    check_destination,
    match_destination,
    parse_destination,
)

__all__ = [
    "PUBLIC_SUFFIX_LIST_VERSION",
    "AddressPolicy",
    "Bounds",
    "CanonicalURL",
    "Destination",
    "DnsResolver",
    "Egress",
    "EgressNotSent",
    "EgressOutcomeUnknown",
    "EgressRefused",
    "HeaderRules",
    "InternalDestinations",
    "Network",
    "Presence",
    "QueryRule",
    "Resolver",
    "Response",
    "canonical_url",
    "check_internal_cidr",
    "check_destination",
    "check_headers",
    "check_injected",
    "match_destination",
    "parse_destination",
]
