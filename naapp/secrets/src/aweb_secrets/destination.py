"""The destination record v1 (§7.2): where a secret's credential may be sent.

The entry is the egress guard's destination, checked by
:func:`aweb_naapp.egress.parse_destination`, which refuses anything not in its
canonical form. The record adds what makes it one form: every field is
present, the scheme is https, and methods and header names are sorted and
distinct. It is the change/1 ``after`` v1 of a destination; an internal
destination is admitted only where the deploy allows internal destinations,
checked here when it is defined and again by the guard at dispatch.
"""

from __future__ import annotations

import re
import secrets as random
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from aweb_naapp.egress import Destination, EgressRefused, InternalDestinations, parse_destination

from aweb_secrets.secret import SECRET_ID

FIELDS = frozenset(
    {
        "v",
        "destination_id",
        "secret_id",
        "scheme",
        "host",
        "port",
        "path",
        "methods",
        "query_rules",
        "header_allow",
        "network",
        "cidr",
    }
)
DESTINATION_ID = re.compile(r"dst_[A-Za-z0-9_-]{4,64}")
_HEADER_NAME = re.compile(r"[a-z0-9!#$%&'*+.^_`|~-]{1,64}")


class DestinationInvalid(ValueError):
    """The record is not destination record v1; ``code`` is the refusal code."""

    def __init__(self, message: str, code: str = "destination_not_in_scope") -> None:
        super().__init__(message)
        self.code = code


def mint_destination_id() -> str:
    return "dst_" + random.token_urlsafe(16)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise DestinationInvalid(message)


def _sorted_distinct(values: Any) -> bool:
    return isinstance(values, list) and values == sorted(set(values))


def _check(after: Any) -> None:
    _require(
        isinstance(after, Mapping) and set(after) == FIELDS,
        f"a destination needs exactly {sorted(FIELDS)}",
    )
    _require(type(after["v"]) is int and after["v"] == 1, "this is destination record v1")
    _require(
        isinstance(after["destination_id"], str)
        and DESTINATION_ID.fullmatch(after["destination_id"]) is not None,
        "destination_id is a minted destination id",
    )
    _require(
        isinstance(after["secret_id"], str) and SECRET_ID.fullmatch(after["secret_id"]) is not None,
        "secret_id is a minted secret id",
    )
    _require(after["scheme"] == "https", "a destination is https")
    _require(type(after["port"]) is int, "the port is an integer")
    _require(_sorted_distinct(after["methods"]), "methods are sorted and distinct")
    header_allow = after["header_allow"]
    _require(
        _sorted_distinct(header_allow)
        and all(isinstance(name, str) and _HEADER_NAME.fullmatch(name) for name in header_allow),
        "allowed headers are lowercase names, sorted and distinct",
    )


def _entry(after: Mapping[str, Any]) -> dict[str, Any]:
    entry = {
        key: after[key]
        for key in ("host", "port", "path", "methods", "query_rules", "header_allow", "network")
    }
    if after["cidr"] is not None:
        entry["cidr"] = after["cidr"]
    return entry


@dataclass(frozen=True)
class DestinationRecord:
    destination_id: str
    secret_id: str
    destination: Destination
    after: Mapping[str, Any]

    @classmethod
    def from_after(
        cls, after: Mapping[str, Any], *, internal_destinations: InternalDestinations
    ) -> DestinationRecord:
        """The record for a change/1 ``after``, refused unless it is destination record v1
        that the deploy's ``internal_destinations`` setting allows."""
        _check(after)
        try:
            destination = parse_destination(
                _entry(after), internal_destinations=internal_destinations
            )
        except EgressRefused as refused:
            raise DestinationInvalid(str(refused), refused.code) from None
        return cls(
            destination_id=after["destination_id"],
            secret_id=after["secret_id"],
            destination=destination,
            after=dict(after),
        )

    @property
    def network(self) -> str:
        return str(self.destination.network)
