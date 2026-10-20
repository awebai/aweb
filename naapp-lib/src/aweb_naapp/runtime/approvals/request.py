"""The canonical form of an approval request, frozen when it is minted.

An approval covers exactly these bytes: the operation, destination, constraints,
source version, executor and policy the app puts in the request object. Changing
any covered value changes the digest, so it needs a new approval.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any

from awid.signing import canonical_json_bytes

DOMAIN_PREFIX = b"aweb.approval-request/1\n"


class RequestNotCanonical(ValueError):
    """The request holds a value without one canonical JSON form."""


def _check(value: Any, where: str) -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise RequestNotCanonical(f"{where}: object keys must be strings")
            _check(item, f"{where}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _check(item, f"{where}[{index}]")
        return
    raise RequestNotCanonical(f"{where}: {type(value).__name__} has no canonical form")


def canonical_request(request: Mapping[str, Any]) -> bytes:
    """Domain-separated canonical JSON bytes of the request object."""
    if not isinstance(request, Mapping):
        raise RequestNotCanonical("request must be a JSON object")
    _check(request, "request")
    return DOMAIN_PREFIX + canonical_json_bytes(dict(request))


def request_sha256(request: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_request(request)).hexdigest()
