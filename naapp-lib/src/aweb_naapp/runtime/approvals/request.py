"""The canonical form of an approval request, frozen when it is minted.

An approval covers exactly these bytes: the operation, destination, constraints,
source version and executor the app puts in the request object, together with
the policy reference and version the primitive adds. Changing any covered value
changes the digest, so it needs a new approval.
"""

from __future__ import annotations

import hashlib
import json
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


def _refuse_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise RequestNotCanonical("duplicate object key")
    return dict(pairs)


def _refuse_number(text: str) -> Any:
    raise RequestNotCanonical(f"non-integer number {text!r} has no canonical form")


def parse_request_json(raw: bytes) -> dict[str, Any]:
    """Parse a request received as JSON, refusing what canonical JSON cannot carry:
    duplicate keys, floats and non-finite numbers."""
    try:
        request = json.loads(
            raw,
            object_pairs_hook=_refuse_duplicates,
            parse_float=_refuse_number,
            parse_constant=_refuse_number,
        )
    except ValueError as exc:
        if isinstance(exc, RequestNotCanonical):
            raise
        raise RequestNotCanonical("request is not valid JSON") from exc
    if not isinstance(request, dict):
        raise RequestNotCanonical("request must be a JSON object")
    return request


def request_sha256(request: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_request(request)).hexdigest()
