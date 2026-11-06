"""A named operation rendered into the one request it allows (secrets §8.1).

The method, host, port and path come from the template, and so do the fixed
headers and the body around its slots. The agent's parameters fill only
their typed slots, each checked against its schema and character class:

- a path parameter is one whole segment, percent-encoded, so it never
  becomes a separator; the guard refuses an encoded ``/``, ``\\`` or NUL, and
  a dot segment;
- a query parameter is one encoded value of its own name;
- a body parameter replaces one ``{"$param": name}`` slot.

Of the agent's headers, only the template's ``allowed`` names pass, once
each and never over a fixed header. An operation that declares idempotency
is rendered only with the broker's upstream key, in the declared header; the
agent never sets that header, even when the template lists it as allowed. The destination is the
template's exact target, and the guard matches the request against it
again before sending.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, urlencode

from aweb_naapp.egress import (
    Bounds,
    Destination,
    EgressRefused,
    InternalDestinations,
    canonical_url,
    parse_destination,
)
from aweb_naapp.egress.send import CONNECT_TIMEOUT_SECONDS, MAX_RESPONSE_BYTES

from aweb_secrets.operation import OperationTemplate

_AMZ_PREFIX = "x-amz-"


@dataclass(frozen=True)
class OperationRequest:
    """One rendered request, and how its response is bounded and handled."""

    method: str
    url: str
    destination: Destination
    headers: list[tuple[str, str]]
    body: bytes = field(repr=False)
    bounds: Bounds
    max_bytes: int
    projection: list[str] | None
    content_types: list[str] | None
    token_issuing: bool
    result_handling: str
    amz_allowed: list[str]


def _text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _fill(template: Any, params: Mapping[str, Any]) -> Any:
    if isinstance(template, Mapping):
        if set(template) == {"$param"}:
            return params[template["$param"]]
        return {key: _fill(value, params) for key, value in template.items()}
    if isinstance(template, list):
        return [_fill(item, params) for item in template]
    return template


def render_operation(
    template: OperationTemplate,
    params: Mapping[str, Any],
    *,
    headers: Sequence[tuple[str, str]],
    idempotency_key: str | None = None,
) -> OperationRequest:
    """The request ``template`` allows with ``params`` and the agent's ``headers``.

    Raises ``EgressRefused`` with ``params_invalid`` for parameters outside
    their slots, and ``header_not_allowed`` for a header the template does not
    let the agent set.
    """
    if not template.params_valid(params):
        raise EgressRefused(
            "params_invalid", "params", "the parameters do not fill the operation's slots"
        )
    after = template.after
    declared = after["params"]
    method = after["method"]

    path = after["url"]["path"]
    for name, param in declared.items():
        if param["placement"] == "path":
            path = path.replace("{" + name + "}", quote(_text(params[name]), safe=""))
    query = [
        (name, _text(params[name]))
        for name, param in declared.items()
        if param["placement"] == "query"
    ]
    port = after["url"]["port"]
    authority = after["url"]["host"] + ("" if port == 443 else f":{port}")
    url = f"https://{authority}{path}" + (f"?{urlencode(query, quote_via=quote)}" if query else "")
    url = str(canonical_url(url))

    fixed: Mapping[str, str] = after["headers"]["fixed"]
    allowed = set(after["headers"]["allowed"])
    sent = [(name, value) for name, value in fixed.items()]
    names = {name.lower() for name in fixed}
    idempotency = after["idempotency"]
    if idempotency and not idempotency_key:
        raise ValueError("an idempotent operation is sent only with the broker's idempotency key")
    # The declared idempotency header is the broker's, even if the template allows it.
    reserved = {idempotency["header"].lower()} if idempotency else set()
    body = b""
    if after["body"] is not None:
        body = json.dumps(
            _fill(after["body"]["template"], params), separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        if "content-type" not in names:
            sent.append(("Content-Type", "application/json"))
            names.add("content-type")
    for name, value in headers:
        lowered = name.lower()
        if lowered not in allowed or lowered in names or lowered in reserved:
            raise EgressRefused("header_not_allowed", "header", name)
        names.add(lowered)
        sent.append((name, value))
    if idempotency and idempotency_key:
        sent.append((idempotency["header"], idempotency_key))

    header_allow = sorted({name.lower() for name in fixed} | allowed | reserved)
    destination = parse_destination(
        {
            "host": after["url"]["host"],
            "port": port,
            "path": after["url"]["path"],
            "methods": [method],
            "header_allow": header_allow,
        },
        internal_destinations=InternalDestinations.DISABLED,
    )
    timeout = float(after["timeout_s"])
    max_bytes = min(after["response"]["max_bytes"], MAX_RESPONSE_BYTES)
    return OperationRequest(
        method=method,
        url=url,
        destination=destination,
        headers=sent,
        body=body,
        bounds=Bounds(
            connect_timeout=min(CONNECT_TIMEOUT_SECONDS, timeout),
            total_timeout=timeout,
            max_response_bytes=max_bytes,
        ),
        max_bytes=max_bytes,
        projection=template.projection,
        content_types=list(after["response"]["content_types"]),
        token_issuing=template.token_issuing,
        result_handling=after["result_handling"],
        amz_allowed=[name for name in header_allow if name.startswith(_AMZ_PREFIX)],
    )
