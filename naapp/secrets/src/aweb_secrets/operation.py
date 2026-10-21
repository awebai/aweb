"""The operation template v1 (§8.1): an owner-defined, bounded use of a secret.

A template is immutable and addressed by ``operation_id@digest``, the digest
being the SHA-256 of ``aweb.secrets.operation/1\\n`` followed by the canonical
JSON of the template without ``v``. Editing any field is a new digest, which no
existing grant covers.

Parameters fill only typed slots. A path parameter fills one whole ``{param}``
segment of a fixed URL, a body parameter one ``{"$param": name}`` slot of a
fixed body template, a query parameter one named value. Each is checked
against its bounded schema (D1's inline-schema subset) and, for strings, a
fixed character class, so a value never becomes a separator, a header, a host
or a method. The template is the change/1 ``after`` v1 of an operation.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any

from aweb_naapp.egress import EgressRefused, InternalDestinations, parse_destination
from aweb_naapp.egress.headers import ALWAYS_REJECTED, ALWAYS_REJECTED_PREFIXES, GUARD_SET
from aweb_naapp.pages import inline_schema_errors, inline_value_valid
from awid.signing import canonical_json_bytes

from aweb_secrets.grant import GRANT_TEMPLATE_ID
from aweb_secrets.policy import IDENTIFIER
from aweb_secrets.secret import KINDS, SECRET_ID

DIGEST_PREFIX = b"aweb.secrets.operation/1\n"

FIELDS = frozenset(
    {
        "v",
        "operation_id",
        "secret_id",
        "method",
        "url",
        "params",
        "body",
        "headers",
        "response",
        "side_effect",
        "token_issuing",
        "result_handling",
        "store_as_secret",
        "idempotency",
        "reconcile",
        "timeout_s",
    }
)
METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
BODY_METHODS = frozenset({"POST", "PUT", "PATCH"})
PLACEMENTS = ("path", "query", "body")
SIDE_EFFECTS = ("none", "reversible", "irreversible")
RESULT_HANDLINGS = ("deny", "withhold", "store_as_secret")
MAX_TIMEOUT_S = 30
MAX_RESPONSE_BYTES = 16 * 1024 * 1024

# The fixed character classes a string parameter may be limited to.
CHARSETS: Mapping[str, re.Pattern[str]] = {
    "digits": re.compile(r"[0-9]+"),
    "hex": re.compile(r"[0-9a-f]+"),
    "alnum": re.compile(r"[A-Za-z0-9]+"),
    "slug": re.compile(r"[a-z0-9][a-z0-9_-]*"),
    "base64url": re.compile(r"[A-Za-z0-9_-]+"),
}

# The structured value fields of each kind, which a derived secret captures (§6.2).
CAPTURE_FIELDS: Mapping[str, tuple[frozenset[str], frozenset[str]]] = {
    "bearer": (frozenset({"value"}), frozenset()),
    "header": (frozenset({"value"}), frozenset()),
    "query": (frozenset({"value"}), frozenset()),
    "basic": (frozenset({"username", "password"}), frozenset()),
    "oauth2-client-credentials": (frozenset({"client_id", "client_secret"}), frozenset()),
    "aws-sigv4": (frozenset({"access_key_id", "secret_access_key"}), frozenset({"session_token"})),
}

_PARAM_NAME = re.compile(r"[a-z_][a-z0-9_]{0,63}")
_PATH_PARAM = re.compile(r"\{([a-z_][a-z0-9_]{0,63})\}")
_TOKEN = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
_LOWER_TOKEN = re.compile(r"[!#$%&'*+\-.^_`|~0-9a-z]+")
_HEADER_VALUE = re.compile(r"[\x20-\x7e\t]*")
_POINTER = re.compile(r"(/([^~/]|~[01])*)+")
_CONTENT_TYPE = re.compile(r"[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*")
_SCALAR_TYPES = frozenset({"string", "integer", "boolean"})
_SAFE_INTEGER = 2**53 - 1


class OperationInvalid(ValueError):
    """The template is not operation template v1."""

    def __init__(self, message: str, code: str = "operation_invalid") -> None:
        super().__init__(message)
        self.code = code


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise OperationInvalid(message)


def _exact(value: Any, keys: frozenset[str], what: str) -> Mapping[str, Any]:
    _require(
        isinstance(value, Mapping) and set(value) == keys, f"{what} needs exactly {sorted(keys)}"
    )
    return value


def _matches(pattern: re.Pattern[str], value: Any) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _sorted_distinct(values: Any) -> bool:
    return isinstance(values, list) and values == sorted(set(values))


def _json_values(value: Any) -> Iterator[Any]:
    yield value
    if isinstance(value, Mapping):
        for item in value.values():
            yield from _json_values(item)
    elif isinstance(value, list):
        for item in value:
            yield from _json_values(item)


def _check_url(method: str, url: Any) -> list[str]:
    """The URL's path parameters, in order, refusing anything but one fixed https target."""
    url = _exact(url, frozenset({"host", "port", "path"}), "url")
    _require(isinstance(url["host"], str) and not url["host"].startswith("*."), "the host is fixed")
    _require(isinstance(url["path"], str) and "**" not in url["path"], "the path is fixed")
    try:
        parse_destination(
            {"host": url["host"], "port": url["port"], "path": url["path"], "methods": [method]},
            internal_destinations=InternalDestinations.DISABLED,
        )
    except EgressRefused as refused:
        raise OperationInvalid(f"the url is not one canonical https target: {refused}") from None
    return _PATH_PARAM.findall(url["path"])


def _schema_types(schema: Mapping[str, Any]) -> set[str]:
    declared = schema.get("type")
    return {declared} if isinstance(declared, str) else set(declared or ())


def _check_params(params: Any) -> dict[str, str]:
    """Each parameter's placement, refusing a parameter outside its typed slot."""
    _require(isinstance(params, Mapping), "params is an object")
    placements = {}
    for name, param in params.items():
        _require(_matches(_PARAM_NAME, name), f"parameter {name!r} is a lowercase name")
        param = _exact(param, frozenset({"schema", "charset", "placement"}), f"parameter {name}")
        _require(
            param["placement"] in PLACEMENTS, f"parameter {name} is placed in path, query or body"
        )
        schema = param["schema"]
        _require(
            isinstance(schema, Mapping) and not inline_schema_errors(schema),
            f"parameter {name}'s schema is a bounded inline schema",
        )
        types = _schema_types(schema)
        if param["placement"] != "body":
            _require(
                bool(types) and types <= _SCALAR_TYPES,
                f"parameter {name} in the {param['placement']} is a scalar",
            )
        if param["charset"] is not None:
            _require(param["charset"] in CHARSETS, f"parameter {name}'s charset is a fixed class")
            _require(types == {"string"}, f"only a string parameter takes a charset, not {name}")
        placements[name] = param["placement"]
    return placements


def _body_slots(template: Any) -> list[str]:
    slots = []
    for value in _json_values(template):
        _require(not isinstance(value, float), "a body template holds no floats")
        if isinstance(value, Mapping) and "$param" in value:
            _require(
                set(value) == {"$param"} and isinstance(value["$param"], str),
                'a slot is exactly {"$param": name}',
            )
            slots.append(value["$param"])
        if isinstance(value, int) and not isinstance(value, bool):
            _require(abs(value) <= _SAFE_INTEGER, "a body template holds only safe integers")
    _require(len(set(slots)) == len(slots), "each body parameter fills one slot")
    return slots


def _check_headers(headers: Any) -> None:
    headers = _exact(headers, frozenset({"fixed", "allowed"}), "headers")
    fixed = headers["fixed"]
    _require(isinstance(fixed, Mapping), "fixed headers are an object")
    for name, value in fixed.items():
        _require(_matches(_TOKEN, name), f"fixed header {name!r} is a token")
        _require(
            _header_name_open(name.lower()), f"fixed header {name!r} is set by the guard or refused"
        )
        _require(_matches(_HEADER_VALUE, value), f"fixed header {name!r} has a plain value")
    allowed = headers["allowed"]
    _require(
        _sorted_distinct(allowed) and all(_matches(_LOWER_TOKEN, name) for name in allowed),
        "allowed agent headers are lowercase names, sorted and distinct",
    )
    for name in allowed:
        _require(_header_name_open(name), f"the agent may not set {name!r}")


def _header_name_open(name: str) -> bool:
    return (
        name not in ALWAYS_REJECTED
        and name not in GUARD_SET
        and not name.startswith(ALWAYS_REJECTED_PREFIXES)
    )


def _check_response(response: Any) -> None:
    response = _exact(response, frozenset({"projection", "max_bytes", "content_types"}), "response")
    projection = response["projection"]
    _require(
        projection is None
        or (
            isinstance(projection, list)
            and len(projection) > 0
            and len(set(projection)) == len(projection)
            and all(_matches(_POINTER, pointer) for pointer in projection)
        ),
        "the projection is null or distinct JSON pointers",
    )
    max_bytes = response["max_bytes"]
    _require(
        type(max_bytes) is int and 1 <= max_bytes <= MAX_RESPONSE_BYTES,
        "response.max_bytes is 1 byte to 16 MiB",
    )
    content_types = response["content_types"]
    _require(
        _sorted_distinct(content_types)
        and len(content_types) > 0
        and all(_matches(_CONTENT_TYPE, value) for value in content_types),
        "content_types are lowercase media types, sorted and distinct",
    )


def _check_store_as_secret(store: Any) -> None:
    store = _exact(
        store,
        frozenset({"derived_kind", "capture", "expires_at", "grant_template"}),
        "store_as_secret",
    )
    _require(store["derived_kind"] in KINDS, "the stored secret's kind is an auth scheme")
    required, optional = CAPTURE_FIELDS[store["derived_kind"]]
    capture = store["capture"]
    _require(
        isinstance(capture, Mapping) and required <= set(capture) <= required | optional,
        f"a {store['derived_kind']} capture takes {sorted(required | optional)}",
    )
    _require(
        all(_matches(_POINTER, pointer) for pointer in capture.values()),
        "each captured field is a JSON pointer",
    )
    _require(_matches(_POINTER, store["expires_at"]), "expires_at is a JSON pointer")
    _require(
        _matches(GRANT_TEMPLATE_ID, store["grant_template"]),
        "grant_template is a grant template id",
    )


def _check(after: Any) -> None:
    _exact(after, FIELDS, "an operation")
    _require(type(after["v"]) is int and after["v"] == 1, "this is operation template v1")
    _require(_matches(IDENTIFIER, after["operation_id"]), "the operation id is a lowercase slug")
    _require(_matches(SECRET_ID, after["secret_id"]), "secret_id is a minted secret id")
    method = after["method"]
    _require(method in METHODS, "the method is GET, POST, PUT, PATCH or DELETE")
    path_params = _check_url(method, after["url"])
    placements = _check_params(after["params"])
    _require(
        path_params == [name for name in path_params if placements.get(name) == "path"]
        and set(path_params) == {name for name, where in placements.items() if where == "path"}
        and len(set(path_params)) == len(path_params),
        "the path parameters are exactly the path's {param} segments",
    )
    body_params = {name for name, where in placements.items() if where == "body"}
    body = after["body"]
    if body is None:
        _require(not body_params, "a body parameter needs a body template")
    else:
        _require(method in BODY_METHODS, f"a {method} request has no body")
        body = _exact(body, frozenset({"template"}), "body")
        _require(
            set(_body_slots(body["template"])) == body_params,
            "the body's slots are its body parameters",
        )
    _check_headers(after["headers"])
    _check_response(after["response"])
    _require(
        after["side_effect"] in SIDE_EFFECTS, "side_effect is none, reversible or irreversible"
    )
    _require(isinstance(after["token_issuing"], bool), "token_issuing is a boolean")
    handling = after["result_handling"]
    _require(handling in RESULT_HANDLINGS, "result_handling is deny, withhold or store_as_secret")
    _require(
        handling == "deny" or after["token_issuing"],
        "only a token-issuing operation handles its result",
    )
    if handling == "store_as_secret":
        _check_store_as_secret(after["store_as_secret"])
    else:
        _require(
            after["store_as_secret"] is None, "store_as_secret is set only for that result handling"
        )
    idempotency = after["idempotency"]
    if idempotency is not None:
        idempotency = _exact(idempotency, frozenset({"header"}), "idempotency")
        _require(_matches(_TOKEN, idempotency["header"]), "the idempotency header is a token")
    reconcile = after["reconcile"]
    _require(
        reconcile is None
        or (_matches(IDENTIFIER, reconcile) and reconcile != after["operation_id"]),
        "reconcile names another operation",
    )
    timeout = after["timeout_s"]
    _require(type(timeout) is int and 1 <= timeout <= MAX_TIMEOUT_S, "timeout_s is 1 to 30 seconds")
    if handling == "store_as_secret":
        raise OperationInvalid(
            "store_as_secret needs derived secrets, which the brokered path does not yet create",
            code="store_as_secret_unavailable",
        )


def operation_digest(after: Mapping[str, Any]) -> str:
    template = {key: value for key, value in after.items() if key != "v"}
    return hashlib.sha256(DIGEST_PREFIX + canonical_json_bytes(template)).hexdigest()


@dataclass(frozen=True)
class OperationTemplate:
    operation_id: str
    secret_id: str
    digest: str
    after: Mapping[str, Any]

    @classmethod
    def from_after(cls, after: Mapping[str, Any]) -> OperationTemplate:
        """The template for a change/1 ``after``, refused unless it is operation template v1."""
        _check(after)
        return cls(
            operation_id=after["operation_id"],
            secret_id=after["secret_id"],
            digest=operation_digest(after),
            after=dict(after),
        )

    @property
    def token_issuing(self) -> bool:
        return bool(self.after["token_issuing"])

    @property
    def projection(self) -> list[str] | None:
        projection = self.after["response"]["projection"]
        return None if projection is None else list(projection)

    def params_valid(self, params: Mapping[str, Any]) -> bool:
        """Whether ``params`` fill exactly this operation's slots, each within its schema and class."""
        declared = self.after["params"]
        if not isinstance(params, Mapping) or set(params) != set(declared):
            return False
        for name, value in params.items():
            if not inline_value_valid(declared[name]["schema"], value):
                return False
            charset = declared[name]["charset"]
            if charset is not None and not _matches(CHARSETS[charset], value):
                return False
        return True
