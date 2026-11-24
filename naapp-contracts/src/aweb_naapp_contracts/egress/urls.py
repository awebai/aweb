"""Canonical outbound URLs and the destinations they are matched against.

The contract is the egress URL conformance vector in ``docs/vectors``. A URL is canonicalized
once, and that one form is what a caller matches, sends, shows to an approver
and records, so the four always agree. Anything ambiguous is refused rather
than guessed at.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network

import idna
from publicsuffixlist import PublicSuffixList

from .addresses import InternalDestinations, IPAddress, IPNetwork, check_internal_cidr
from .refused import EgressRefused

# Pinned in the egress extra and in the egress URL vector, which says how to update it.
PUBLIC_SUFFIX_LIST_VERSION = "1.1.0.20261018"

DEFAULT_PORT = 443
METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})

OUT_OF_SCOPE = "destination_not_in_scope"

_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
_SUB_DELIMS = frozenset("!$&'()*+,;=")
_PATH_RAW = _UNRESERVED | _SUB_DELIMS | frozenset(":@/%")
_QUERY_RAW = _UNRESERVED | (_SUB_DELIMS - frozenset("&+=")) | frozenset(":@/?%")
_CONTROL_BYTES = frozenset(range(0x20)) | {0x7F}
_PATH_REFUSED_BYTES = _CONTROL_BYTES | {ord("/"), ord("\\")}
_HEX = frozenset("0123456789abcdefABCDEF")
_NUMERIC_LABEL = re.compile(r"^(?:[0-9]+|0x[0-9a-f]*)$")
_DOTTED_QUAD = re.compile(r"^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$")
_PORT = re.compile(r"^[1-9][0-9]{0,4}$")
_PARAM = re.compile(r"^\{([a-z_][a-z0-9_]{0,63})\}$")

_public_suffixes = PublicSuffixList()


class _EntryError(ValueError):
    """A malformed destination entry; its argument is the contract rule."""


def _refuse(rule: str, detail: str = "") -> EgressRefused:
    return EgressRefused(OUT_OF_SCOPE, rule, detail)


@dataclass(frozen=True)
class CanonicalURL:
    """An https URL in canonical form.

    ``host`` is lowercase A-labels, or the address text of an IP literal (with
    ``ip`` set). ``path`` and each query key and value are percent-encoded
    canonically; ``query`` keeps the request's order.
    """

    host: str
    port: int
    path: str
    query: tuple[tuple[str, str | None], ...] = ()
    ip: IPAddress | None = None

    @property
    def authority(self) -> str:
        host = f"[{self.host}]" if isinstance(self.ip, IPv6Address) else self.host
        return host if self.port == DEFAULT_PORT else f"{host}:{self.port}"

    @property
    def target(self) -> str:
        """The request target: path and query, as sent on the request line."""
        if not self.query:
            return self.path
        pairs = (key if value is None else f"{key}={value}" for key, value in self.query)
        return f"{self.path}?{'&'.join(pairs)}"

    def __str__(self) -> str:
        return f"https://{self.authority}{self.target}"


def canonical_url(url: str) -> CanonicalURL:
    """Canonicalize ``url``, or refuse it with ``destination_not_in_scope``."""
    scheme, sep, rest = url.partition("://")
    if not sep or scheme.lower() != "https":
        raise _refuse("scheme")
    if any(_is_space_or_control(char) or char == "\\" for char in rest):
        raise _refuse("character")
    if "#" in rest:
        raise _refuse("fragment")
    end = len(rest)
    for delimiter in "/?":
        index = rest.find(delimiter)
        if index != -1:
            end = min(end, index)
    authority, remainder = rest[:end], rest[end:]
    if "@" in authority:
        raise _refuse("userinfo")
    if any(not char.isascii() for char in remainder):
        raise _refuse("character")
    host, ip, port = _authority(authority)
    path, _, query = remainder.partition("?")
    return CanonicalURL(
        host=host, port=port, path=_canonical_path(path or "/"), query=_query(query), ip=ip
    )


def _is_space_or_control(char: str) -> bool:
    return char.isspace() or ord(char) < 0x20 or ord(char) == 0x7F


def _authority(authority: str) -> tuple[str, IPAddress | None, int]:
    if authority.startswith("["):
        literal, bracket, port_text = authority[1:].partition("]")
        if not bracket or (port_text and not port_text.startswith(":")):
            raise _refuse("host")
        try:
            ipv6 = IPv6Address(literal)
        except ValueError as error:
            raise _refuse("host") from error
        if ipv6.scope_id is not None:
            raise _refuse("host")
        return ipv6.compressed, ipv6, _port(port_text[1:] if port_text else None)
    host, colon, port_text = authority.partition(":")
    host, ip = canonical_host(host)
    return host, ip, _port(port_text if colon else None)


def _port(text: str | None) -> int:
    if text is None:
        return DEFAULT_PORT
    if not _PORT.match(text) or int(text) > 65535:
        raise _refuse("port")
    return int(text)


def canonical_host(host: str) -> tuple[str, IPAddress | None]:
    """A hostname as lowercase A-labels, or a dotted-quad IPv4 literal."""
    if not host or "%" in host:
        raise _refuse("host")
    if any(unicodedata.category(char) == "Cf" for char in host):
        raise _refuse("host", "an invisible format character")
    try:
        encoded = idna.encode(host, uts46=True, std3_rules=True, transitional=False)
    except idna.IDNAError as error:
        raise _refuse("host") from error
    name = encoded.decode("ascii")
    if not name or name.endswith(".") or len(name) > 253:
        raise _refuse("host")
    if _NUMERIC_LABEL.match(name.rsplit(".", 1)[-1]):
        if not _DOTTED_QUAD.match(name):
            raise _refuse("host")
        try:
            ipv4 = IPv4Address(name)
        except ValueError as error:
            raise _refuse("host") from error
        return str(ipv4), ipv4
    return name, None


def _decode_percent(text: str, index: int) -> int:
    pair = text[index + 1 : index + 3]
    if len(pair) != 2 or not set(pair) <= _HEX:
        raise ValueError(text)
    return int(pair, 16)


def _reencode(text: str, raw: frozenset[str], refused_bytes: frozenset[int]) -> str:
    """Decode unreserved encodings, uppercase the others, refuse forbidden bytes."""
    out: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char == "%":
            byte = _decode_percent(text, index)
            if byte in refused_bytes:
                raise ValueError(text)
            decoded = chr(byte)
            out.append(decoded if decoded in _UNRESERVED else f"%{byte:02X}")
            index += 3
            continue
        if char not in raw:
            raise LookupError(char)
        out.append(char)
        index += 1
    return "".join(out)


def _canonical_path(path: str) -> str:
    if not path.startswith("/"):
        raise _refuse("path")
    segments = path[1:].split("/")
    canonical: list[str] = []
    for position, segment in enumerate(segments):
        try:
            value = _reencode(segment, _PATH_RAW, frozenset(_PATH_REFUSED_BYTES))
        except LookupError as error:
            raise _refuse("character") from error
        except ValueError as error:
            raise _refuse("path") from error
        last = position == len(segments) - 1
        if value in (".", "..") or (value == "" and not last):
            raise _refuse("path")
        canonical.append(value)
    return "/" + "/".join(canonical)


def _query(query: str) -> tuple[tuple[str, str | None], ...]:
    if not query:
        return ()
    pairs: list[tuple[str, str | None]] = []
    for pair in query.split("&"):
        key, equals, value = pair.partition("=")
        if not key:
            raise _refuse("query")
        if "+" in pair or "=" in value:
            raise _refuse("query")
        parts = [key, value] if equals else [key]
        try:
            canonical = [_reencode(part, _QUERY_RAW, frozenset(_CONTROL_BYTES)) for part in parts]
        except LookupError as error:
            raise _refuse("character") from error
        except ValueError as error:
            raise _refuse("query") from error
        for part in canonical:
            try:
                _percent_decode(part)
            except UnicodeDecodeError as error:
                raise _refuse("query") from error
        pairs.append((canonical[0], canonical[1] if equals else None))
    return tuple(pairs)


def _percent_decode(text: str) -> str:
    out = bytearray()
    index = 0
    while index < len(text):
        if text[index] == "%":
            out.append(int(text[index + 1 : index + 3], 16))
            index += 3
        else:
            out.extend(text[index].encode("ascii"))
            index += 1
    return out.decode("utf-8")


class Network(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"


class Presence(StrEnum):
    REQUIRED = "required"
    OPTIONAL = "optional"
    FORBIDDEN = "forbidden"


@dataclass(frozen=True)
class QueryRule:
    presence: Presence = Presence.OPTIONAL
    repeatable: bool = False


@dataclass(frozen=True)
class Destination:
    """Where a request may go. Build one with :func:`parse_destination`."""

    host: str
    path: str
    methods: frozenset[str]
    port: int = DEFAULT_PORT
    query_rules: Mapping[str, QueryRule] = field(default_factory=dict)
    header_allow: frozenset[str] = frozenset()
    network: Network = Network.PUBLIC
    cidr: IPNetwork | None = None

    @property
    def wildcard(self) -> bool:
        return self.host.startswith("*.")

    @property
    def ip(self) -> IPAddress | None:
        try:
            return ip_address(self.host)
        except ValueError:
            return None


def parse_destination(
    entry: Mapping[str, object], *, internal_destinations: InternalDestinations
) -> Destination:
    """Validate a destination entry when it is defined, under the deploy setting."""
    try:
        destination = Destination(
            host=_string(entry["host"]),
            path=_string(entry["path"]),
            methods=frozenset(_strings(entry["methods"])),
            port=_integer(entry.get("port", DEFAULT_PORT)),
            query_rules=_query_rules(entry.get("query_rules", {})),
            header_allow=frozenset(_strings(entry.get("header_allow", []))),
            network=Network(_string(entry.get("network", Network.PUBLIC))),
            cidr=_cidr(entry.get("cidr")),
        )
    except (KeyError, TypeError, ValueError) as error:
        rule = error.args[0] if isinstance(error, _EntryError) else "destination"
        raise _refuse(rule) from error
    check_destination(destination, internal_destinations=internal_destinations)
    return destination


def _string(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError(value)
    return value


def _integer(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(value)
    return value


def _strings(value: object) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise TypeError(value)
    return value


def _query_rules(value: object) -> dict[str, QueryRule]:
    if not isinstance(value, Mapping):
        raise _EntryError("query_rules")
    rules: dict[str, QueryRule] = {}
    for name, rule in value.items():
        if not isinstance(name, str) or not name or not isinstance(rule, Mapping):
            raise _EntryError("query_rules")
        repeatable = rule.get("repeatable", False)
        try:
            presence = Presence(rule.get("presence", Presence.OPTIONAL))
        except ValueError as error:
            raise _EntryError("query_rules") from error
        if not isinstance(repeatable, bool) or set(rule) - {"presence", "repeatable"}:
            raise _EntryError("query_rules")
        rules[name] = QueryRule(presence, repeatable)
    return rules


def _cidr(value: object) -> IPNetwork | None:
    if value is None:
        return None
    try:
        return ip_network(_string(value), strict=True)
    except (TypeError, ValueError) as error:
        raise _EntryError("network") from error


def check_destination(
    destination: Destination, *, internal_destinations: InternalDestinations
) -> None:
    """Refuse a destination the contract or the deploy setting does not allow."""
    if not destination.methods or not destination.methods <= METHODS:
        raise _refuse("method")
    if not 1 <= destination.port <= 65535:
        raise _refuse("port")
    internal = destination.network is Network.INTERNAL
    if internal != (destination.cidr is not None):
        raise _refuse("network")
    if destination.cidr is not None:
        check_internal_cidr(destination.cidr)
    _check_destination_host(destination)
    _check_destination_path(destination.path)
    if (internal or destination.ip is not None) and (
        internal_destinations is not InternalDestinations.ALLOWED
    ):
        raise EgressRefused("internal_destinations_disabled", "internal_destinations")


def _check_destination_host(destination: Destination) -> None:
    host = destination.host
    ip = destination.ip
    if ip is not None:
        if destination.network is not Network.INTERNAL or destination.cidr is None:
            raise _refuse("destination_host", "an IP literal must be an internal destination")
        if ip.version != destination.cidr.version or ip not in destination.cidr:
            raise _refuse("destination_host", "the IP literal is outside the destination CIDR")
        return
    parent = host[2:] if destination.wildcard else host
    try:
        canonical, literal = canonical_host(parent)
    except EgressRefused as error:
        raise _refuse("destination_host", host) from error
    if canonical != parent or literal is not None:
        raise _refuse("destination_host", host)
    if destination.wildcard and ("." not in parent or _public_suffixes.is_public(parent)):
        raise _refuse("destination_host", "a wildcard over a public suffix")


def _check_destination_path(path: str) -> None:
    if not path.startswith("/"):
        raise _refuse("destination_path")
    segments = path[1:].split("/")
    names: set[str] = set()
    for position, segment in enumerate(segments):
        if segment == "**":
            if position != len(segments) - 1:
                raise _refuse("destination_path")
            continue
        param = _PARAM.match(segment)
        if param:
            if param.group(1) in names:
                raise _refuse("destination_path")
            names.add(param.group(1))
            continue
        if "*" in segment or "{" in segment or "}" in segment:
            raise _refuse("destination_path")
    literal = "/" + "/".join(s for s in segments if s != "**" and not _PARAM.match(s))
    try:
        if _canonical_path(literal) != literal:
            raise _refuse("destination_path")
    except EgressRefused as error:
        raise _refuse("destination_path") from error


def match_destination(
    destination: Destination,
    method: str,
    url: str | CanonicalURL,
    *,
    internal_destinations: InternalDestinations,
) -> dict[str, str]:
    """Match a request against a destination at dispatch.

    Returns the captured ``{param}`` segments in canonical encoding; the
    caller validates their types. Refuses with ``destination_not_in_scope``,
    or ``internal_destinations_disabled`` when the deploy setting no longer
    allows the destination.
    """
    check_destination(destination, internal_destinations=internal_destinations)
    canonical = url if isinstance(url, CanonicalURL) else canonical_url(url)
    if method not in METHODS or method not in destination.methods:
        raise _refuse("method")
    _match_host(destination, canonical)
    if canonical.port != destination.port:
        raise _refuse("port")
    params = _match_path(destination.path, canonical.path)
    _match_query(destination.query_rules, canonical.query)
    return params


def _match_host(destination: Destination, url: CanonicalURL) -> None:
    if destination.ip is not None or url.ip is not None:
        if destination.ip is None or url.ip != destination.ip:
            raise _refuse("host")
        return
    if destination.wildcard:
        label, dot, parent = url.host.partition(".")
        if not dot or not label or parent != destination.host[2:]:
            raise _refuse("host")
        return
    if url.host != destination.host:
        raise _refuse("host")


def _match_path(pattern: str, path: str) -> dict[str, str]:
    expected = pattern[1:].split("/")
    actual = path[1:].split("/")
    params: dict[str, str] = {}
    for position, segment in enumerate(expected):
        if segment == "**":
            return params
        if position >= len(actual):
            raise _refuse("path")
        param = _PARAM.match(segment)
        if param:
            if not actual[position]:
                raise _refuse("path")
            params[param.group(1)] = actual[position]
        elif actual[position] != segment:
            raise _refuse("path")
    if len(actual) != len(expected):
        raise _refuse("path")
    return params


def _match_query(rules: Mapping[str, QueryRule], query: tuple[tuple[str, str | None], ...]) -> None:
    seen: dict[str, int] = {}
    for key, _ in query:
        name = _percent_decode(key)
        seen[name] = seen.get(name, 0) + 1
    for name, count in seen.items():
        rule = rules.get(name, QueryRule())
        if rule.presence is Presence.FORBIDDEN or (count > 1 and not rule.repeatable):
            raise _refuse("query", name)
    for name, rule in rules.items():
        if rule.presence is Presence.REQUIRED and name not in seen:
            raise _refuse("query", name)
