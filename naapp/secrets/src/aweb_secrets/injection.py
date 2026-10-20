"""Server-side credential injection for the bearer, basic, header and query
kinds (secrets §7.5).

The raw value is opened from custody, placed into the request here and sent
by the egress guard as an injected header, so it never leaves secrets. Every
placed value (the raw value, and for basic the ``user:pass`` composite whose
base64 the header carries) goes into the dispatch's known values, so the
response handling redacts it. Where a value goes is the secret's metadata
(``kind_params``), never the agent's choice.

- ``bearer``: ``Authorization: Bearer <value>``.
- ``basic``: ``Authorization: Basic base64(username:password)``.
- ``header``: ``<name>: <prefix><value>``, name and prefix owner-set.
- ``query``: ``<param>=<value>`` added to the URL. The agent's URL may not
  carry that parameter already, and the URL recorded for the request has the
  value replaced with ``[REDACTED]``.
"""

from __future__ import annotations

import base64
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, quote, urlsplit

from aweb_naapp.egress import EgressRefused

from aweb_secrets.redaction import KnownValues

# Headers the egress guard sets itself; a credential never takes their place.
_GUARD_HEADERS = frozenset(
    {"host", "user-agent", "connection", "content-length", "accept-encoding", "transfer-encoding"}
)
_TOKEN = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+\Z")


@dataclass(frozen=True)
class Injection:
    """Where one secret's value goes in one request.

    ``url`` is what is sent; ``recorded_url`` is what may be recorded or shown.
    ``headers`` are sent as the guard's injected headers, and
    ``injected_names`` declares them in its header rules, so an agent header
    of the same name is refused.
    """

    url: str
    recorded_url: str
    headers: list[tuple[str, str]] = field(repr=False)
    injected_names: frozenset[str]
    known: KnownValues = field(repr=False)


def _required(values: Mapping[str, str], name: str) -> str:
    value = values.get(name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"the secret has no {name}")
    return value


def _header(name: str, value: str, *, url: str, known: KnownValues) -> Injection:
    if not _TOKEN.match(name) or name.lower() in _GUARD_HEADERS:
        raise ValueError(f"{name!r} cannot carry a credential")
    return Injection(
        url=url,
        recorded_url=url,
        headers=[(name, value)],
        injected_names=frozenset({name.lower()}),
        known=known,
    )


def _query(param: str, value: str, *, url: str, known: KnownValues) -> Injection:
    query = urlsplit(url).query
    if any(name == param for name, _ in parse_qsl(query, keep_blank_values=True)):
        raise EgressRefused("params_invalid", "query", f"the request may not set {param}")
    separator = "&" if query else "?"
    name = quote(param, safe="")
    return Injection(
        url=f"{url}{separator}{name}={quote(value, safe='')}",
        recorded_url=f"{url}{separator}{name}=[REDACTED]",
        headers=[],
        injected_names=frozenset(),
        known=known,
    )


def inject(
    kind: str,
    value: Mapping[str, str],
    kind_params: Mapping[str, str],
    *,
    secret_ref: str,
    url: str,
) -> Injection:
    """Place an opened secret ``value`` into a request to ``url``."""
    known = KnownValues()
    if kind == "basic":
        username = value.get("username", "")
        password = _required(value, "password")
        if ":" in username:
            raise ValueError("a basic username cannot contain ':'")
        known.add_basic(secret_ref, username, password)
        composite = base64.b64encode(f"{username}:{password}".encode()).decode()
        return _header("Authorization", f"Basic {composite}", url=url, known=known)
    if kind not in ("bearer", "header", "query"):
        raise ValueError(f"{kind!r} is not injected here")
    raw = _required(value, "value")
    known.add(secret_ref, raw)
    if kind == "bearer":
        return _header("Authorization", f"Bearer {raw}", url=url, known=known)
    if kind == "header":
        name = _required(kind_params, "name")
        prefix = kind_params.get("prefix", "")
        return _header(name, f"{prefix}{raw}", url=url, known=known)
    return _query(_required(kind_params, "param"), raw, url=url, known=known)
