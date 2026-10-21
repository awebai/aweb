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
- ``aws-sigv4``: the final request, as the guard will send it (canonical URL,
  ``Host`` as its authority, the agent's headers, the body), signed with
  botocore's SigV4 signer. The region and service are the secret's, never
  the agent's. ``X-Amz-Content-SHA256`` is always sent, and a session
  token goes as ``X-Amz-Security-Token``. An agent header that would take
  the place of a signed one is refused.
"""

from __future__ import annotations

import base64
import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, quote, urlsplit

from aweb_naapp.egress import EgressRefused, canonical_url
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials

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


_SIGV4_HEADERS = ("Authorization", "X-Amz-Date", "X-Amz-Content-SHA256", "X-Amz-Security-Token")


def _sigv4(
    value: Mapping[str, str],
    kind_params: Mapping[str, str],
    *,
    secret_ref: str,
    url: str,
    method: str,
    body: bytes,
    headers: Sequence[tuple[str, str]],
    known: KnownValues,
) -> Injection:
    access_key_id = _required(value, "access_key_id")
    secret_access_key = _required(value, "secret_access_key")
    session_token = value.get("session_token") or None
    region = _required(kind_params, "region")
    service = _required(kind_params, "service")
    signed_names = {name.lower() for name in _SIGV4_HEADERS}
    for name, _ in headers:
        if name.lower() in signed_names:
            raise EgressRefused("header_not_allowed", "header", name)
    known.add(secret_ref, secret_access_key)
    if session_token is not None:
        known.add(secret_ref, session_token)
    canonical = canonical_url(url)
    request = AWSRequest(
        method=method,
        url=str(canonical),
        data=body,
        headers={
            "Host": canonical.authority,
            "X-Amz-Content-SHA256": hashlib.sha256(body).hexdigest(),
            **dict(headers),
        },
    )
    SigV4Auth(Credentials(access_key_id, secret_access_key, session_token), service, region).add_auth(
        request
    )
    injected = [(name, request.headers[name]) for name in _SIGV4_HEADERS if name in request.headers]
    return Injection(
        url=str(canonical),
        recorded_url=str(canonical),
        headers=injected,
        injected_names=frozenset(name.lower() for name, _ in injected),
        known=known,
    )


def inject(
    kind: str,
    value: Mapping[str, str],
    kind_params: Mapping[str, str],
    *,
    secret_ref: str,
    url: str,
    method: str = "GET",
    body: bytes = b"",
    headers: Sequence[tuple[str, str]] = (),
) -> Injection:
    """Place an opened secret ``value`` into a request to ``url``.

    ``method``, ``body`` and the agent's ``headers`` are what a signing kind
    signs; the other kinds do not read them.
    """
    known = KnownValues()
    if kind == "aws-sigv4":
        return _sigv4(
            value,
            kind_params,
            secret_ref=secret_ref,
            url=url,
            method=method,
            body=body,
            headers=headers,
            known=known,
        )
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
