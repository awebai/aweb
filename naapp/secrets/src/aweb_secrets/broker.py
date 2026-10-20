"""One brokered call: inject the secret, send through the egress guard, and
handle the response (secrets §7.3–§7.6).

The guard matches the URL and method against the destination, refuses the
agent's headers that §7.4 forbids (the always-rejected names, any name this
secret injects, credential-shaped values) and resolves and pins the address,
all before any byte is sent. So a request for any other host never carries
the credential. The injected headers go out only as the guard's injected
headers, and every injected value is redacted from what comes back.

An ``oauth2-client-credentials`` secret is first exchanged at its owner-set
token endpoint, through the guard to that endpoint's own destination, with
the client authenticated by ``client_secret_basic`` or ``client_secret_post``
and the owner-set scope. The access token is cached for its lifetime less
60 s under a key secrets derives (:class:`aweb_secrets.tokens.TokenKey`),
never returned, and injected as a bearer. The client secret and the
token are both known values. If the exchange fails, the target was never
called: :class:`TokenExchangeFailed` is a kind of ``EgressNotSent``.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from urllib.parse import quote_plus, urlencode

from aweb_naapp.egress import (
    Bounds,
    Destination,
    Egress,
    EgressNotSent,
    EgressOutcomeUnknown,
    HeaderRules,
)

from aweb_secrets.credential_shapes import is_credential_shaped_value
from aweb_secrets.injection import Injection, inject
from aweb_secrets.redaction import KnownValues
from aweb_secrets.responses import BrokeredResult, handle_response
from aweb_secrets.tokens import TokenCache, TokenKey

OAUTH2 = "oauth2-client-credentials"
# A cached access token is dropped this long before the upstream says it expires.
TOKEN_EXPIRY_MARGIN = timedelta(seconds=60)


class TokenExchangeFailed(EgressNotSent):
    """The token endpoint did not issue an access token, so the target was
    never called. The message never carries a credential or the response."""


@dataclass(frozen=True)
class SecretVersion:
    """The secret version a call opened, which its cached tokens belong to."""

    installation_id: str
    team_id: str
    secret_id: str
    version: int


@dataclass(frozen=True)
class BrokeredCall:
    """The handled result, the request URL as it may be recorded, and every
    value this call placed, for redaction elsewhere."""

    result: BrokeredResult
    recorded_url: str
    known: KnownValues = field(repr=False)


def _required(values: Mapping[str, str], name: str) -> str:
    value = values.get(name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"the secret has no {name}")
    return value


async def _exchange(
    egress: Egress,
    *,
    client_id: str,
    client_secret: str,
    kind_params: Mapping[str, str],
    destination: Destination,
) -> tuple[str, int | None]:
    """An access token and its lifetime in seconds, from the token endpoint."""
    form = {"grant_type": "client_credentials", "scope": kind_params["scope"]}
    injected: list[tuple[str, str]] = []
    if kind_params["client_auth"] == "client_secret_basic":
        pair = f"{quote_plus(client_id)}:{quote_plus(client_secret)}"
        injected.append(("Authorization", "Basic " + base64.b64encode(pair.encode()).decode()))
    elif kind_params["client_auth"] == "client_secret_post":
        form |= {"client_id": client_id, "client_secret": client_secret}
    else:
        raise ValueError("client_auth must be client_secret_basic or client_secret_post")
    try:
        response = await egress.send(
            "POST",
            kind_params["token_endpoint"],
            destination,
            header_rules=HeaderRules(
                injected=[name for name, _ in injected],
                amz_allowed=(),
                is_credential=is_credential_shaped_value,
            ),
            headers=[
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("Accept", "application/json"),
            ],
            injected=injected,
            body=urlencode(form).encode(),
        )
    except (EgressNotSent, EgressOutcomeUnknown) as error:
        raise TokenExchangeFailed(f"the token endpoint could not be reached ({type(error).__name__})") from None
    if response.status != 200 or response.truncated:
        raise TokenExchangeFailed(f"the token endpoint answered {response.status}")
    try:
        answer = json.loads(response.body)
    except ValueError:
        raise TokenExchangeFailed("the token endpoint did not answer JSON") from None
    token = answer.get("access_token") if isinstance(answer, dict) else None
    if not isinstance(token, str) or not token:
        raise TokenExchangeFailed("the token endpoint issued no access token")
    lifetime = answer.get("expires_in")
    return token, lifetime if isinstance(lifetime, int) and not isinstance(lifetime, bool) else None


async def _oauth2_injection(
    egress: Egress,
    *,
    value: Mapping[str, str],
    kind_params: Mapping[str, str],
    secret_ref: str,
    url: str,
    destination: Destination | None,
    tokens: TokenCache | None,
    secret: SecretVersion | None,
) -> Injection:
    client_id = _required(value, "client_id")
    client_secret = _required(value, "client_secret")
    for name in ("token_endpoint", "client_auth", "scope"):
        _required(kind_params, name)
    if destination is None or tokens is None or secret is None:
        raise ValueError("an OAuth2 secret needs its token destination, token cache and version")
    key = TokenKey(
        installation_id=secret.installation_id,
        team_id=secret.team_id,
        secret_id=secret.secret_id,
        version=secret.version,
        token_endpoint=kind_params["token_endpoint"],
        scope=kind_params["scope"],
    )
    token = await tokens.get(key)
    if token is None:
        token, lifetime = await _exchange(
            egress,
            client_id=client_id,
            client_secret=client_secret,
            kind_params=kind_params,
            destination=destination,
        )
        if lifetime is not None and lifetime > TOKEN_EXPIRY_MARGIN.total_seconds():
            expires_at = datetime.now(UTC) + timedelta(seconds=lifetime) - TOKEN_EXPIRY_MARGIN
            await tokens.put(key, token, expires_at)
    injection = inject("bearer", {"value": token}, {}, secret_ref=secret_ref, url=url)
    injection.known.add_basic(secret_ref, client_id, client_secret)
    # client_secret_basic form-encodes the pair before base64 (RFC 6749 §2.3.1).
    injection.known.add(secret_ref, f"{quote_plus(client_id)}:{quote_plus(client_secret)}")
    return injection


async def broker(
    egress: Egress,
    *,
    method: str,
    url: str,
    destination: Destination,
    headers: Sequence[tuple[str, str]],
    body: bytes,
    kind: str,
    value: Mapping[str, str],
    kind_params: Mapping[str, str],
    secret_ref: str,
    max_bytes: int,
    projection: Sequence[str] | None,
    token_issuing: bool,
    amz_allowed: Sequence[str] = (),
    bounds: Bounds | None = None,
    token_destination: Destination | None = None,
    tokens: TokenCache | None = None,
    secret: SecretVersion | None = None,
) -> BrokeredCall:
    """Send one request with ``value`` injected; ``headers`` are the agent's.

    An OAuth2 secret also needs ``token_destination`` (its token endpoint's
    destination), ``tokens`` and ``secret``, the version whose tokens the
    cache keeps. Raises the guard's ``EgressRefused`` before sending, and its
    ``EgressNotSent`` (including :class:`TokenExchangeFailed`) or
    ``EgressOutcomeUnknown`` when the exchange fails.
    """
    if kind == OAUTH2:
        injection = await _oauth2_injection(
            egress,
            value=value,
            kind_params=kind_params,
            secret_ref=secret_ref,
            url=url,
            destination=token_destination,
            tokens=tokens,
            secret=secret,
        )
    else:
        injection = inject(
            kind,
            value,
            kind_params,
            secret_ref=secret_ref,
            url=url,
            method=method,
            body=body,
            headers=headers,
        )
    response = await egress.send(
        method,
        injection.url,
        destination,
        header_rules=HeaderRules(
            injected=injection.injected_names,
            amz_allowed=amz_allowed,
            is_credential=is_credential_shaped_value,
        ),
        headers=headers,
        injected=injection.headers,
        body=body,
        bounds=bounds,
    )
    result = handle_response(
        status=response.status,
        headers=response.headers,
        body=response.body,
        truncated=response.truncated,
        max_bytes=max_bytes,
        projection=projection,
        known=injection.known,
        token_issuing=token_issuing,
    )
    return BrokeredCall(result=result, recorded_url=injection.recorded_url, known=injection.known)
