"""One brokered call: inject the secret, send through the egress guard, and
handle the response (secrets §7.3–§7.6).

The guard matches the URL and method against the destination, refuses the
agent's headers that §7.4 forbids (the always-rejected names, any name this
secret injects, credential-shaped values) and resolves and pins the address,
all before any byte is sent. So a request for any other host never carries
the credential. The injected headers go out only as the guard's injected
headers, and every injected value is redacted from what comes back.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from aweb_naapp.egress import Bounds, Destination, Egress, HeaderRules

from aweb_secrets.credential_shapes import is_credential_shaped_value
from aweb_secrets.injection import inject
from aweb_secrets.responses import BrokeredResult, handle_response


@dataclass(frozen=True)
class BrokeredCall:
    """The handled result, and the request URL as it may be recorded."""

    result: BrokeredResult
    recorded_url: str


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
) -> BrokeredCall:
    """Send one request with ``value`` injected; ``headers`` are the agent's.

    Raises the guard's ``EgressRefused`` before sending, and its
    ``EgressNotSent`` or ``EgressOutcomeUnknown`` when the exchange fails.
    """
    injection = inject(kind, value, kind_params, secret_ref=secret_ref, url=url)
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
    return BrokeredCall(result=result, recorded_url=injection.recorded_url)
