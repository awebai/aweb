"""Apply the shared ID-tree verifier after original request authentication."""

from __future__ import annotations

import asyncio
import json
import logging
from time import monotonic
from types import SimpleNamespace
from typing import Any

from awid.id_certificates import (
    IDCertificateError,
    decode_id_chain_header,
    request_disposition,
)
from fastapi import HTTPException, Request

from aweb.application_state import (
    RegistryClientUnavailable,
    application_registry_client,
    native_application_state,
)
from aweb.identity_binding import IdentityBinding
from aweb.human_kind import observe_identity_kind, unverified_kind

logger = logging.getLogger(__name__)
_CHAIN_UNAVAILABLE_TTL = 5
_CHAIN_BACKOFF_LIMIT = 4096
SUPERSEDED_ID_CHAIN_RECOVERY = (
    "Run aw id parent refresh from this identity's home to install the current "
    "registered chain and its ancestors, then reconnect."
)


def read_id_chain_header(request: Request) -> dict[str, Any] | None:
    headers = request.headers.getlist("X-AWID-ID-Chain")
    if len(headers) > 1:
        raise IDCertificateError("invalid_shape")
    return decode_id_chain_header(headers[0]) if headers else None


async def _observe_optional_chain(
    request: Request,
    client,
    binding: IdentityBinding,
    bundle: dict[str, Any] | None,
    deadline: float | None,
):
    registry_url = getattr(client, "registry_url", None)
    if not isinstance(registry_url, str) or not registry_url.strip():
        raise RegistryClientUnavailable()
    read_evidence = getattr(client, "id_chain_evidence", None)
    state = native_application_state(request.app.state)
    backoff = getattr(state, "id_chain_status_backoff", None)
    if backoff is None:
        backoff = state.id_chain_status_backoff = {}
    attempted = None
    failed = False

    async def read_status(bundle, subject, *, domain):
        nonlocal attempted
        key = (registry_url, domain)
        if backoff.get(key, 0) > monotonic():
            return await read_evidence(bundle, subject, domain=domain, refresh=False)
        attempted = key
        return await read_evidence(bundle, subject, domain=domain)

    reader = (
        SimpleNamespace(id_chain_evidence=read_status)
        if callable(read_evidence)
        else client
    )
    try:
        async with asyncio.timeout_at(deadline):
            observation = await observe_identity_kind(reader, binding, bundle)
        failed = observation.result["outcome"] == "unavailable"
        return observation
    except TimeoutError:
        failed = True
        raise
    finally:
        if failed and attempted is not None:
            backoff.pop(attempted, None)
            backoff[attempted] = monotonic() + _CHAIN_UNAVAILABLE_TTL
            if len(backoff) > _CHAIN_BACKOFF_LIMIT:
                del backoff[next(iter(backoff))]


async def authenticate_id_chain(
    request: Request,
    binding: IdentityBinding,
    *,
    registry_client=None,
    allow_unavailable: bool = False,
    deadline: float | None = None,
) -> dict[str, Any]:
    """Use only the already-verified subject and its fresh enrollment carrier.

    The caller must finish its original authentication first. No address/team
    inference, ordinary resolve_key read, extra enrollment cache or uncached
    tree fetch is allowed here. A missing cache capability gives unavailable
    evidence; the shared disposition decides whether this subject may act.
    """
    subject = {"id": binding.did_aw or binding.did_key, "did_key": binding.did_key}
    try:
        bundle = read_id_chain_header(request)
        client = (
            registry_client
            if registry_client is not None
            else application_registry_client(request.app.state)
        )
        if allow_unavailable:
            observation = await _observe_optional_chain(
                request, client, binding, bundle, deadline
            )
        else:
            observation = await observe_identity_kind(client, binding, bundle)
        request.state.identity_kind = observation
        result = dict(observation.result)
    except IDCertificateError as exc:
        result = unverified_kind(exc.code)
    request.state.id_chain_result = result
    if allow_unavailable and result["outcome"] == "unavailable":
        request.state.identity_kind = None
        request.state.id_chain = None
        return result
    if (
        request_disposition(result, subject=subject, original_auth_passed=True)
        == "refuse"
    ):
        logger.warning("ID-tree request refused: %s", result["reason"])
        raise HTTPException(
            status_code=503 if result["outcome"] == "unavailable" else 403,
            detail=result["reason"],
        )
    request.state.id_chain = bundle
    return result


def stored_id_chain(value):
    """Decode the optional JSONB carrier; consumers verify it on current evidence."""
    return json.loads(value) if isinstance(value, str) else value
