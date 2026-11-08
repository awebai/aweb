"""Apply the shared ID-tree verifier after original request authentication."""

from __future__ import annotations

import logging
import json
from typing import Any

from awid.id_certificates import (
    IDCertificateError,
    decode_id_chain_header,
    request_disposition,
)
from fastapi import HTTPException, Request

from aweb.identity_binding import IdentityBinding
from aweb.human_kind import observe_identity_kind, unverified_kind

logger = logging.getLogger(__name__)


async def authenticate_id_chain(request: Request, binding: IdentityBinding, *, registry_client=None) -> dict[str, Any]:
    """Use only the already-verified subject and its fresh enrollment carrier.

    The caller must finish its original authentication first. No address/team
    inference, ordinary resolve_key read, extra enrollment cache or uncached
    tree fetch is allowed here. A missing cache capability gives unavailable
    evidence; the shared disposition decides whether this subject may act.
    """
    subject = {'id': binding.did_aw or binding.did_key, 'did_key': binding.did_key}
    try:
        headers = request.headers.getlist('X-AWID-ID-Chain')
        if len(headers) > 1:
            raise IDCertificateError('invalid_shape')
        bundle = decode_id_chain_header(headers[0]) if headers else None
        client = registry_client if registry_client is not None else getattr(request.app.state, 'awid_registry_client', None)
        observation = await observe_identity_kind(client, binding, bundle)
        request.state.identity_kind = observation
        result = dict(observation.result)
    except IDCertificateError as exc:
        result = unverified_kind(exc.code)
    request.state.id_chain_result = result
    if request_disposition(result, subject=subject, original_auth_passed=True) == 'refuse':
        logger.warning('ID-tree request refused: %s', result['reason'])
        raise HTTPException(status_code=503 if result['outcome'] == 'unavailable' else 403,
                            detail=result['reason'])
    request.state.id_chain = bundle
    return result


def stored_id_chain(value):
    """Decode the optional JSONB carrier; consumers verify it on current evidence."""
    return json.loads(value) if isinstance(value, str) else value
