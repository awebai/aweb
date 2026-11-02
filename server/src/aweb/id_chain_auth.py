"""Apply the shared ID-tree verifier after original request authentication."""

from __future__ import annotations

import logging
import json
from typing import Any

from awid.id_certificates import (
    IDCertificateError,
    decode_id_chain_header,
    request_disposition,
    status_request,
    verify_id_chain,
)
from fastapi import HTTPException, Request

from aweb.identity_binding import IdentityBinding

logger = logging.getLogger(__name__)


def _unverified(reason: str) -> dict[str, Any]:
    unavailable = reason in ('evidence_unavailable', 'status_expired')
    return {'outcome': 'unavailable' if unavailable else 'unknown', 'human_id': None,
            'identity_valid': None if unavailable or reason == 'unregistered_identity' else False,
            'kind': None, 'reason': reason}


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
        enrollment = binding.id_tree
        if binding.did_aw and enrollment is None:
            result = _unverified('evidence_unavailable')
        elif binding.did_aw and not enrollment.enrolled and bundle is None:
            result = _unverified('unregistered_identity')
        else:
            domain = enrollment.domain if binding.did_aw and enrollment.enrolled else None
            plan = status_request(bundle, subject, domain=domain)
            evidence = None
            if plan is not None:
                client = registry_client if registry_client is not None else getattr(request.app.state, 'awid_registry_client', None)
                cached_evidence = getattr(client, 'id_chain_evidence', None)
                if callable(cached_evidence):
                    try:
                        evidence = await cached_evidence(bundle, subject, domain=plan['domain'])
                    except Exception:
                        logger.warning('ID-tree cached evidence failed', exc_info=True)
            result = verify_id_chain(bundle, subject=subject, evidence=evidence, domain=domain)
    except IDCertificateError as exc:
        result = _unverified(exc.code)
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
