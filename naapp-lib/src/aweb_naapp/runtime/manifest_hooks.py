"""Matched request evidence and caller-transaction manifest hook recording.

Only the request commitment survives preparation. Raw bytes are bounded and
cached for authentication/dispatch, never copied into an event or a repr.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from fastapi import HTTPException, Request

from aweb_naapp.hooks.commitment import CommitmentContext, CommitmentKey, RequestBytes
from aweb_naapp.runtime.authorization import DeclaredTool, Grant
from aweb_naapp.runtime.team_auth import Principal, raw_request_target, signed_payload_bytes


@dataclass(frozen=True, repr=False)
class ManifestEvidence:
    principal: Principal
    tool: DeclaredTool
    grant: Grant
    context: CommitmentContext
    commitment: str
    occurred_at: datetime
    actor: dict[str, Any]
    trace_id: str | None


async def bounded_body(request: Request, maximum: int) -> None:
    """Consume at most the configured bound, leaving Starlette's body cache.

    An early/oversize/disconnected request has no complete body and therefore
    no attributable event. Never drain it to make it attributable.
    """
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > maximum:
            raise HTTPException(status_code=413, detail={"code": "request_too_large"})
        body.extend(chunk)
    # Request.body() and later parameter parsing use this same immutable body.
    request._body = bytes(body)


def prepare(
    request: Request,
    *,
    key: CommitmentKey,
    app_id: str,
    principal: Principal,
    tool: DeclaredTool,
    grant: Grant,
) -> ManifestEvidence:
    """Called only after authentication and B1's matched, fresh grant checks."""
    if grant.installation_id is None or grant.generation is None:
        raise HTTPException(status_code=503, detail={"code": "installation_identity_required"})
    context = CommitmentContext(
        app_id=app_id,
        team_id=principal.team_id,
        installation_id=grant.installation_id,
        generation=grant.generation,
        tool=tool.name,
    )
    inbound = RequestBytes(
        method=request.method.upper(),
        raw_target=raw_request_target(request).encode("ascii"),
        content_types=tuple(
            value
            for name, value in request.scope.get("headers", ())
            if name.lower() == b"content-type"
        ),
        body=request._body,
    )
    actor: dict[str, Any] = {
        "authority_mode": "team_cert",
        "attestations": [],
        "did_key": principal.did_key,
        "certificate_id": principal.certificate_id,
        "alias": principal.alias,
    }
    if principal.did_aw_registry_verified and principal.did_aw is not None:
        actor["did_aw"] = principal.did_aw
    # This is read only after the authentication layer verified those bytes.
    trace_id = json.loads(signed_payload_bytes(request)).get("trace_id")
    return ManifestEvidence(
        principal=principal,
        tool=tool,
        grant=grant,
        context=context,
        commitment=key.request(context, inbound),
        occurred_at=datetime.now(UTC),
        actor=actor,
        trace_id=trace_id if isinstance(trace_id, str) else None,
    )
