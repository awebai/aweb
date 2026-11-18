"""Covering controller HTTP envelopes; legacy acceptance is rollout-only."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
from dataclasses import dataclass

from fastapi import HTTPException, Request
from fastapi.routing import APIRoute

from awid.dns_auth import (
    enforce_timestamp_skew,
    parse_didkey_auth,
    require_timestamp,
    verify_signed_json_request,
)
from awid.id_tree_requests import CONTROLLER_REQUEST_TYPE
from awid.log import canonical_server_origin
from awid.request_auth import raw_request_target as raw_controller_request_target
from awid.signing import canonical_json_bytes, verify_did_key_signature

CONTROLLER_OPERATIONS = frozenset(
    {
        "register",
        "update_namespace",
        "rotate_controller",
        "delete_namespace",
        "authorize_subdomain_registration",
        "authorize_subdomain_rotation",
        "create_team",
        "delete_team",
        "rotate_team_key",
        "set_team_visibility",
        "register_certificate",
        "revoke_certificate",
        "publish_team_custodian",
        "publish_member_custody",
        "publish_member_person",
        "register_address",
        "update_address",
        "delete_address",
        "reassign_address",
        "register_id_certificate",
        "revoke_id_certificate",
        "rotate_namespace_controller",
        "read_team",
    }
)
logger = logging.getLogger(__name__)

# Accepted-authentication metrics, one event per signed-request form.
LEGACY_CONTROLLER_AUTH_EVENT = "awid_legacy_controller_auth_accepted"
COVERING_CONTROLLER_AUTH_EVENT = "awid_controller_auth_accepted"
PATH_SIGNED_READ_EVENT = "awid_path_signed_read_accepted"
_FORMS = {
    LEGACY_CONTROLLER_AUTH_EVENT: "legacy",
    COVERING_CONTROLLER_AUTH_EVENT: "covering",
    PATH_SIGNED_READ_EVENT: "path",
}
# Distinct aw versions counted per process; later ones count as aw/other. Any
# key can sign an accepted read, so the client label must not grow without bound.
MAX_TRACKED_AW_VERSIONS = 16
# aw's User-Agent: aw/<version> (<os>/<arch>), cli/go/cmd/aw/main.go cliUserAgent.
_AW_USER_AGENT = re.compile(
    r"aw/(\d{1,6}\.\d{1,6}\.\d{1,6}(?:-[0-9A-Za-z]{1,16}(?:\.[0-9A-Za-z]{1,16}){0,3})?) \([0-9a-z_]{1,16}/[0-9a-z_]{1,16}\)"
)


def client_family(user_agent: str | None) -> str:
    """The sending client for usage metrics: aw with its version, the Python
    client, or other. Never the raw User-Agent."""
    match = _AW_USER_AGENT.fullmatch(user_agent or "")
    if match:
        return "aw/" + match.group(1)
    if (user_agent or "").startswith("python-httpx/"):
        return "python-httpx"
    return "other"


def _tracked_client(state, client: str) -> str:
    """client, or aw/other once MAX_TRACKED_AW_VERSIONS aw versions are tracked."""
    if not client.startswith("aw/"):
        return client
    tracked = getattr(state, "tracked_aw_versions", None)
    if tracked is None:
        tracked = set()
        state.tracked_aw_versions = tracked
    if client in tracked:
        return client
    if len(tracked) >= MAX_TRACKED_AW_VERSIONS:
        return "aw/other"
    tracked.add(client)
    return client


def record_accepted_auth(request: Request, event: str, operation: str) -> None:
    """Note a verified proof; ControllerAuthRoute counts it if the route succeeds."""
    pending = getattr(request.state, "accepted_auth", None)
    if pending is None:
        pending = set()
        request.state.accepted_auth = pending
    pending.add((event, operation))


@dataclass(frozen=True)
class ControllerProof:
    """The exact bytes a controller signed for this request, its key and signature."""

    signer_did_key: str
    signed_payload: bytes
    signature: str


def verified_controller_proof(request: Request) -> ControllerProof:
    """The proof verify_controller_json_request accepted for this request."""
    proof = getattr(request.state, "controller_proof", None)
    if not isinstance(proof, ControllerProof):
        raise RuntimeError("no verified controller proof for this request")
    return proof


async def verify_controller_json_request(
    request: Request,
    *,
    payload_dict: dict[str, str],
    authorization_header: str = "Authorization",
    timestamp_header: str = "X-AWEB-Timestamp",
    signed_payload_header: str = "X-AWEB-Signed-Payload",
) -> str:
    """Verify exact covering bytes, or the separately measured legacy form.

    Route helpers supply the closed operation and its existing contextual
    claims. Only the route's success records usage; proof alone is not authority.
    The accepted proof is kept on ``request.state`` for routes that store it.
    """
    operation = payload_dict["operation"]
    if operation not in CONTROLLER_OPERATIONS:
        raise ValueError("unregistered controller operation")
    supplied = request.headers.get(signed_payload_header)
    if supplied is None:
        did = verify_signed_json_request(
            request,
            payload_dict=payload_dict,
            authorization_header=authorization_header,
            timestamp_header=timestamp_header,
        )
        record_accepted_auth(request, LEGACY_CONTROLLER_AUTH_EVENT, operation)
        _, signature = parse_didkey_auth(request.headers.get(authorization_header))
        timestamp = require_timestamp(request, header_name=timestamp_header)
        request.state.controller_proof = ControllerProof(
            did,
            canonical_json_bytes(payload_dict | {"timestamp": timestamp}),
            signature,
        )
        return did

    did, signature = parse_didkey_auth(request.headers.get(authorization_header))
    timestamp = require_timestamp(request, header_name=timestamp_header)
    enforce_timestamp_skew(timestamp)
    try:
        if len(supplied) > 16384 or not re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", supplied):
            raise ValueError("invalid encoding")
        raw = base64.b64decode(
            supplied + "=" * (-len(supplied) % 4), altchars=b"-_", validate=True
        )
        payload = json.loads(raw)
        if not isinstance(payload, dict) or not isinstance(payload.get("aud"), str):
            raise ValueError("invalid envelope")
        audience = canonical_server_origin(payload["aud"])
    except (ValueError, TypeError, UnicodeError) as exc:
        raise HTTPException(
            status_code=401, detail="Invalid AWID controller envelope"
        ) from exc

    origins = getattr(request.app.state, "awid_public_origins", ())
    allowed = {canonical_server_origin(value) for value in origins}
    if not allowed:
        raise HTTPException(
            status_code=503,
            detail="AWID controller public origins are not configured: set AWID_PUBLIC_ORIGINS to the "
            "comma-separated public origins clients write to",
        )
    if audience not in allowed:
        raise HTTPException(
            status_code=401, detail="AWID controller audience is not allowed"
        )
    body = await request.body()
    expected = {
        **payload_dict,
        "timestamp": timestamp,
        "v": 2,
        "type": CONTROLLER_REQUEST_TYPE,
        "aud": audience,
        "method": request.method.upper(),
        "path": raw_controller_request_target(request),
        "body_sha256": hashlib.sha256(body).hexdigest(),
    }
    if raw != canonical_json_bytes(expected):
        raise HTTPException(
            status_code=401, detail="AWID controller envelope does not match request"
        )
    try:
        verify_did_key_signature(did_key=did, payload=raw, signature_b64=signature)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="Invalid signature") from exc
    request.state.controller_proof = ControllerProof(did, raw, signature)
    record_accepted_auth(request, COVERING_CONTROLLER_AUTH_EVENT, operation)
    return did


class ControllerAuthRoute(APIRoute):
    """Count successful signed requests by form, operation and client family,
    never raw identifiers.

    The existing AWID metric convention is a per-process aggregate, reported at
    one and powers of two. Embedding operators ingest these structured metrics;
    this adds no public metrics endpoint or telemetry dependency.
    """

    def get_route_handler(self):
        handler = super().get_route_handler()

        async def measured(request: Request):
            response = await handler(request)
            if response.status_code < 400:
                counts = getattr(request.app.state, "controller_auth_counts", None)
                if counts is None:
                    counts = {}
                    request.app.state.controller_auth_counts = counts
                client = _tracked_client(
                    request.app.state, client_family(request.headers.get("user-agent"))
                )
                for event, operation in sorted(
                    getattr(request.state, "accepted_auth", ())
                ):
                    key = (event, operation, client)
                    count = counts.get(key, 0) + 1
                    counts[key] = count
                    if count == 1 or count & (count - 1) == 0:
                        logger.info(
                            "event=%s metric=%s value=%s operation=%s client=%s form=%s",
                            event,
                            event,
                            count,
                            operation,
                            client,
                            _FORMS[event],
                        )
            return response

        return measured
