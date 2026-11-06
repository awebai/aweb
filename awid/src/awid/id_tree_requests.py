"""The identity-tree registry requests, byte for byte.

Paths, bodies and covering-v2 payloads for registration, revocation and signed
namespace rotation. RegistryClient sends exactly these bytes, and a host that
holds a signing key can rebuild them to check that a payload is the request it
intends before it signs. Pure: no I/O and no server framework.
"""

from __future__ import annotations

import hashlib
from typing import Any

from awid.signing import canonical_json_bytes

CONTROLLER_REQUEST_TYPE = "aweb.awid-controller-request"

REGISTER_PATH = "/v1/id-certificates/register"
REVOKE_PATH = "/v1/id-certificates/revoke"
REGISTER_OPERATION = "register_id_certificate"
REVOKE_OPERATION = "revoke_id_certificate"
ROTATE_OPERATION = "rotate_namespace_controller"


def rotate_path(domain: str) -> str:
    return f"/v1/namespaces/{domain}/rotate"


def register_body(signed_leaf: dict[str, Any], *, expected_head: str | None, invitation_id: str | None) -> bytes:
    """The registration body for ``signed_leaf``, the certificate and its signature."""
    return canonical_json_bytes(
        {"certificate": signed_leaf, "expected_head": expected_head, "invitation_id": invitation_id}
    )


def revoke_body(domain: str, id: str, *, expected_head: str | None, effective_from: str | None) -> bytes:
    return canonical_json_bytes(
        {"domain": domain, "id": id, "expected_head": expected_head, "effective_from": effective_from}
    )


def rotate_claims(*, from_seq: int, previous_did_key: str, new_did_key: str) -> dict[str, Any]:
    """The rotation claims, carried in both the body and the covering payload."""
    return {"from_seq": from_seq, "previous_did_key": previous_did_key, "new_did_key": new_did_key}


def rotate_body(domain: str, claims: dict[str, Any]) -> bytes:
    return canonical_json_bytes({"domain": domain, "operation": ROTATE_OPERATION, **claims})


def covering_payload(
    *,
    aud: str,
    path: str,
    domain: str,
    operation: str,
    body: bytes,
    timestamp: str,
    claims: dict[str, Any] | None = None,
) -> bytes:
    """The covering-v2 payload every signer of a POST of ``body`` to ``path`` signs.

    ``aud`` is the canonical origin of the registry the request is sent to.
    """
    return canonical_json_bytes({
        **(claims or {}),
        "v": 2,
        "type": CONTROLLER_REQUEST_TYPE,
        "aud": aud,
        "method": "POST",
        "path": path,
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "timestamp": timestamp,
        "domain": domain,
        "operation": operation,
    })
