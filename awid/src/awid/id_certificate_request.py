"""The child CSR wire in docs/id-certificates.md §6, as aw reads and writes it.

Pure: no I/O. Key possession is not admission. Callers still bind the
invitation and resolve an existing global subject's current key before
authorizing parent issuance, and verify a response's chain on current status
before relying on it.
"""
from __future__ import annotations

import base64
import json
import re
from typing import Any, Awaitable, Callable

from awid.id_certificates import (
    ID_CHAIN_MAX_BYTES,
    IDCertificateError,
    _bundle_shape,
    _canonical,
    _decode_b64,
    _domain,
    _id,
    _shape,
    _signature_by,
    verify_ed25519,
)

_PREFIX = b"aweb.id-certificate-request/1\n"
_MAX_BYTES = 8192
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_FIELDS = {
    "v", "type", "request_id", "operation", "id", "domain", "parent", "kind",
    "subject_key", "invitation_id", "old_certificate",
}


def _is_uuid(value: Any) -> bool:
    return isinstance(value, str) and _UUID.fullmatch(value) is not None


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise IDCertificateError("invalid_json")
        result[key] = value
    return result


def _reject_number(_: str) -> Any:
    raise IDCertificateError("invalid_shape")


def id_certificate_request_signing_bytes(request: dict[str, Any]) -> bytes:
    """The exact bytes the child signs with its subject key."""
    return _PREFIX + _canonical(request)


async def build_id_certificate_request(
    *,
    request_id: str,
    invitation_id: str,
    id: str,
    domain: str,
    parent: dict[str, Any],
    kind: str,
    subject_key: str,
    signer: Callable[[bytes], tuple[str, bytes] | Awaitable[tuple[str, bytes]]],
) -> bytes:
    """The signed request file for a first certificate, as ``aw id parent request`` writes it.

    ``invitation_id``, ``domain`` and ``parent`` are what the parent's
    invitation fixed: ``{"kind": "identity", "id": ...}``, or
    ``{"kind": "namespace", "id": domain}`` for the namespace root.
    ``request_id`` is the caller's: a retry resends the bytes returned here,
    never a rebuilt request. The request is checked as the receiver checks it
    before ``signer`` is asked, once, to sign its signing bytes with
    ``subject_key``; a malformed answer raises IDCertificateError('invalid_signature').
    """
    # A snapshot, so the bytes signed are exactly the request returned.
    request = json.loads(_canonical({
        "v": 1, "type": "aweb.id-certificate-request", "request_id": request_id, "operation": "issue",
        "id": id, "domain": domain, "parent": parent, "kind": kind, "subject_key": subject_key,
        "invitation_id": invitation_id, "old_certificate": None,
    }))
    _request_shape(request)
    signature = await _signature_by(signer, id_certificate_request_signing_bytes(request), subject_key)
    return _canonical({"request": request, "signature": base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")})


def _decode(raw: bytes) -> Any:
    """Strict canonical JSON within the file cap, refused with the Go reader's codes."""
    if not isinstance(raw, bytes):
        raise IDCertificateError("invalid_shape")
    if len(raw) > _MAX_BYTES:
        raise IDCertificateError("bundle_too_large")
    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_pairs,
            parse_float=_reject_number, parse_constant=_reject_number,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise IDCertificateError("invalid_json") from exc
    except IDCertificateError:
        raise
    except ValueError as exc:
        raise IDCertificateError("invalid_shape") from exc
    if _canonical(value) != raw:
        raise IDCertificateError("noncanonical_json")
    return value


def parse_id_certificate_request(raw: bytes) -> dict[str, Any]:
    """Validate canonical CSR shape and the subject_key's strict Ed25519 proof.

    Returns the signed ``{request, signature}`` wrapper. Does no I/O, stable-ID
    derivation, invitation authorization or current registry-binding check.
    Refusals use the same IDCertificateError codes as the Go request reader.
    """
    signed = _decode(raw)
    if type(signed) is not dict or set(signed) != {"request", "signature"}:
        raise IDCertificateError("invalid_shape")
    request = signed["request"]
    _request_shape(request)
    signature = _decode_b64(signed["signature"])
    if len(signature) != 64:
        raise IDCertificateError("invalid_encoding")
    verify_ed25519(request["subject_key"], id_certificate_request_signing_bytes(request), signature)
    return signed


def _request_shape(request: Any) -> None:
    if type(request) is not dict or set(request) != _FIELDS:
        raise IDCertificateError("invalid_shape")
    if (type(request["v"]) is not int or request["v"] != 1
            or request["type"] != "aweb.id-certificate-request"
            or not _is_uuid(request["request_id"])):
        raise IDCertificateError("invalid_shape")
    if request["kind"] not in ("human", "agent"):
        raise IDCertificateError("invalid_kind")
    _id(request["id"])
    if request["kind"] == "human" and not request["id"].startswith("did:aw:"):
        raise IDCertificateError("invalid_shape")
    _domain(request["domain"])
    parent = request["parent"]
    if type(parent) is not dict or set(parent) != {"kind", "id"}:
        raise IDCertificateError("invalid_shape")
    if parent["kind"] == "identity":
        _id(parent["id"])
    elif parent["kind"] == "namespace":
        _domain(parent["id"])
        if parent["id"] != request["domain"]:
            raise IDCertificateError("domain_mismatch")
    else:
        raise IDCertificateError("invalid_shape")
    subject = request["subject_key"]
    _id(subject, key_only=True)
    if request["id"].startswith("did:key:") and request["id"] != subject:
        raise IDCertificateError("invalid_shape")
    if request["operation"] == "issue":
        if not _is_uuid(request["invitation_id"]) or request["old_certificate"] is not None:
            raise IDCertificateError("invalid_shape")
    elif request["operation"] == "resign":
        if (request["invitation_id"] is not None or request["kind"] != "agent"
                or not request["id"].startswith("did:key:")):
            raise IDCertificateError("invalid_shape")
        _shape(request["old_certificate"])
    else:
        raise IDCertificateError("invalid_shape")


def parse_id_certificate_response(raw: bytes, *, request: bytes) -> dict[str, Any]:
    """Read the parent's response file against the request file it answers.

    Checks what ``aw id parent import`` checks before any registry read: the
    strict response shape and every certificate's signature under its own
    issuer_key, the request's own validity, the same request_id, and a leaf
    with exactly the requested id, domain, parent and kind
    (``request_binding_mismatch``). Returns ``{v, request_id, chain}``. The
    chain still needs verify_id_chain on current status, and a did:aw leaf
    its own registration, before it carries any authority.
    """
    response = _decode(raw)
    if (type(response) is not dict or set(response) != {"v", "request_id", "chain"}
            or type(response["v"]) is not int or response["v"] != 1
            or not _is_uuid(response["request_id"]) or type(response["chain"]) is not dict):
        raise IDCertificateError("invalid_shape")
    if len(_canonical(response["chain"])) > ID_CHAIN_MAX_BYTES:
        raise IDCertificateError("bundle_too_large")
    _bundle_shape(response["chain"])
    asked = parse_id_certificate_request(request)["request"]
    leaf = response["chain"]["certificates"][-1]["certificate"]
    if response["request_id"] != asked["request_id"] or any(
        leaf[field] != asked[field] for field in ("id", "domain", "parent", "kind")
    ):
        raise IDCertificateError("request_binding_mismatch")
    return response
