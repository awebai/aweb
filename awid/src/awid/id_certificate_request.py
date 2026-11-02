"""Pure reader for the existing child CSR wire in docs/id-certificates.md §6.

Key possession is not admission. Callers still bind the invitation and resolve
an existing global subject's current key before authorizing parent issuance.
"""
from __future__ import annotations

import json
import re
from typing import Any

from awid.id_certificates import (
    IDCertificateError,
    _canonical,
    _decode_b64,
    _domain,
    _id,
    _shape,
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


def parse_id_certificate_request(raw: bytes) -> dict[str, Any]:
    """Validate canonical CSR shape and the subject_key's strict Ed25519 proof.

    Returns the signed ``{request, signature}`` wrapper. Does no I/O, stable-ID
    derivation, invitation authorization or current registry-binding check.
    Refusals use the same IDCertificateError codes as the Go request reader.
    """
    if not isinstance(raw, bytes):
        raise IDCertificateError("invalid_shape")
    if len(raw) > _MAX_BYTES:
        raise IDCertificateError("bundle_too_large")
    try:
        signed = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_pairs,
            parse_float=_reject_number, parse_constant=_reject_number,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise IDCertificateError("invalid_json") from exc
    except IDCertificateError:
        raise
    except ValueError as exc:
        raise IDCertificateError("invalid_shape") from exc
    if _canonical(signed) != raw:
        raise IDCertificateError("noncanonical_json")
    if type(signed) is not dict or set(signed) != {"request", "signature"}:
        raise IDCertificateError("invalid_shape")
    request = signed["request"]
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
    signature = _decode_b64(signed["signature"])
    if len(signature) != 64:
        raise IDCertificateError("invalid_encoding")
    verify_ed25519(subject, _PREFIX + _canonical(request), signature)
    return signed
