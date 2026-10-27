"""Pure codecs for docs/id-certificates.md; no registry or authentication I/O.

A certificate signature alone establishes neither issuance authority nor current
validity. The chain verifier must check independently supplied authority/status.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from typing import Any

from nacl.bindings import crypto_core_ed25519_is_valid_point
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from awid.did import did_from_public_key, public_key_from_did, validate_stable_id
from awid.utc_timestamps import parse_utc_seconds

ID_CERTIFICATE_PREFIX = b"aweb.id-certificate/1\n"
ID_CHAIN_MAX_DEPTH = 8
ID_CHAIN_MAX_BYTES = 6144
ID_CHAIN_HEADER_MAX_BYTES = 8192
_FIELDS = frozenset({"v", "type", "id", "domain", "parent", "kind", "issuer_key", "issued_at"})
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_B64URL = re.compile(r"[A-Za-z0-9_-]+")
_BASE58 = re.compile(r"[1-9A-HJ-NP-Za-km-z]+")
_ED25519_ORDER = 2**252 + 27742317777372353535851937790883648493


class IDCertificateError(ValueError):
    """A contract refusal; ``code`` is stable, prose is diagnostic only."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _canonical(value: Any) -> bytes:
    def check(node: Any) -> None:
        if node is None or type(node) in (bool, int):
            return
        if type(node) is str:
            node.encode("utf-8", errors="strict")
        elif type(node) is list:
            for item in node:
                check(item)
        elif type(node) is dict and all(type(key) is str for key in node):
            for key, item in node.items():
                key.encode("utf-8", errors="strict")
                check(item)
        else:
            raise IDCertificateError("invalid_shape")
    try:
        check(value)
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except (UnicodeError, RecursionError) as exc:
        raise IDCertificateError("invalid_json") from exc


def id_certificate_signing_bytes(certificate: dict[str, Any]) -> bytes:
    """Compute canonical bytes, including for negative shape-test fixtures.

    This low-level operation does not validate or confer certificate authority.
    """
    return ID_CERTIFICATE_PREFIX + _canonical(certificate)


def id_certificate_id(certificate: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(id_certificate_signing_bytes(certificate)).hexdigest()


def _domain(value: Any) -> None:
    if not isinstance(value, str) or len(value) > 253 or not all(_LABEL.fullmatch(label) for label in value.split(".")):
        raise IDCertificateError("invalid_domain")


def _id(value: Any, *, key_only: bool = False) -> None:
    try:
        if not isinstance(value, str):
            raise ValueError("not text")
        if value.startswith("did:key:"):
            public = public_key_from_did(value)
            if did_from_public_key(public) != value or not crypto_core_ed25519_is_valid_point(public):
                raise ValueError("noncanonical or non-prime-subgroup key")
        elif not key_only and value.startswith("did:aw:"):
            if not _BASE58.fullmatch(value[7:]) or validate_stable_id(value) != value:
                raise ValueError("noncanonical stable id")
        else:
            raise ValueError("wrong ID kind")
    except (TypeError, ValueError) as exc:
        raise IDCertificateError("invalid_shape") from exc


def _shape(signed: Any) -> dict[str, Any]:
    if type(signed) is not dict or set(signed) != {"certificate", "signature"}:
        raise IDCertificateError("invalid_shape")
    c = signed["certificate"]
    if type(c) is not dict or set(c) != _FIELDS:
        raise IDCertificateError("invalid_shape")
    if type(c["v"]) is not int or c["v"] != 1 or c["type"] != "aweb.id-certificate":
        raise IDCertificateError("invalid_shape")
    if c["kind"] not in ("human", "agent"):
        raise IDCertificateError("invalid_kind")
    _id(c["id"])
    if c["kind"] == "human" and not c["id"].startswith("did:aw:"):
        raise IDCertificateError("invalid_shape")
    _domain(c["domain"])
    parent = c["parent"]
    if type(parent) is not dict or set(parent) != {"kind", "id"}:
        raise IDCertificateError("invalid_shape")
    if parent["kind"] == "identity":
        _id(parent["id"])
    elif parent["kind"] == "namespace":
        _domain(parent["id"])
        if parent["id"] != c["domain"]:
            raise IDCertificateError("domain_mismatch")
    else:
        raise IDCertificateError("invalid_shape")
    _id(c["issuer_key"], key_only=True)
    try:
        parse_utc_seconds(c["issued_at"])
    except ValueError as exc:
        raise IDCertificateError("invalid_shape") from exc
    return c


def _decode_b64(value: Any) -> bytes:
    if not isinstance(value, str) or not _B64URL.fullmatch(value):
        raise IDCertificateError("invalid_encoding")
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise IDCertificateError("invalid_encoding") from exc
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode() != value:
        raise IDCertificateError("invalid_encoding")
    return decoded


def verify_id_certificate(signed: dict[str, Any], *, issuer_key: str) -> None:
    """Check shape and signature with an independently selected issuer key."""
    c = _shape(signed)
    signature = _decode_b64(signed["signature"])
    if len(signature) != 64:
        raise IDCertificateError("invalid_encoding")
    if c["issuer_key"] != issuer_key:
        raise IDCertificateError("invalid_signature")
    # This profile requires canonical, nonidentity prime-subgroup R and S<L.
    # Library verification alone can accept a mixed-order A for some messages.
    if (
        not crypto_core_ed25519_is_valid_point(signature[:32])
        or int.from_bytes(signature[32:], "little") >= _ED25519_ORDER
    ):
        raise IDCertificateError("invalid_signature")
    try:
        VerifyKey(public_key_from_did(issuer_key)).verify(id_certificate_signing_bytes(c), signature)
    except (BadSignatureError, ValueError, TypeError) as exc:
        raise IDCertificateError("invalid_signature") from exc


def _bundle_shape(bundle: Any) -> None:
    if type(bundle) is not dict or set(bundle) != {"v", "type", "certificates"}:
        raise IDCertificateError("invalid_shape")
    if type(bundle["v"]) is not int or bundle["v"] != 1 or bundle["type"] != "aweb.id-chain":
        raise IDCertificateError("invalid_shape")
    certs = bundle["certificates"]
    if type(certs) is not list or not certs:
        raise IDCertificateError("invalid_shape")
    if len(certs) > ID_CHAIN_MAX_DEPTH:
        raise IDCertificateError("depth_exceeded")
    for signed in certs:
        c = _shape(signed)
        verify_id_certificate(signed, issuer_key=c["issuer_key"])


def encode_id_chain_header(bundle: dict[str, Any]) -> str:
    raw = _canonical(bundle)
    if len(raw) > ID_CHAIN_MAX_BYTES:
        raise IDCertificateError("bundle_too_large")
    _bundle_shape(bundle)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def decode_id_chain_header(value: str) -> dict[str, Any]:
    if not isinstance(value, str):
        raise IDCertificateError("invalid_encoding")
    if len(value) > ID_CHAIN_HEADER_MAX_BYTES:
        raise IDCertificateError("bundle_too_large")
    raw = _decode_b64(value)
    if len(raw) > ID_CHAIN_MAX_BYTES:
        raise IDCertificateError("bundle_too_large")
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in items:
            if key in result:
                raise IDCertificateError("invalid_json")
            result[key] = item
        return result
    def reject_number(_: str) -> Any:
        raise IDCertificateError("invalid_shape")
    try:
        bundle = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_float=reject_number, parse_constant=reject_number)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise IDCertificateError("invalid_json") from exc
    except IDCertificateError:
        raise
    except ValueError as exc:
        # json's integer digit limit is a shape refusal, not an uncoded error.
        raise IDCertificateError("invalid_shape") from exc
    if _canonical(bundle) != raw:
        raise IDCertificateError("noncanonical_json")
    _bundle_shape(bundle)
    return bundle
