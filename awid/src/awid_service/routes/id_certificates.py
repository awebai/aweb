"""Identity-tree registry endpoints (docs/id-certificates.md §3, §4)."""

from __future__ import annotations

import json
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from awid.controller_request import verify_controller_json_request
from awid.dns_verify import DnsVerificationError, DomainVerifier
from awid.id_certificates import IDCertificateError, decode_id_chain_header, verify_id_certificate
from awid.ratelimit import rate_limit_dep
from awid_service.deps import get_db, get_domain_verifier
from awid_service.id_chains import check_chain_structure
from awid_service.id_registration import register_certificate
from awid_service.id_revocation import revoke_identity
from awid_service.id_tree_gate import IdentityTreeRefusal
from awid_service.id_tree_clock import app_clock
from awid_service.namespace_epochs import is_exact

router = APIRouter(prefix="/v1/id-certificates", tags=["id-certificates"])

ID_CHAIN_HEADER = "X-AWID-ID-Chain"
SIGNED_PAYLOAD_HEADER = "X-AWEB-Signed-Payload"
_MAX_BODY_BYTES = 16384
_REGISTER_FIELDS = frozenset({"certificate", "expected_head", "invitation_id"})
_REVOKE_FIELDS = frozenset({"domain", "id", "expected_head", "effective_from"})
_CERTIFICATE_ID = re.compile(r"sha256:[0-9a-f]{64}")
_WIRE_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z")


def _refusal(code: str, status: int) -> HTTPException:
    return HTTPException(status_code=status, detail={"code": code, "message": code.replace("_", " ")})


def _strict_json_object(raw: bytes) -> dict[str, Any]:
    if len(raw) > _MAX_BODY_BYTES:
        raise IDCertificateError("invalid_shape")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise IDCertificateError("invalid_json")
            result[key] = value
        return result

    def reject(_: str) -> Any:
        raise IDCertificateError("invalid_shape")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_float=reject, parse_constant=reject)
    except (UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, IDCertificateError):
            raise
        raise IDCertificateError("invalid_json") from exc
    if type(value) is not dict:
        raise IDCertificateError("invalid_shape")
    return value


def _expected_head(value: Any) -> str | None:
    if value is not None and (type(value) is not str or not _CERTIFICATE_ID.fullmatch(value)):
        raise IDCertificateError("invalid_shape")
    return value


def _register_body(raw: bytes) -> tuple[dict, str | None, str | None]:
    body = _strict_json_object(raw)
    if set(body) != _REGISTER_FIELDS:
        raise IDCertificateError("invalid_shape")
    expected_head = _expected_head(body["expected_head"])
    invitation_id = body["invitation_id"]
    if invitation_id is not None:
        try:
            canonical = type(invitation_id) is str and str(uuid.UUID(invitation_id)) == invitation_id
        except ValueError:
            canonical = False
        if not canonical:
            raise IDCertificateError("invalid_shape")
    signed = body["certificate"]
    if type(signed) is not dict or type(signed.get("certificate")) is not dict:
        raise IDCertificateError("invalid_shape")
    verify_id_certificate(signed, issuer_key=signed["certificate"].get("issuer_key"))
    if not signed["certificate"]["id"].startswith("did:aw:"):
        # A local agent's did:key certificate is carried by its holder, never
        # registered; enrollment acquires a did:aw instead.
        raise IDCertificateError("invalid_shape")
    return signed, expected_head, invitation_id


def _revoke_body(raw: bytes) -> tuple[str, str, str | None, datetime | None]:
    body = _strict_json_object(raw)
    if set(body) != _REVOKE_FIELDS:
        raise IDCertificateError("invalid_shape")
    domain, id_ = body["domain"], body["id"]
    if type(domain) is not str or not domain or type(id_) is not str or not id_.startswith("did:aw:"):
        raise IDCertificateError("invalid_shape")
    effective_from = body["effective_from"]
    if effective_from is not None:
        if type(effective_from) is not str or not _WIRE_TIME.fullmatch(effective_from):
            raise IDCertificateError("invalid_shape")
        try:
            effective_from = datetime.strptime(effective_from, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
        except ValueError as exc:
            raise IDCertificateError("invalid_shape") from exc
    return domain, id_, _expected_head(body["expected_head"]), effective_from


async def _exact_dns_key(verify_domain: DomainVerifier, domain: str) -> str | None:
    """The controller key exact DNS proves for ``domain`` right now, or None.

    Looked up before the transaction so no network call happens under its
    locks. The skip-DNS bypass proves nothing.
    """
    if os.environ.get("AWID_SKIP_DNS_VERIFY", "").strip() == "1":
        return None
    try:
        authority = await verify_domain(domain)
    except DnsVerificationError:
        return None
    return authority.controller_did if is_exact(authority) else None


async def _covering_signer(request: Request, *, domain: str, operation: str) -> str:
    if request.headers.get(SIGNED_PAYLOAD_HEADER) is None:
        raise HTTPException(status_code=401, detail="Covering AWID request envelope required")
    return await verify_controller_json_request(request, payload_dict={"domain": domain, "operation": operation})


@router.post(
    "/register",
    dependencies=[Depends(rate_limit_dep("id_certificate_register", allow_trusted_service=True))],
)
async def register_id_certificate(
    request: Request, db_infra=Depends(get_db), verify_domain: DomainVerifier = Depends(get_domain_verifier),
) -> dict:
    """Register a parent-signed ID certificate as its subject's new head.

    The subject proves its current key with the covering request envelope;
    the parent's signature, checked against the parent's current key under
    the gate's locks, authorizes the issuance.
    """
    try:
        signed, expected_head, invitation_id = _register_body(await request.body())
    except IDCertificateError as exc:
        raise _refusal(exc.code, 400) from exc
    cert = signed["certificate"]

    signer = await _covering_signer(request, domain=cert["domain"], operation="register_id_certificate")

    header = request.headers.get(ID_CHAIN_HEADER)
    if header is None:
        raise _refusal("invalid_shape", 400)
    try:
        chain = decode_id_chain_header(header)["certificates"]
    except IDCertificateError as exc:
        raise _refusal(exc.code, 400) from exc
    if chain[-1] != signed:
        raise _refusal("invalid_shape", 400)

    db = db_infra.get_manager("aweb")
    try:
        check_chain_structure(chain)
        dns_key = await _exact_dns_key(verify_domain, cert["domain"])
        return await register_certificate(
            db, chain=chain, expected_head=expected_head, invitation_id=invitation_id,
            signer=signer, dns_key=dns_key, clock=app_clock(request.app),
        )
    except IdentityTreeRefusal as refused:
        raise _refusal(refused.code, refused.status) from refused


@router.post(
    "/revoke",
    dependencies=[Depends(rate_limit_dep("id_certificate_revoke", allow_trusted_service=True))],
)
async def revoke_id_certificate(
    request: Request, db_infra=Depends(get_db), verify_domain: DomainVerifier = Depends(get_domain_verifier),
) -> dict:
    """Revoke a registered ID, proved by the ID itself, its valid parent or the namespace root."""
    try:
        domain, id_, expected_head, effective_from = _revoke_body(await request.body())
    except IDCertificateError as exc:
        raise _refusal(exc.code, 400) from exc
    signer = await _covering_signer(request, domain=domain, operation="revoke_id_certificate")

    db = db_infra.get_manager("aweb")
    dns_key = await _exact_dns_key(verify_domain, domain)
    try:
        return await revoke_identity(
            db, domain=domain, subject_id=id_, expected_head=expected_head, effective_from=effective_from,
            signer=signer, dns_key=dns_key, clock=app_clock(request.app),
        )
    except IdentityTreeRefusal as refused:
        raise _refusal(refused.code, refused.status) from refused
