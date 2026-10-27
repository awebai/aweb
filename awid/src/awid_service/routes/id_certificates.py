"""Identity-tree registry endpoints (docs/id-certificates.md §3, §4)."""

from __future__ import annotations

import json
import re
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from awid.controller_request import verify_controller_json_request
from awid.id_certificates import IDCertificateError, decode_id_chain_header, verify_id_certificate
from awid.ratelimit import rate_limit_dep
from awid_service.deps import get_db
from awid_service.id_chains import check_chain_structure
from awid_service.id_registration import RegistrationRefused, register_certificate
from awid_service.id_tree_clock import app_clock

router = APIRouter(prefix="/v1/id-certificates", tags=["id-certificates"])

ID_CHAIN_HEADER = "X-AWID-ID-Chain"
SIGNED_PAYLOAD_HEADER = "X-AWEB-Signed-Payload"
_MAX_BODY_BYTES = 16384
_REGISTER_FIELDS = frozenset({"certificate", "expected_head", "invitation_id"})
_CERTIFICATE_ID = re.compile(r"sha256:[0-9a-f]{64}")


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


def _register_body(raw: bytes) -> tuple[dict, str | None, str | None]:
    body = _strict_json_object(raw)
    if set(body) != _REGISTER_FIELDS:
        raise IDCertificateError("invalid_shape")
    expected_head = body["expected_head"]
    if expected_head is not None and (type(expected_head) is not str or not _CERTIFICATE_ID.fullmatch(expected_head)):
        raise IDCertificateError("invalid_shape")
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


@router.post(
    "/register",
    dependencies=[Depends(rate_limit_dep("id_certificate_register", allow_trusted_service=True))],
)
async def register_id_certificate(request: Request, db_infra=Depends(get_db)) -> dict:
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

    if request.headers.get(SIGNED_PAYLOAD_HEADER) is None:
        raise HTTPException(status_code=401, detail="Covering AWID request envelope required")
    signer = await verify_controller_json_request(
        request, payload_dict={"domain": cert["domain"], "operation": "register_id_certificate"},
    )

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
        return await register_certificate(
            db, chain=chain, expected_head=expected_head, invitation_id=invitation_id,
            signer=signer, clock=app_clock(request.app),
        )
    except RegistrationRefused as refused:
        raise _refusal(refused.code, refused.status) from refused
