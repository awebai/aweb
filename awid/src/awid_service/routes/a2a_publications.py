"""A2A Agent Card publication and bridge delegation registry routes."""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from awid.a2a_publication import (
    A2A_AUTHORITY_HOSTED_DELEGATION,
    A2A_AUTHORITY_HOSTED_SESSION,
    A2A_AUTHORITY_SELF_DELEGATION,
    A2A_AUTHORITY_SELF_IDENTITY_KEY,
    A2A_CARD_DIGEST_ALG_SHA256,
    A2A_CONFLICT_CODES,
    A2A_CUSTODY_DELEGATED_BRIDGE,
    A2A_CUSTODY_HOSTED_DELEGATED_BRIDGE,
    A2A_DELEGATION_OPERATION,
    A2A_PUBLICATION_OPERATION,
    A2A_STATUS_ACTIVE,
    A2A_STATUS_REVOKED,
    A2ADelegationFields,
    A2APublicationFields,
    a2a_delegation_canonical,
    a2a_delegation_payload,
    a2a_publication_canonical,
    a2a_publication_payload,
    canonical_address,
    normalize_a2a_delegation_fields,
    normalize_a2a_publication_fields,
    parse_contract_time,
    signed_assertion_digest,
)
from awid.atomic_claim import CUSTODY_HOSTED, CUSTODY_SELF
from awid.did import validate_stable_id
from awid.dns_auth import enforce_timestamp_skew
from awid.log import sha256_hex as awid_sha256_hex
from awid.ratelimit import rate_limit_dep
from awid.signing import verify_did_key_signature
from awid_service.deps import get_db

router = APIRouter(prefix="/v1", tags=["a2a"])
logger = logging.getLogger(__name__)

_A2A_PUBLICATION_ENABLED_ENV = "AWID_ENABLE_A2A_PUBLICATION"
_MAX_ROUTE_LIFETIME = timedelta(days=90)

_PUBLICATION_EXISTS_DIFFERENT_DIGEST = "a2a_publication_exists_different_digest"
_PUBLICATION_EXISTS_DIFFERENT_GATEWAY = "a2a_publication_exists_different_gateway"
_DELEGATION_MISSING = "a2a_delegation_missing"
_DELEGATION_DIGEST_MISMATCH = "a2a_delegation_digest_mismatch"
_DELEGATION_EXPIRED = "a2a_delegation_expired"
_DELEGATION_REVOKED = "a2a_delegation_revoked"
_CARD_DIGEST_MISMATCH = "a2a_card_digest_mismatch"
_CARD_URL_INVALID = "a2a_card_url_invalid"
_RPC_URL_INVALID = "a2a_rpc_url_invalid"
_ROUTE_ID_INVALID = "a2a_route_id_invalid"
_IDENTITY_SIGNATURE_INVALID = "a2a_identity_signature_invalid"
_DELEGATION_SIGNATURE_INVALID = "a2a_delegation_signature_invalid"
_TIMESTAMP_STALE = "a2a_timestamp_stale"
_NAMESPACE_NOT_REGISTERED = "a2a_namespace_not_registered"
_ADDRESS_NOT_REGISTERED = "a2a_address_not_registered"
_CUSTODY_UNSUPPORTED = "a2a_custody_combination_unsupported"
_AUTHORITY_INVALID = "a2a_authority_source_invalid"
_PAYLOAD_CANONICALIZATION = "a2a_payload_canonicalization_mismatch"
_PRIMITIVE_DISABLED = "a2a_primitive_disabled"


class A2ADelegationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    operation: Literal["delegate_a2a_bridge"] = A2A_DELEGATION_OPERATION
    delegation_id: str = Field(..., max_length=128)
    delegator_did_aw: str = Field(..., max_length=256)
    delegator_current_did_key: str = Field(..., max_length=256)
    delegated_gateway_identity: str = Field(..., max_length=256)
    address: str = Field(..., max_length=512)
    route_id: str = Field(..., max_length=128)
    card_url: str = Field(..., max_length=1024)
    rpc_url: str = Field(..., max_length=1024)
    allowed_operations: list[str] = Field(..., min_length=1, max_length=32)
    card_digest_alg: Literal["sha256"] = A2A_CARD_DIGEST_ALG_SHA256
    card_digest: str = Field(..., max_length=128)
    custody_mode: str = Field(..., max_length=64)
    authority_source: str = Field(..., max_length=64)
    signer_did: str = Field(..., max_length=256)
    signer_kid: str = Field(..., max_length=512)
    issued_at: str = Field(..., max_length=64)
    expires_at: str = Field(..., max_length=64)
    status: Literal["active", "revoked"] = A2A_STATUS_ACTIVE
    revoked_at: str | None = Field(default=None, max_length=64)
    revocation_reason: str | None = Field(default=None, max_length=128)
    registry_url: str = Field(..., max_length=512)
    signature: str = Field(..., max_length=2048)


class A2APublicationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    operation: Literal["publish_a2a_route"] = A2A_PUBLICATION_OPERATION
    assertion_id: str = Field(..., max_length=128)
    address: str = Field(..., max_length=512)
    did_aw: str = Field(..., max_length=256)
    current_did_key: str = Field(..., max_length=256)
    signer_did: str = Field(..., max_length=256)
    signer_kid: str = Field(..., max_length=512)
    card_url: str = Field(..., max_length=1024)
    rpc_url: str = Field(..., max_length=1024)
    route_id: str = Field(..., max_length=128)
    tenant: str | None = Field(default=None, max_length=256)
    gateway_identity: str = Field(..., max_length=256)
    delegation_id: str | None = Field(default=None, max_length=128)
    delegation_digest: str | None = Field(default=None, max_length=128)
    card_digest_alg: Literal["sha256"] = A2A_CARD_DIGEST_ALG_SHA256
    card_digest: str = Field(..., max_length=128)
    card_revision: str = Field(..., max_length=128)
    default_for_host: bool = False
    status: Literal["active", "revoked"] = A2A_STATUS_ACTIVE
    published_at: str = Field(..., max_length=64)
    expires_at: str = Field(..., max_length=64)
    registry_url: str = Field(..., max_length=512)
    identity_custody: Literal["self", "hosted_custodial"]
    authority_source: str = Field(..., max_length=64)
    signature: str = Field(..., max_length=2048)


class A2AWriteResponse(BaseModel):
    status: str
    assertion_id: str | None = None
    delegation_id: str | None = None
    assertion_digest: str
    address: str
    route_id: str


class A2ADirectoryEntry(BaseModel):
    status: str
    card_url: str
    rpc_url: str
    route_id: str
    tenant: str | None = None
    gateway_identity: str
    card_digest_alg: str
    card_digest: str
    card_revision: str
    publication_assertion_id: str
    delegation_id: str | None = None
    delegation_digest: str | None = None
    published_at: str
    expires_at: str
    verification: str = "awid_publication_available"


class A2AAddressDirectoryResponse(BaseModel):
    address: str
    did_aw: str
    a2a: A2ADirectoryEntry | None = None


def _enabled() -> bool:
    value = os.getenv(_A2A_PUBLICATION_ENABLED_ENV, "true").strip().lower()
    return value not in {"0", "false", "no", "off", "disabled"}


def _request_id(request: Request) -> str:
    return request.headers.get("X-Request-ID") or request.headers.get("X-AWEB-Request-ID") or uuid.uuid4().hex


def _error(status_code: int, code: str, message: str) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"code": code, "message": message})


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _body_to_delegation_fields(body: A2ADelegationRequest) -> A2ADelegationFields:
    try:
        return normalize_a2a_delegation_fields(
            A2ADelegationFields(
                operation=body.operation,
                delegation_id=body.delegation_id,
                delegator_did_aw=body.delegator_did_aw,
                delegator_current_did_key=body.delegator_current_did_key,
                delegated_gateway_identity=body.delegated_gateway_identity,
                address=body.address,
                route_id=body.route_id,
                card_url=body.card_url,
                rpc_url=body.rpc_url,
                allowed_operations=tuple(body.allowed_operations),
                card_digest_alg=body.card_digest_alg,
                card_digest=body.card_digest,
                custody_mode=body.custody_mode,
                authority_source=body.authority_source,
                signer_did=body.signer_did,
                signer_kid=body.signer_kid,
                issued_at=body.issued_at,
                expires_at=body.expires_at,
                status=body.status,
                revoked_at=body.revoked_at,
                revocation_reason=body.revocation_reason,
                registry_url=body.registry_url,
            )
        )
    except ValueError as exc:
        code = _payload_error_code(str(exc))
        raise _error(422, code, str(exc)) from exc


def _body_to_publication_fields(body: A2APublicationRequest) -> A2APublicationFields:
    try:
        return normalize_a2a_publication_fields(
            A2APublicationFields(
                operation=body.operation,
                assertion_id=body.assertion_id,
                address=body.address,
                did_aw=body.did_aw,
                current_did_key=body.current_did_key,
                signer_did=body.signer_did,
                signer_kid=body.signer_kid,
                card_url=body.card_url,
                rpc_url=body.rpc_url,
                route_id=body.route_id,
                tenant=body.tenant,
                gateway_identity=body.gateway_identity,
                delegation_id=body.delegation_id,
                delegation_digest=body.delegation_digest,
                card_digest_alg=body.card_digest_alg,
                card_digest=body.card_digest,
                card_revision=body.card_revision,
                default_for_host=body.default_for_host,
                status=body.status,
                published_at=body.published_at,
                expires_at=body.expires_at,
                registry_url=body.registry_url,
                identity_custody=body.identity_custody,
                authority_source=body.authority_source,
            )
        )
    except ValueError as exc:
        code = _payload_error_code(str(exc))
        raise _error(422, code, str(exc)) from exc


def _payload_error_code(message: str) -> str:
    if "card_url" in message:
        return _CARD_URL_INVALID
    if "rpc_url" in message:
        return _RPC_URL_INVALID
    if "route_id" in message:
        return _ROUTE_ID_INVALID
    return _PAYLOAD_CANONICALIZATION


def _verify_timestamp(value: str) -> None:
    try:
        enforce_timestamp_skew(value)
    except HTTPException as exc:
        raise _error(401, _TIMESTAMP_STALE, "timestamp outside allowed skew window") from exc


def _validate_lifetime(*, start_text: str, expires_text: str) -> tuple[datetime, datetime]:
    try:
        start = parse_contract_time(start_text, field_name="timestamp")
        expires = parse_contract_time(expires_text, field_name="expires_at")
    except ValueError as exc:
        raise _error(422, _PAYLOAD_CANONICALIZATION, str(exc)) from exc
    if expires <= start:
        raise _error(422, _PAYLOAD_CANONICALIZATION, "expires_at must be after assertion timestamp")
    if expires - start > _MAX_ROUTE_LIFETIME:
        raise _error(422, _PAYLOAD_CANONICALIZATION, "expires_at must be within 90 days")
    return start, expires


def _verify_signature(*, did_key: str, payload: bytes, signature: str, code: str, message: str) -> None:
    try:
        verify_did_key_signature(did_key=did_key, payload=payload, signature_b64=signature)
    except Exception as exc:
        raise _error(401, code, message) from exc


def _validate_delegation_authority(fields: A2ADelegationFields) -> None:
    if fields.custody_mode == A2A_CUSTODY_DELEGATED_BRIDGE:
        if fields.authority_source != A2A_AUTHORITY_SELF_DELEGATION:
            raise _error(
                403,
                _AUTHORITY_INVALID,
                "expected self_identity_delegation authority for self-custodial bridge delegation",
            )
        if fields.signer_did != fields.delegator_current_did_key:
            raise _error(
                403,
                _DELEGATION_SIGNATURE_INVALID,
                "self-custodial delegation must be signed by the delegator current did:key",
            )
        return
    if fields.custody_mode == A2A_CUSTODY_HOSTED_DELEGATED_BRIDGE:
        if fields.authority_source != A2A_AUTHORITY_HOSTED_DELEGATION:
            raise _error(
                403,
                _AUTHORITY_INVALID,
                "expected hosted_delegation authority for hosted-custodial bridge delegation",
            )
        if fields.signer_did != fields.delegator_current_did_key:
            raise _error(
                403,
                _DELEGATION_SIGNATURE_INVALID,
                "hosted delegation must be signed by the hosted current did:key",
            )
        return
    raise _error(422, _CUSTODY_UNSUPPORTED, "unsupported A2A bridge custody mode")


def _validate_publication_authority(fields: A2APublicationFields) -> None:
    if fields.identity_custody == CUSTODY_SELF:
        if fields.authority_source != A2A_AUTHORITY_SELF_IDENTITY_KEY:
            raise _error(403, _AUTHORITY_INVALID, "expected self_identity_key authority for self publication")
        if fields.signer_did != fields.current_did_key:
            raise _error(401, _IDENTITY_SIGNATURE_INVALID, "self publication must be signed by current did:key")
        return
    if fields.identity_custody == CUSTODY_HOSTED:
        if fields.authority_source != A2A_AUTHORITY_HOSTED_SESSION:
            raise _error(
                403,
                _AUTHORITY_INVALID,
                "expected hosted_session authority for hosted-custodial publication",
            )
        if fields.signer_did != fields.current_did_key:
            raise _error(
                401,
                _IDENTITY_SIGNATURE_INVALID,
                "hosted publication must be signed by the hosted current did:key",
            )
        return
    raise _error(422, _CUSTODY_UNSUPPORTED, "unsupported A2A publication custody")


async def _fetch_registered_address(tx, *, address: str):
    domain, name = address.split("/", 1)
    return await tx.fetch_one(
        """
        SELECT pa.address_id, pa.name, pa.did_aw, m.current_did_key, ns.namespace_id, ns.domain
        FROM {{tables.public_addresses}} pa
        JOIN {{tables.dns_namespaces}} ns ON ns.namespace_id = pa.namespace_id
        JOIN {{tables.did_aw_mappings}} m ON m.did_aw = pa.did_aw
        WHERE ns.domain = $1
          AND pa.name = $2
          AND pa.deleted_at IS NULL
          AND ns.deleted_at IS NULL
        FOR SHARE OF pa, ns, m
        """,
        domain,
        name,
    )


async def _ensure_address_matches(tx, *, address: str, did_aw: str, current_did_key: str) -> None:
    row = await _fetch_registered_address(tx, address=address)
    if row is None:
        domain, _ = address.split("/", 1)
        ns = await tx.fetch_one(
            "SELECT namespace_id FROM {{tables.dns_namespaces}} WHERE domain = $1 AND deleted_at IS NULL",
            domain,
        )
        if ns is None:
            raise _error(404, _NAMESPACE_NOT_REGISTERED, "namespace must exist before A2A publication")
        raise _error(404, _ADDRESS_NOT_REGISTERED, "address must be registered before A2A publication")
    if row["did_aw"] != did_aw or row["current_did_key"] != current_did_key:
        raise _error(409, _ADDRESS_NOT_REGISTERED, "address is registered to a different identity")


def _row_delegation_digest(row) -> str:
    return row["assertion_digest"]


@router.post(
    "/a2a/delegations",
    response_model=A2AWriteResponse,
    dependencies=[Depends(rate_limit_dep("a2a_delegation_publish"))],
)
async def publish_a2a_delegation(
    request: Request,
    body: A2ADelegationRequest,
    db_infra=Depends(get_db),
) -> A2AWriteResponse:
    request_id = _request_id(request)
    if not _enabled():
        raise _error(404, _PRIMITIVE_DISABLED, "A2A publication primitive is disabled")
    fields = _body_to_delegation_fields(body)
    _validate_delegation_authority(fields)
    _verify_timestamp(fields.issued_at)
    issued_at, expires_at = _validate_lifetime(start_text=fields.issued_at, expires_text=fields.expires_at)
    canonical = a2a_delegation_canonical(fields)
    _verify_signature(
        did_key=fields.signer_did,
        payload=canonical,
        signature=body.signature,
        code=_DELEGATION_SIGNATURE_INVALID,
        message="A2A delegation signature invalid",
    )
    assertion_digest = signed_assertion_digest(canonical, body.signature)

    db = db_infra.get_manager("aweb")
    async with db.transaction() as tx:
        await _ensure_address_matches(
            tx,
            address=fields.address,
            did_aw=fields.delegator_did_aw,
            current_did_key=fields.delegator_current_did_key,
        )
        existing = await tx.fetch_one(
            """
            SELECT delegation_id, delegator_did_aw, delegator_current_did_key,
                   delegated_gateway_identity, address, route_id, assertion_digest,
                   assertion_canonical
            FROM {{tables.a2a_bridge_delegations}}
            WHERE delegation_id = $1
            FOR UPDATE
            """,
            fields.delegation_id,
        )
        if existing is not None:
            if fields.status == A2A_STATUS_REVOKED:
                for field_name in (
                    "delegator_did_aw",
                    "delegator_current_did_key",
                    "delegated_gateway_identity",
                    "address",
                    "route_id",
                ):
                    if existing[field_name] != getattr(fields, field_name):
                        raise _error(409, _DELEGATION_DIGEST_MISMATCH, f"delegation {field_name} mismatch")
                revoked_at = parse_contract_time(fields.revoked_at, field_name="revoked_at") if fields.revoked_at else _now()
                await tx.execute(
                    """
                    UPDATE {{tables.a2a_bridge_delegations}}
                    SET status = 'revoked',
                        revoked_at_text = $2,
                        revocation_reason = $3,
                        assertion_signature = $4,
                        assertion_canonical = $5,
                        assertion_digest = $6,
                        updated_at = NOW(),
                        revoked_at = $7
                    WHERE delegation_id = $1
                    """,
                    fields.delegation_id,
                    fields.revoked_at,
                    fields.revocation_reason,
                    body.signature,
                    canonical.decode("utf-8"),
                    assertion_digest,
                    revoked_at,
                )
                return A2AWriteResponse(
                    status="revoked",
                    delegation_id=fields.delegation_id,
                    assertion_digest=assertion_digest,
                    address=fields.address,
                    route_id=fields.route_id,
                )
            if existing["assertion_digest"] == assertion_digest:
                return A2AWriteResponse(
                    status="already_applied",
                    delegation_id=fields.delegation_id,
                    assertion_digest=assertion_digest,
                    address=fields.address,
                    route_id=fields.route_id,
            )
            raise _error(409, _DELEGATION_DIGEST_MISMATCH, "delegation id exists with different assertion digest")
        if fields.status == A2A_STATUS_REVOKED:
            raise _error(409, _DELEGATION_MISSING, "cannot revoke a delegation that is not registered")

        await tx.execute(
            """
            INSERT INTO {{tables.a2a_bridge_delegations}}
                (delegation_id, delegator_did_aw, delegator_current_did_key,
                 delegated_gateway_identity, address, route_id, card_url, rpc_url,
                 allowed_operations, card_digest_alg, card_digest, custody_mode,
                 authority_source, signer_did, signer_kid, issued_at_text, expires_at_text,
                 status, revoked_at_text, revocation_reason, registry_url, assertion_signature,
                 assertion_canonical, assertion_digest, issued_at, expires_at, revoked_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11,$12,$13,$14,$15,$16,$17,
                    $18,$19,$20,$21,$22,$23,$24,$25,$26,$27)
            """,
            fields.delegation_id,
            fields.delegator_did_aw,
            fields.delegator_current_did_key,
            fields.delegated_gateway_identity,
            fields.address,
            fields.route_id,
            fields.card_url,
            fields.rpc_url,
            json.dumps(list(fields.allowed_operations), separators=(",", ":")),
            fields.card_digest_alg,
            fields.card_digest,
            fields.custody_mode,
            fields.authority_source,
            fields.signer_did,
            fields.signer_kid,
            fields.issued_at,
            fields.expires_at,
            fields.status,
            fields.revoked_at,
            fields.revocation_reason,
            fields.registry_url,
            body.signature,
            canonical.decode("utf-8"),
            assertion_digest,
            issued_at,
            expires_at,
            parse_contract_time(fields.revoked_at, field_name="revoked_at") if fields.revoked_at else None,
        )

    logger.info(
        "a2a_delegation_publish request_id=%s outcome=applied delegation_id=%s address_hash=%s gateway_hash=%s",
        request_id,
        fields.delegation_id,
        awid_sha256_hex(fields.address.encode("utf-8"))[:12],
        awid_sha256_hex(fields.delegated_gateway_identity.encode("utf-8"))[:12],
    )
    return A2AWriteResponse(
        status="applied",
        delegation_id=fields.delegation_id,
        assertion_digest=assertion_digest,
        address=fields.address,
        route_id=fields.route_id,
    )


@router.post(
    "/a2a/publications",
    response_model=A2AWriteResponse,
    dependencies=[Depends(rate_limit_dep("a2a_publication_publish"))],
)
async def publish_a2a_route(
    request: Request,
    body: A2APublicationRequest,
    db_infra=Depends(get_db),
) -> A2AWriteResponse:
    request_id = _request_id(request)
    if not _enabled():
        raise _error(404, _PRIMITIVE_DISABLED, "A2A publication primitive is disabled")
    fields = _body_to_publication_fields(body)
    _validate_publication_authority(fields)
    _verify_timestamp(fields.published_at)
    published_at, expires_at = _validate_lifetime(start_text=fields.published_at, expires_text=fields.expires_at)
    canonical = a2a_publication_canonical(fields)
    _verify_signature(
        did_key=fields.signer_did,
        payload=canonical,
        signature=body.signature,
        code=_IDENTITY_SIGNATURE_INVALID,
        message="A2A publication signature invalid",
    )
    assertion_digest = signed_assertion_digest(canonical, body.signature)

    db = db_infra.get_manager("aweb")
    async with db.transaction() as tx:
        await _ensure_address_matches(
            tx,
            address=fields.address,
            did_aw=fields.did_aw,
            current_did_key=fields.current_did_key,
        )
        if fields.gateway_identity != fields.did_aw and not fields.delegation_id:
            raise _error(409, _DELEGATION_MISSING, "delegated gateway publication requires a delegation")
        if fields.delegation_id:
            delegation = await tx.fetch_one(
                """
                SELECT *
                FROM {{tables.a2a_bridge_delegations}}
                WHERE delegation_id = $1
                FOR SHARE
                """,
                fields.delegation_id,
            )
            if delegation is None:
                raise _error(409, _DELEGATION_MISSING, "A2A bridge delegation is missing")
            if delegation["status"] != A2A_STATUS_ACTIVE or delegation["revoked_at"] is not None:
                raise _error(409, _DELEGATION_REVOKED, "A2A bridge delegation is revoked")
            if delegation["expires_at"] <= _now():
                raise _error(409, _DELEGATION_EXPIRED, "A2A bridge delegation is expired")
            if _row_delegation_digest(delegation) != fields.delegation_digest:
                raise _error(409, _DELEGATION_DIGEST_MISMATCH, "A2A bridge delegation digest mismatch")
            for field_name in ("address", "route_id", "card_url", "rpc_url", "card_digest"):
                if delegation[field_name] != getattr(fields, field_name):
                    code = _CARD_DIGEST_MISMATCH if field_name == "card_digest" else _DELEGATION_DIGEST_MISMATCH
                    raise _error(409, code, f"A2A delegation {field_name} mismatch")
            if delegation["delegated_gateway_identity"] != fields.gateway_identity:
                raise _error(409, _PUBLICATION_EXISTS_DIFFERENT_GATEWAY, "gateway identity mismatch")

        existing_assertion = await tx.fetch_one(
            """
            SELECT assertion_id, address, did_aw, current_did_key, gateway_identity, route_id,
                   assertion_digest
            FROM {{tables.a2a_route_publications}}
            WHERE assertion_id = $1
            FOR UPDATE
            """,
            fields.assertion_id,
        )
        if existing_assertion is not None:
            if fields.status == A2A_STATUS_REVOKED:
                for field_name in ("address", "did_aw", "current_did_key", "gateway_identity", "route_id"):
                    if existing_assertion[field_name] != getattr(fields, field_name):
                        raise _error(409, _PUBLICATION_EXISTS_DIFFERENT_DIGEST, f"publication {field_name} mismatch")
                await tx.execute(
                    """
                    UPDATE {{tables.a2a_route_publications}}
                    SET status = 'revoked',
                        assertion_signature = $2,
                        assertion_canonical = $3,
                        assertion_digest = $4,
                        updated_at = NOW(),
                        revoked_at = NOW()
                    WHERE assertion_id = $1
                    """,
                    fields.assertion_id,
                    body.signature,
                    canonical.decode("utf-8"),
                    assertion_digest,
                )
                return A2AWriteResponse(
                    status="revoked",
                    assertion_id=fields.assertion_id,
                    assertion_digest=assertion_digest,
                    address=fields.address,
                    route_id=fields.route_id,
                )
            if existing_assertion["assertion_digest"] == assertion_digest:
                return A2AWriteResponse(
                    status="already_applied",
                    assertion_id=fields.assertion_id,
                    assertion_digest=assertion_digest,
                    address=fields.address,
                    route_id=fields.route_id,
                )
            raise _error(409, _PUBLICATION_EXISTS_DIFFERENT_DIGEST, "publication id exists with different digest")
        if fields.status == A2A_STATUS_REVOKED:
            raise _error(409, _PUBLICATION_EXISTS_DIFFERENT_DIGEST, "cannot revoke a publication that is not registered")

        if fields.status == A2A_STATUS_ACTIVE:
            active_route = await tx.fetch_one(
                """
                SELECT assertion_id, gateway_identity, card_digest
                FROM {{tables.a2a_route_publications}}
                WHERE address = $1
                  AND route_id = $2
                  AND status = 'active'
                  AND revoked_at IS NULL
                FOR SHARE
                """,
                fields.address,
                fields.route_id,
            )
            if active_route is not None:
                if active_route["gateway_identity"] != fields.gateway_identity:
                    raise _error(409, _PUBLICATION_EXISTS_DIFFERENT_GATEWAY, "active route uses different gateway")
                if active_route["card_digest"] != fields.card_digest:
                    raise _error(409, _PUBLICATION_EXISTS_DIFFERENT_DIGEST, "active route uses different card digest")
                raise _error(409, _PUBLICATION_EXISTS_DIFFERENT_DIGEST, "active route already has a different publication")

        await tx.execute(
            """
            INSERT INTO {{tables.a2a_route_publications}}
                (assertion_id, address, did_aw, current_did_key, signer_did, signer_kid,
                 card_url, rpc_url, route_id, tenant, gateway_identity, delegation_id,
                 delegation_digest, card_digest_alg, card_digest, card_revision, default_for_host,
                 status, published_at_text, expires_at_text, registry_url, identity_custody,
                 authority_source, assertion_signature, assertion_canonical, assertion_digest,
                 published_at, expires_at, revoked_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,
                    $18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29)
            """,
            fields.assertion_id,
            fields.address,
            fields.did_aw,
            fields.current_did_key,
            fields.signer_did,
            fields.signer_kid,
            fields.card_url,
            fields.rpc_url,
            fields.route_id,
            fields.tenant,
            fields.gateway_identity,
            fields.delegation_id,
            fields.delegation_digest,
            fields.card_digest_alg,
            fields.card_digest,
            fields.card_revision,
            fields.default_for_host,
            fields.status,
            fields.published_at,
            fields.expires_at,
            fields.registry_url,
            fields.identity_custody,
            fields.authority_source,
            body.signature,
            canonical.decode("utf-8"),
            assertion_digest,
            published_at,
            expires_at,
            None if fields.status == A2A_STATUS_ACTIVE else _now(),
        )

    logger.info(
        "a2a_publication_publish request_id=%s outcome=applied assertion_id=%s address_hash=%s gateway_hash=%s",
        request_id,
        fields.assertion_id,
        awid_sha256_hex(fields.address.encode("utf-8"))[:12],
        awid_sha256_hex(fields.gateway_identity.encode("utf-8"))[:12],
    )
    return A2AWriteResponse(
        status="applied",
        assertion_id=fields.assertion_id,
        assertion_digest=assertion_digest,
        address=fields.address,
        route_id=fields.route_id,
    )


@router.get(
    "/namespaces/{domain}/addresses/{name}/a2a",
    response_model=A2AAddressDirectoryResponse,
    response_model_exclude_none=True,
    dependencies=[Depends(rate_limit_dep("a2a_publication_get"))],
)
async def get_a2a_publication(
    request: Request,
    domain: str,
    name: str,
    db_infra=Depends(get_db),
) -> A2AAddressDirectoryResponse:
    try:
        address, domain, name = canonical_address(f"{domain}/{name}")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    db = db_infra.get_manager("aweb")
    row = await db.fetch_one(
        """
        SELECT pa.did_aw AS address_did_aw, pub.*
        FROM {{tables.public_addresses}} pa
        JOIN {{tables.dns_namespaces}} ns ON ns.namespace_id = pa.namespace_id
        LEFT JOIN LATERAL (
            SELECT *
            FROM {{tables.a2a_route_publications}} p
            WHERE p.address = $3
              AND p.status = 'active'
              AND p.revoked_at IS NULL
              AND p.expires_at > NOW()
              AND (
                  p.delegation_id IS NULL
                  OR EXISTS (
                      SELECT 1
                      FROM {{tables.a2a_bridge_delegations}} d
                      WHERE d.delegation_id = p.delegation_id
                        AND d.assertion_digest = p.delegation_digest
                        AND d.status = 'active'
                        AND d.revoked_at IS NULL
                        AND d.expires_at > NOW()
                  )
              )
            ORDER BY p.default_for_host DESC, p.published_at DESC
            LIMIT 1
        ) pub ON TRUE
        WHERE ns.domain = $1
          AND pa.name = $2
          AND pa.deleted_at IS NULL
          AND ns.deleted_at IS NULL
        """,
        domain,
        name,
        address,
    )
    if row is None:
        raise _error(404, _ADDRESS_NOT_REGISTERED, "address is not registered")

    entry = None
    if row["assertion_id"] is not None:
        entry = A2ADirectoryEntry(
            status=row["status"],
            card_url=row["card_url"],
            rpc_url=row["rpc_url"],
            route_id=row["route_id"],
            tenant=row["tenant"],
            gateway_identity=row["gateway_identity"],
            card_digest_alg=row["card_digest_alg"],
            card_digest=row["card_digest"],
            card_revision=row["card_revision"],
            publication_assertion_id=row["assertion_id"],
            delegation_id=row["delegation_id"],
            delegation_digest=row["delegation_digest"],
            published_at=row["published_at_text"],
            expires_at=row["expires_at_text"],
        )
    return A2AAddressDirectoryResponse(address=address, did_aw=validate_stable_id(row["address_did_aw"]), a2a=entry)


def a2a_conflict_codes() -> tuple[str, ...]:
    return A2A_CONFLICT_CODES


def a2a_publication_wire_payload(body: A2APublicationRequest) -> dict:
    return a2a_publication_payload(_body_to_publication_fields(body))


def a2a_delegation_wire_payload(body: A2ADelegationRequest) -> dict:
    return a2a_delegation_payload(_body_to_delegation_fields(body))
