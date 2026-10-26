"""Messaging participant discovery; the ordinary agent roster stays unchanged."""

# ruff: noqa: B008
from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from uuid import UUID

from awid.e2ee_keys import validate_encryption_key_assertion
from fastapi import APIRouter, Depends, HTTPException, Request

from aweb.deps import get_db
from aweb.identity_auth_deps import MessagingAuth, auth_dids, get_messaging_auth
from aweb.messaging.messages import authorize_message_delivery
from aweb.messaging.participants import messaging_participant_by_alias
from aweb.service_errors import ServiceError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/messaging", tags=["messaging"])


@router.get("/participants/{alias}")
async def participant(
    alias: str,
    request: Request,
    db=Depends(get_db),
    auth: MessagingAuth = Depends(get_messaging_auth),
):
    """Selected-team identity/key discovery, not signing-custody authority.

    Key assertions retain their original identity signature. No assertion is
    needed for plaintext delivery; explicit encryption must refuse without one.
    """
    if not auth.team_id or any(c in alias for c in ("/", "~", ":")):
        raise HTTPException(422, detail="Selected-team participant alias required")
    row = await messaging_participant_by_alias(
        db,
        team_id=auth.team_id,
        alias=alias,
        selected_team_id=auth.team_id,
        request=request,
    )
    if not row or row.get("status") != "active":
        raise HTTPException(404, detail="Recipient not found")
    try:
        await authorize_message_delivery(
            db,
            recipient_agent=row,
            sender_did=auth.did_aw or auth.did_key,
            sender_address=auth.address,
            sender_team_id=auth.team_id,
            sender_verified_team_id=auth.verified_team_id,
            sender_verified_dids=auth_dids(auth),
        )
    except ServiceError as error:
        raise HTTPException(error.status_code, detail=error.detail) from error
    assertion = await db.get_manager("aweb").fetch_one(
        """SELECT assertion_canonical, assertion_signature FROM {{tables.agent_encryption_keys}}
           WHERE agent_id=$1 AND team_id=$2 AND identity_did=$3
             AND identity_stable_id IS NOT DISTINCT FROM $4
             AND revoked_at IS NULL AND not_before_at<=NOW() AND expires_at>NOW()
           ORDER BY assertion_created_at DESC, not_before_at DESC, encryption_key_id DESC LIMIT 1""",
        UUID(str(row["agent_id"])),
        auth.team_id,
        row["did_key"],
        row.get("did_aw") or None,
    )
    key = None
    if assertion:
        try:
            if row.get("did_aw"):
                registry = getattr(request.app.state, "awid_registry_client", None)
                if registry is None:
                    raise HTTPException(503, detail={"code": "authority_unavailable"})
                resolution = await registry.resolve_key_fresh(row["did_aw"])
                if (
                    not resolution
                    or resolution.did_aw != row["did_aw"]
                    or resolution.current_did_key != row["did_key"]
                ):
                    raise HTTPException(409, detail={"code": "stale"})
            key = {
                **json.loads(assertion["assertion_canonical"]),
                "signature": assertion["assertion_signature"],
            }
            validate_encryption_key_assertion(
                key,
                current_did_key=row["did_key"],
                stable_id=row.get("did_aw") or None,
                now=datetime.now(UTC),
            )
        except HTTPException:
            raise
        except ValueError as error:
            logger.warning(
                "Invalid participant encryption assertion for %s",
                row["agent_id"],
                exc_info=True,
            )
            raise HTTPException(
                422, detail={"code": "invalid_encryption_key_assertion"}
            ) from error
        except Exception as error:
            logger.warning(
                "Participant current-key authority unavailable for %s",
                row["agent_id"],
                exc_info=True,
            )
            raise HTTPException(
                503, detail={"code": "authority_unavailable"}
            ) from error
    return {
        **{
            name: str(row[name]) if name == "agent_id" else row.get(name)
            for name in (
                "agent_id",
                "alias",
                "did_key",
                "did_aw",
                "address",
                "agent_type",
                "status",
            )
        },
        "team_id": auth.team_id,
        "encryption_key": key,
    }


# Embeddings configure a NativeMessagingService using its public constructor.
# Missing current custody/access authority disables the advanced facade; it does
# not change native alias routing or imply self custody.
def _service(request):
    service = getattr(request.app.state, "human_channels_service", None)
    if service is None:
        from aweb.human_channels.contract import ContractError

        raise ContractError(
            "authority_unavailable", "configured custody/access authority"
        )
    return service


def _record(schema, value):
    from awid.signing import canonical_json_bytes

    from aweb.human_channels.contract import decode_record

    return decode_record(schema, canonical_json_bytes(value))


def _refusal(error, family):
    status = {
        "forbidden": 403,
        "not_found": 404,
        "unsupported": 422,
        "invalid": 422,
        "stale": 409,
        "replay_conflict": 409,
        "authority_unavailable": 503,
        "limit_exceeded": 429,
    }.get(error.code, 422)
    retry = (
        "refresh"
        if error.code == "stale"
        else "backoff"
        if error.code in ("authority_unavailable", "limit_exceeded")
        else "never"
    )
    logger.warning("Human channels %s refused: %s", family, error)
    return HTTPException(
        status,
        detail=_record(
            "Refusal",
            {
                "version": "aweb-human-channels-error-v1",
                "family": family,
                "code": error.code,
                "retry": retry,
                "effects": "none",
            },
        ).value,
    )


@router.get("/capabilities")
async def capabilities(
    request: Request, auth: MessagingAuth = Depends(get_messaging_auth)
):
    service = getattr(request.app.state, "human_channels_service", None)
    if service is None:
        return {
            "version": "aweb-human-channels-capabilities-v1",
            "implemented": ["human-alias-v1"],
            "enabled": ["human-alias-v1"],
            "refused": ["human-send-uow-v1"],
        }
    return (await service.capabilities(auth)).value


@router.post("/resolve")
async def resolve(request: Request, auth: MessagingAuth = Depends(get_messaging_auth)):
    from aweb.human_channels.contract import ContractError, decode_record

    try:
        return (
            await _service(request).resolve(
                auth, decode_record("ResolveRequest", await request.body())
            )
        ).value
    except ContractError as error:
        raise _refusal(error, "resolve") from error


@router.post("/prepare")
async def prepare(request: Request, auth: MessagingAuth = Depends(get_messaging_auth)):
    from aweb.human_channels.contract import ContractError, decode_record

    try:
        return (
            await _service(request).prepare(
                auth, decode_record("PrepareRequest", await request.body())
            )
        ).value
    except ContractError as error:
        raise _refusal(error, "prepare") from error


@router.get("/ingress-results/{namespace}/{key}")
async def ingress_result(
    namespace: str,
    key: str,
    input_hash: str,
    request: Request,
    auth: MessagingAuth = Depends(get_messaging_auth),
):
    from aweb.human_channels.contract import ContractError

    try:
        lookup = _record(
            "IngressKey",
            {
                "issuer": auth.did_aw or auth.did_key,
                "namespace": namespace,
                "key": key,
                "input_hash": input_hash,
            },
        )
        return (await _service(request).ingress_result(auth, lookup)).value
    except ContractError as error:
        raise _refusal(error, "accept") from error
