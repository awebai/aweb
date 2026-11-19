"""Messaging participant discovery; the ordinary agent roster stays unchanged."""

# ruff: noqa: B008
from __future__ import annotations

from aweb.human_kind import effective_agent_type

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
from aweb.messaging.sender_address import sender_address
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
        registry_client=getattr(request.app.state, "awid_registry_client", None),
    )
    if not row or row.get("status") != "active":
        raise HTTPException(404, detail="Recipient not found")
    try:
        await authorize_message_delivery(
            db,
            recipient_agent=row,
            sender_did=auth.did_aw or auth.did_key,
            sender_address=sender_address(auth),
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
        "agent_type": effective_agent_type(row),
        "team_id": auth.team_id,
        "encryption_key": key,
    }
