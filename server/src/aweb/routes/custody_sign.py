from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, model_validator

from aweb.auth import get_actor_agent_id_from_auth
from aweb.awid.custody import CustodyError, SelfCustodialError, sign_arbitrary_payload

from ..db import DatabaseInfra, get_db_infra

router = APIRouter(prefix="/v1/custody", tags=["custody"])


class SignPayloadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sign_payload: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_sign_payload(self):
        if "timestamp" in self.sign_payload:
            raise ValueError("sign_payload must not include timestamp")
        return self


class SignPayloadResponse(BaseModel):
    did_key: str
    signature: str
    timestamp: str


@router.post("/sign", response_model=SignPayloadResponse)
async def sign_payload(
    request: Request,
    payload: SignPayloadRequest,
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> SignPayloadResponse:
    actor_id = await get_actor_agent_id_from_auth(request, db_infra, manager_name="aweb")
    try:
        did_key, signature, timestamp = await sign_arbitrary_payload(
            actor_id,
            payload.sign_payload,
            db_infra,
        )
    except SelfCustodialError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except CustodyError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    return SignPayloadResponse(
        did_key=did_key,
        signature=signature,
        timestamp=timestamp,
    )
