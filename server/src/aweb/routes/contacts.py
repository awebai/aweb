from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator

from awid.federation_errors import FederationAuthorityError
from awid.signing import canonical_json_bytes, verify_did_key_signature

from aweb.messaging.handle_addresses import normalize_hosted_handle_reference
from aweb.messaging.contacts import (
    CONTACT_ADDRESS_PATTERN,
    add_contact,
    bind_contact_identity,
    list_contacts,
    normalize_owner_dids,
    remove_contact,
)
from aweb.deps import get_db
from aweb.identity_auth_deps import MessagingAuth, get_messaging_auth

router = APIRouter(prefix="/v1/contacts", tags=["aweb-contacts"])


def _owner_dids(identity: MessagingAuth) -> list[str]:
    return normalize_owner_dids(owner_dids=[identity.did_aw, identity.did_key])


class CreateContactRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    contact_address: str = Field(..., min_length=1, max_length=256)
    label: str = Field(default="")

    @field_validator("contact_address")
    @classmethod
    def _validate_contact_address(cls, v: str) -> str:
        v = normalize_hosted_handle_reference(v)
        if not v:
            raise ValueError("contact_address must not be empty")
        if not CONTACT_ADDRESS_PATTERN.match(v):
            raise ValueError("Invalid contact_address format")
        return v


class ContactView(BaseModel):
    contact_id: str
    contact_address: str | None
    label: str
    created_at: str
    reference_type: str = "identity"
    status: str = "active"
    handle_namespace: str | None = None
    target_agent_name: str | None = None
    contact_did_aw: str | None = None
    binding_controller_did: str | None = None
    binding_accepted_at: str | None = None


class ListContactsResponse(BaseModel):
    contacts: list[ContactView]


@router.post("", response_model=ContactView)
async def create_contact(
    request: Request, payload: CreateContactRequest, db=Depends(get_db),
    identity: MessagingAuth = Depends(get_messaging_auth),
) -> ContactView:
    owner_keys = _owner_dids(identity)
    owner_did = owner_keys[0] if owner_keys else ""
    authority = getattr(request.app.state, "federation_authority", None)
    if authority is None:
        raise FederationAuthorityError("federation_authority_coordination_unavailable")
    resolved = await authority.resolve_contact(
        payload.contact_address,
        source_ip=str(request.client.host if request.client else "unknown"),
    )
    result = await add_contact(
        db,
        owner_did=owner_did,
        contact_address=resolved.canonical_address,
        contact_did_aw=resolved.did_aw,
        binding_controller_did=resolved.controller_did,
        label=payload.label,
    )
    return ContactView(**result)


class BindContactIdentityRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_old_did_aw: str | None = None
    address: str = Field(..., min_length=1, max_length=256)
    new_did_aw: str | None = None
    controller_did: str | None = None
    timestamp: str | None = None
    signature: str | None = None
    accept_reassignment: bool = False


@router.post("/{contact_id}/bind", response_model=ContactView)
async def bind_contact_identity_route(
    request: Request,
    contact_id: str,
    payload: BindContactIdentityRequest,
    db=Depends(get_db),
    identity: MessagingAuth = Depends(get_messaging_auth),
) -> ContactView:
    authority = getattr(request.app.state, "federation_authority", None)
    if authority is None:
        raise FederationAuthorityError("federation_authority_coordination_unavailable")
    resolved = await authority.resolve_contact(
        payload.address,
        source_ip=str(request.client.host if request.client else "unknown"),
    )
    replacement = bool(payload.expected_old_did_aw and payload.expected_old_did_aw != resolved.did_aw)
    if replacement:
        if (
            payload.new_did_aw != resolved.did_aw
            or payload.controller_did != resolved.controller_did
            or not payload.timestamp
            or not payload.signature
            or not payload.accept_reassignment
        ):
            raise FederationAuthorityError("contact_identity_binding_required")
        try:
            announcement_time = datetime.fromisoformat(
                payload.timestamp.replace("Z", "+00:00")
            )
            if announcement_time.tzinfo is None or announcement_time.microsecond != 0:
                raise ValueError("replacement timestamp shape")
            if abs(
                (
                    datetime.now(timezone.utc)
                    - announcement_time.astimezone(timezone.utc)
                ).total_seconds()
            ) > 300:
                raise ValueError("replacement timestamp stale")
        except Exception as exc:
            raise FederationAuthorityError(
                "contact_identity_binding_required"
            ) from exc
        announcement = canonical_json_bytes(
            {
                "address": resolved.canonical_address,
                "controller_did": payload.controller_did,
                "new_did": payload.new_did_aw,
                "old_did": payload.expected_old_did_aw,
                "timestamp": payload.timestamp,
            }
        )
        try:
            verify_did_key_signature(
                did_key=payload.controller_did,
                payload=announcement,
                signature_b64=payload.signature,
            )
        except Exception as exc:
            raise FederationAuthorityError("contact_identity_binding_required") from exc
    result = await bind_contact_identity(
        db,
        owner_dids=_owner_dids(identity),
        contact_id=contact_id,
        contact_address=resolved.canonical_address,
        expected_old_did_aw=payload.expected_old_did_aw,
        contact_did_aw=resolved.did_aw,
        controller_did=resolved.controller_did,
        replacement_accepted=replacement,
    )
    return ContactView(**result)


@router.get("", response_model=ListContactsResponse)
async def list_contacts_route(
    request: Request, db=Depends(get_db),
    identity: MessagingAuth = Depends(get_messaging_auth),
) -> ListContactsResponse:
    contacts = await list_contacts(db, owner_dids=_owner_dids(identity))
    return ListContactsResponse(contacts=[ContactView(**c) for c in contacts])


@router.delete("/{contact_id}")
async def delete_contact(
    request: Request, contact_id: str, db=Depends(get_db),
    identity: MessagingAuth = Depends(get_messaging_auth),
) -> dict:
    await remove_contact(db, owner_dids=_owner_dids(identity), contact_id=contact_id)
    return {"deleted": True}
