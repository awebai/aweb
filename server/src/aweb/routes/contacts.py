from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator

from aweb.messaging.contacts import (
    CONTACT_ADDRESS_PATTERN,
    add_contact,
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
        v = v.strip()
        if not v:
            raise ValueError("contact_address must not be empty")
        if not CONTACT_ADDRESS_PATTERN.match(v):
            raise ValueError("Invalid contact_address format")
        return v


class ContactView(BaseModel):
    contact_id: str
    contact_address: str
    label: str
    created_at: str


class ListContactsResponse(BaseModel):
    contacts: list[ContactView]


@router.post("", response_model=ContactView)
async def create_contact(
    request: Request, payload: CreateContactRequest, db=Depends(get_db),
    identity: MessagingAuth = Depends(get_messaging_auth),
) -> ContactView:
    owner_keys = _owner_dids(identity)
    owner_did = owner_keys[0] if owner_keys else ""
    result = await add_contact(
        db,
        owner_did=owner_did,
        contact_address=payload.contact_address,
        label=payload.label,
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
