from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator

from aweb.auth import get_project_from_auth
from aweb.contacts_service import CONTACT_ADDRESS_PATTERN, add_contact, list_contacts, remove_contact
from aweb.deps import get_db

router = APIRouter(prefix="/v1/contacts", tags=["aweb-contacts"])


class CreateContactRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    contact_address: str = Field(..., min_length=1, max_length=256)
    label: str | None = None

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
    label: str | None
    created_at: str


class ListContactsResponse(BaseModel):
    contacts: list[ContactView]


@router.post("", response_model=ContactView)
async def create_contact(
    request: Request, payload: CreateContactRequest, db=Depends(get_db)
) -> ContactView:
    project_id = await get_project_from_auth(request, db, manager_name="aweb")
    result = await add_contact(
        db,
        project_id=project_id,
        contact_address=payload.contact_address,
        label=payload.label,
    )
    return ContactView(**result)


@router.get("", response_model=ListContactsResponse)
async def list_contacts_route(request: Request, db=Depends(get_db)) -> ListContactsResponse:
    project_id = await get_project_from_auth(request, db, manager_name="aweb")
    contacts = await list_contacts(db, project_id=project_id)
    return ListContactsResponse(
        contacts=[ContactView(**c) for c in contacts]
    )


@router.delete("/{contact_id}")
async def delete_contact(request: Request, contact_id: str, db=Depends(get_db)) -> dict:
    project_id = await get_project_from_auth(request, db, manager_name="aweb")
    await remove_contact(db, project_id=project_id, contact_id=contact_id)
    return {"deleted": True}
