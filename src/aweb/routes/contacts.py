from __future__ import annotations

import re
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator

from aweb.auth import get_project_from_auth
from aweb.deps import get_db

CONTACT_ADDRESS_PATTERN = re.compile(r"^[a-zA-Z0-9/_.\-]+$")

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
    aweb_db = db.get_manager("aweb")

    # Look up project slug for self-contact check.
    proj = await aweb_db.fetch_one(
        "SELECT slug FROM {{tables.projects}} WHERE project_id = $1 AND deleted_at IS NULL",
        UUID(project_id),
    )
    if proj is None:
        raise HTTPException(status_code=404, detail="Project not found")

    slug = proj["slug"]
    addr = payload.contact_address.strip()
    if addr == slug or addr.startswith(slug + "/"):
        raise HTTPException(status_code=400, detail="Cannot add self as contact")

    row = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.contacts}} (project_id, contact_address, label)
        VALUES ($1, $2, $3)
        ON CONFLICT (project_id, contact_address) DO NOTHING
        RETURNING contact_id, contact_address, label, created_at
        """,
        UUID(project_id),
        addr,
        payload.label,
    )
    if row is None:
        raise HTTPException(status_code=409, detail="Contact already exists")

    return ContactView(
        contact_id=str(row["contact_id"]),
        contact_address=row["contact_address"],
        label=row["label"],
        created_at=row["created_at"].isoformat(),
    )


@router.get("", response_model=ListContactsResponse)
async def list_contacts(request: Request, db=Depends(get_db)) -> ListContactsResponse:
    project_id = await get_project_from_auth(request, db, manager_name="aweb")
    aweb_db = db.get_manager("aweb")

    rows = await aweb_db.fetch_all(
        """
        SELECT contact_id, contact_address, label, created_at
        FROM {{tables.contacts}}
        WHERE project_id = $1
        ORDER BY contact_address
        """,
        UUID(project_id),
    )

    return ListContactsResponse(
        contacts=[
            ContactView(
                contact_id=str(r["contact_id"]),
                contact_address=r["contact_address"],
                label=r["label"],
                created_at=r["created_at"].isoformat(),
            )
            for r in rows
        ]
    )


@router.delete("/{contact_id}")
async def delete_contact(request: Request, contact_id: str, db=Depends(get_db)) -> dict:
    project_id = await get_project_from_auth(request, db, manager_name="aweb")

    try:
        contact_uuid = UUID(contact_id.strip())
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid contact_id format")

    aweb_db = db.get_manager("aweb")
    await aweb_db.execute(
        "DELETE FROM {{tables.contacts}} WHERE contact_id = $1 AND project_id = $2",
        contact_uuid,
        UUID(project_id),
    )

    return {"deleted": True}
