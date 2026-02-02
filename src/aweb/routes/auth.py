from __future__ import annotations

import os
from uuid import UUID

from fastapi import APIRouter, Depends, Request

from aweb.auth import get_project_from_auth, parse_bearer_token, verify_bearer_token_details
from aweb.deps import get_db

router = APIRouter(prefix="/v1/auth", tags=["aweb-auth"])


@router.get("/introspect")
async def introspect(request: Request, db=Depends(get_db)) -> dict:
    """Validate the caller's auth context and return the scoped project_id.

    This endpoint exists primarily so BeadHub (as a separate service) can
    validate incoming Bearer tokens without owning API key verification.
    """
    # In proxy-header mode, the core may not have a Bearer token to introspect.
    if os.getenv("AWEB_TRUST_PROXY_HEADERS", "").strip().lower() in ("1", "true", "yes", "on"):
        project_id = await get_project_from_auth(request, db)
        return {"project_id": project_id}

    token = parse_bearer_token(request)
    if token is None:
        # get_project_from_auth() would already have raised; keep defensive behavior.
        return {"project_id": await get_project_from_auth(request, db)}

    details = await verify_bearer_token_details(db, token, manager_name="aweb")
    result: dict = {"project_id": details["project_id"], "api_key_id": details["api_key_id"]}
    if details.get("agent_id"):
        result["agent_id"] = details["agent_id"]
        aweb_db = db.get_manager("aweb")
        agent = await aweb_db.fetch_one(
            """
            SELECT alias, human_name, agent_type
            FROM {{tables.agents}}
            WHERE agent_id = $1 AND project_id = $2
            """,
            UUID(details["agent_id"]),
            UUID(details["project_id"]),
        )
        if agent:
            result["alias"] = agent["alias"]
            result["human_name"] = agent.get("human_name") or ""
            result["agent_type"] = agent.get("agent_type") or "agent"
    if details.get("user_id"):
        result["user_id"] = details["user_id"]
    return result
