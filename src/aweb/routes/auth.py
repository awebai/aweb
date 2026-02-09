from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Request

from aweb.auth import (
    _parse_internal_auth_context,
    _trust_aweb_proxy_headers,
    get_project_from_auth,
    parse_bearer_token,
    verify_bearer_token_details,
)
from aweb.deps import get_db

router = APIRouter(prefix="/v1/auth", tags=["aweb-auth"])


@router.get("/introspect")
async def introspect(request: Request, db=Depends(get_db)) -> dict:
    """Validate the caller's auth context and return the scoped project_id.

    This endpoint exists primarily so BeadHub (as a separate service) can
    validate incoming Bearer tokens without owning API key verification.
    """
    # In wrapper/proxy deployments (BeadHub Cloud), auth is validated by the wrapper,
    # and aweb sees only signed proxy headers. In that mode, ignore any Bearer token
    # that may be present (Cloud keys are not stored in aweb.api_keys).
    if _trust_aweb_proxy_headers():
        internal = _parse_internal_auth_context(request)
        if internal is not None:
            result: dict = {
                "project_id": internal["project_id"],
                "agent_id": internal["actor_id"],
            }
            if internal["principal_type"] == "k":
                result["api_key_id"] = internal["principal_id"]
            elif internal["principal_type"] == "u":
                result["user_id"] = internal["principal_id"]

            aweb_db = db.get_manager("aweb")
            agent = await aweb_db.fetch_one(
                """
                SELECT alias, human_name, agent_type
                FROM {{tables.agents}}
                WHERE agent_id = $1 AND project_id = $2
                """,
                UUID(internal["actor_id"]),
                UUID(internal["project_id"]),
            )
            if agent:
                result["alias"] = agent["alias"]
                result["human_name"] = agent.get("human_name") or ""
                result["agent_type"] = agent.get("agent_type") or "agent"
            return result

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
