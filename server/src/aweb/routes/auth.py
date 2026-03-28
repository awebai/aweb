from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Request

from aweb.auth import (
    get_project_from_auth,
    parse_bearer_token,
    verify_bearer_token_details,
)
from aweb.internal_auth import _trust_aweb_proxy_headers, parse_internal_auth_context
from aweb.deps import get_db

router = APIRouter(prefix="/v1/auth", tags=["aweb-auth"])


_AGENT_QUERY = """
    SELECT a.alias, a.human_name, a.agent_type, a.access_mode,
           a.role, a.program, a.context
    FROM {{tables.agents}} a
    JOIN {{tables.projects}} p USING (project_id)
    WHERE a.agent_id = $1 AND a.project_id = $2
      AND p.deleted_at IS NULL
"""


def _enrich_with_agent(result: dict, agent) -> None:
    """Add agent fields to an introspect result dict."""
    result["alias"] = agent["alias"]
    result["human_name"] = agent.get("human_name") or ""
    result["agent_type"] = agent.get("agent_type") or "agent"
    result["access_mode"] = agent.get("access_mode") or "open"
    result["role"] = agent.get("role")
    result["role_name"] = agent.get("role")
    result["program"] = agent.get("program")
    ctx = agent.get("context")
    result["context"] = _parse_json(ctx) if isinstance(ctx, str) else ctx


def _parse_json(val):
    """Parse a JSON string, returning None on failure."""
    if val is None:
        return None
    import json

    try:
        return json.loads(val)
    except (json.JSONDecodeError, TypeError):
        return val


@router.get("/introspect")
async def introspect(request: Request, db=Depends(get_db)) -> dict:
    """Validate the caller's auth context and return the scoped project_id.

    This endpoint exists primarily so wrapper or proxy deployments can validate
    incoming Bearer tokens without duplicating API key verification logic.
    """
    # In wrapper/proxy deployments, auth may already be validated upstream and
    # forwarded via signed proxy headers. In that mode, ignore any Bearer token
    # that may also be present because the wrapper's own keys are not stored in
    # aweb.api_keys.
    if _trust_aweb_proxy_headers():
        internal = parse_internal_auth_context(request)
        if internal is not None:
            internal_result: dict = {
                "project_id": internal["project_id"],
                "agent_id": internal["actor_id"],
            }
            if internal["principal_type"] == "k":
                internal_result["api_key_id"] = internal["principal_id"]
            elif internal["principal_type"] == "u":
                internal_result["user_id"] = internal["principal_id"]

            aweb_db = db.get_manager("aweb")
            agent = await aweb_db.fetch_one(
                _AGENT_QUERY,
                UUID(internal["actor_id"]),
                UUID(internal["project_id"]),
            )
            if agent:
                _enrich_with_agent(internal_result, agent)
            return internal_result

    token = parse_bearer_token(request)
    if token is None:
        # get_project_from_auth() would already have raised; keep defensive behavior.
        return {"project_id": await get_project_from_auth(request, db, manager_name="aweb")}

    details = await verify_bearer_token_details(db, token, manager_name="aweb")
    result: dict = {"project_id": details["project_id"], "api_key_id": details["api_key_id"]}
    if details.get("agent_id"):
        result["agent_id"] = details["agent_id"]
        aweb_db = db.get_manager("aweb")
        agent = await aweb_db.fetch_one(
            _AGENT_QUERY,
            UUID(details["agent_id"]),
            UUID(details["project_id"]),
        )
        if agent:
            _enrich_with_agent(result, agent)
    if details.get("user_id"):
        result["user_id"] = details["user_id"]
    return result
