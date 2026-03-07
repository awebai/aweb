from __future__ import annotations

import json
import logging
from typing import Any
from uuid import UUID

from aweb.messages_service import deliver_message
from aweb.messages_service import utc_iso as _utc_iso
from fastapi import APIRouter, Depends, HTTPException, Request
from redis.asyncio import Redis

from beadhub.auth import verify_workspace_access
from beadhub.aweb_introspection import AuthIdentity, get_identity_from_auth, get_project_from_auth

from ..db import DatabaseInfra, get_db_infra
from ..presence import (
    get_workspace_ids_by_project_id,
    list_agent_presences_by_workspace_ids,
    update_agent_presence,
)
from ..redis_client import get_redis
from .beads import beads_ready as http_beads_ready
from .beads import get_issue_by_bead_id as http_get_issue
from .escalations import (
    CreateEscalationRequest,
    CreateEscalationResponse,
    create_escalation,
)
from .escalations import get_escalation as http_get_escalation
from .status import status as http_status
from .subscriptions import SubscribeRequest
from .subscriptions import list_subscriptions as http_list_subscriptions
from .subscriptions import subscribe as http_subscribe
from .subscriptions import unsubscribe as http_unsubscribe

logger = logging.getLogger(__name__)

router = APIRouter(tags=["mcp"])


def _rpc_error(id_value: Any, code: int, message: str, data: Any | None = None) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": id_value, "error": error}


def _rpc_result(id_value: Any, payload: Any) -> dict[str, Any]:
    # MCP clients expect text content with a JSON string payload.
    return {
        "jsonrpc": "2.0",
        "id": id_value,
        "result": {"content": [{"type": "text", "text": json.dumps(payload)}]},
    }


TOOL_CATALOG: list[dict[str, Any]] = [
    {
        "name": "register_agent",
        "description": "Register agent presence for a workspace.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspace_id": {"type": "string", "description": "Workspace UUID"},
                "alias": {"type": "string", "description": "Agent alias"},
                "human_name": {"type": "string", "description": "Human operator name"},
                "program": {"type": "string", "description": "Agent program name"},
                "model": {"type": "string", "description": "Model identifier"},
                "role": {"type": "string", "description": "Agent role"},
            },
            "required": ["workspace_id", "alias"],
        },
    },
    {
        "name": "list_agents",
        "description": "List all agents with active presence in the project.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspace_id": {"type": "string", "description": "Workspace UUID"},
            },
            "required": ["workspace_id"],
        },
    },
    {
        "name": "status",
        "description": "Get workspace status including agents, claims, and conflicts.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspace_id": {"type": "string", "description": "Workspace UUID"},
            },
            "required": ["workspace_id"],
        },
    },
    {
        "name": "get_ready_issues",
        "description": "List beads issues that are ready to work on (open, no blockers).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspace_id": {"type": "string", "description": "Workspace UUID"},
                "repo": {"type": "string", "description": "Filter by repo canonical origin"},
                "branch": {"type": "string", "description": "Filter by branch"},
                "limit": {"type": "integer", "description": "Max results (default 10)"},
            },
            "required": ["workspace_id"],
        },
    },
    {
        "name": "get_issue",
        "description": "Get details of a specific beads issue by bead_id.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "bead_id": {"type": "string", "description": "Bead issue ID"},
            },
            "required": ["bead_id"],
        },
    },
    {
        "name": "subscribe_to_bead",
        "description": "Subscribe to status change notifications for a bead.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspace_id": {"type": "string", "description": "Workspace UUID"},
                "bead_id": {"type": "string", "description": "Bead issue ID"},
                "repo": {"type": "string", "description": "Repo canonical origin"},
                "event_types": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Event types to subscribe to",
                },
            },
            "required": ["workspace_id", "bead_id"],
        },
    },
    {
        "name": "list_subscriptions",
        "description": "List active bead subscriptions for a workspace.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspace_id": {"type": "string", "description": "Workspace UUID"},
            },
            "required": ["workspace_id"],
        },
    },
    {
        "name": "unsubscribe",
        "description": "Remove a bead subscription.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspace_id": {"type": "string", "description": "Workspace UUID"},
                "subscription_id": {"type": "string", "description": "Subscription ID"},
            },
            "required": ["workspace_id", "subscription_id"],
        },
    },
    {
        "name": "escalate",
        "description": "Create a human-in-the-loop escalation.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspace_id": {"type": "string", "description": "Workspace UUID"},
                "alias": {"type": "string", "description": "Agent alias"},
                "subject": {"type": "string", "description": "Escalation subject"},
                "situation": {"type": "string", "description": "Description of the situation"},
                "options": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Options for the human to choose from",
                },
                "expires_in_hours": {"type": "integer", "description": "Hours until expiry"},
                "member_email": {"type": "string", "description": "Email to notify"},
            },
            "required": ["workspace_id", "alias", "subject", "situation"],
        },
    },
    {
        "name": "get_escalation",
        "description": "Get details of an escalation by ID.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "escalation_id": {"type": "string", "description": "Escalation ID"},
            },
            "required": ["escalation_id"],
        },
    },
    {
        "name": "ensure_project",
        "description": "Idempotently verify the current project exists and return its info (Agent Mail compatible).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "human_key": {
                    "type": "string",
                    "description": "Working directory path (Agent Mail convention). Accepted for compatibility; project resolved from auth.",
                },
                "project_key": {
                    "type": "string",
                    "description": "Project slug. If provided, validated against the authenticated project.",
                },
            },
        },
    },
    {
        "name": "send_message",
        "description": "Send a message to one or more agents (Agent Mail compatible).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_key": {"type": "string", "description": "Project slug"},
                "sender_name": {"type": "string", "description": "Sender agent alias"},
                "to": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Recipient agent aliases",
                },
                "subject": {"type": "string", "description": "Message subject"},
                "body_md": {"type": "string", "description": "Message body (markdown)"},
                "importance": {
                    "type": "string",
                    "description": "Message priority (normal, urgent)",
                    "default": "normal",
                },
                "thread_id": {"type": "string", "description": "Thread UUID for grouping"},
            },
            "required": ["project_key", "sender_name", "to", "subject", "body_md"],
        },
    },
    {
        "name": "fetch_inbox",
        "description": "Fetch inbox messages for an agent (Agent Mail compatible).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_key": {"type": "string", "description": "Project slug"},
                "agent_name": {"type": "string", "description": "Agent alias"},
                "limit": {"type": "integer", "description": "Max messages to return"},
                "urgent_only": {"type": "boolean", "description": "Only urgent messages"},
                "include_bodies": {
                    "type": "boolean",
                    "description": "Include message bodies",
                    "default": True,
                },
                "since_ts": {"type": "string", "description": "ISO timestamp filter"},
            },
            "required": ["project_key", "agent_name"],
        },
    },
    {
        "name": "acknowledge_message",
        "description": "Acknowledge a message (Agent Mail compatible).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_key": {"type": "string", "description": "Project slug"},
                "agent_name": {"type": "string", "description": "Agent alias"},
                "message_id": {"type": "string", "description": "Message UUID"},
            },
            "required": ["project_key", "agent_name", "message_id"],
        },
    },
    {
        "name": "mark_message_read",
        "description": "Mark a message as read (Agent Mail compatible).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_key": {"type": "string", "description": "Project slug"},
                "agent_name": {"type": "string", "description": "Agent alias"},
                "message_id": {"type": "string", "description": "Message UUID"},
            },
            "required": ["project_key", "agent_name", "message_id"],
        },
    },
    {
        "name": "reply_message",
        "description": "Reply to a message, preserving the thread (Agent Mail compatible).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_key": {"type": "string", "description": "Project slug"},
                "message_id": {"type": "string", "description": "Message UUID to reply to"},
                "sender_name": {"type": "string", "description": "Sender agent alias"},
                "body_md": {"type": "string", "description": "Reply body (markdown)"},
                "to": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Override recipients (default: original sender)",
                },
                "subject_prefix": {
                    "type": "string",
                    "description": "Subject prefix (default: Re:)",
                    "default": "Re:",
                },
            },
            "required": ["project_key", "message_id", "sender_name", "body_md"],
        },
    },
]

RESOURCE_CATALOG: list[dict[str, Any]] = [
    {
        "uri": "beadhub://status",
        "name": "Workspace status",
        "description": "Agents, claims, conflicts, and escalations for the current project.",
        "mimeType": "application/json",
    },
]


@router.post("/mcp")
async def mcp_entry(
    request: Request,
    payload: dict[str, Any],
    redis: Redis = Depends(get_redis),
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> dict[str, Any]:
    """JSON-RPC 2.0 entrypoint for BeadHub MCP tools.

    Clean-slate split:
    - mail/chat/locks live in aweb and are not exposed here
    - this surface is bead/workspace specific (ready issues, subscriptions, status, escalations)
    """
    rpc_id = payload.get("id")
    if payload.get("jsonrpc") != "2.0":
        return _rpc_error(rpc_id, -32600, "Invalid jsonrpc version")

    # Authenticate before dispatching any method.
    try:
        await get_project_from_auth(request, db_infra)
    except HTTPException as exc:
        return _rpc_error(rpc_id, exc.status_code, str(exc.detail))

    method = payload.get("method")

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rpc_id, "result": {"tools": TOOL_CATALOG}}

    if method == "resources/list":
        return {"jsonrpc": "2.0", "id": rpc_id, "result": {"resources": RESOURCE_CATALOG}}

    if method == "resources/read":
        return await _handle_resources_read(rpc_id, request, redis, db_infra, payload)

    if method == "tools/call":
        return await _handle_tools_call(rpc_id, request, redis, db_infra, payload)

    return _rpc_error(rpc_id, -32601, f"Method not found: {method}")


async def _handle_resources_read(
    rpc_id: Any,
    request: Request,
    redis: Redis,
    db_infra: DatabaseInfra,
    payload: dict[str, Any],
) -> dict[str, Any]:
    params = payload.get("params") or {}
    uri = params.get("uri")
    if not isinstance(uri, str) or not uri:
        return _rpc_error(rpc_id, -32602, "uri parameter is required")

    try:
        if uri == "beadhub://status":
            data = await http_status(
                request, workspace_id=None, repo_id=None, redis=redis, db_infra=db_infra
            )
        else:
            return _rpc_error(rpc_id, -32602, f"Unknown resource URI: {uri}")
    except HTTPException as exc:
        return _rpc_error(rpc_id, exc.status_code, str(exc.detail))
    except Exception:
        logger.exception("MCP resources/read failed: %s", uri)
        return _rpc_error(rpc_id, -32000, "Internal error")

    return {
        "jsonrpc": "2.0",
        "id": rpc_id,
        "result": {
            "contents": [
                {
                    "uri": uri,
                    "mimeType": "application/json",
                    "text": json.dumps(data),
                }
            ]
        },
    }


async def _handle_tools_call(
    rpc_id: Any,
    request: Request,
    redis: Redis,
    db_infra: DatabaseInfra,
    payload: dict[str, Any],
) -> dict[str, Any]:
    params = payload.get("params") or {}
    name = params.get("name")
    arguments = params.get("arguments") or {}
    if not isinstance(name, str):
        return _rpc_error(rpc_id, -32602, "Tool name must be a string")
    if not isinstance(arguments, dict):
        return _rpc_error(rpc_id, -32602, "Tool arguments must be an object")

    try:
        if name == "register_agent":
            result = await _tool_register_agent(request, redis, db_infra, arguments)
        elif name == "list_agents":
            result = await _tool_list_agents(request, redis, db_infra, arguments)
        elif name == "status":
            result = await _tool_status(request, redis, db_infra, arguments)
        elif name == "get_ready_issues":
            result = await _tool_get_ready_issues(request, db_infra, arguments)
        elif name == "get_issue":
            result = await _tool_get_issue(request, db_infra, arguments)
        elif name == "subscribe_to_bead":
            result = await _tool_subscribe_to_bead(request, db_infra, arguments)
        elif name == "list_subscriptions":
            result = await _tool_list_subscriptions(request, db_infra, arguments)
        elif name == "unsubscribe":
            result = await _tool_unsubscribe(request, db_infra, arguments)
        elif name == "escalate":
            result = await _tool_escalate(request, redis, db_infra, arguments)
        elif name == "get_escalation":
            result = await _tool_get_escalation(request, db_infra, arguments)
        elif name == "ensure_project":
            result = await _tool_ensure_project(request, db_infra, arguments)
        elif name == "send_message":
            result = await _tool_send_message(request, db_infra, arguments)
        elif name == "fetch_inbox":
            result = await _tool_fetch_inbox(request, db_infra, arguments)
        elif name == "acknowledge_message":
            result = await _tool_acknowledge_message(request, db_infra, arguments)
        elif name == "mark_message_read":
            result = await _tool_mark_message_read(request, db_infra, arguments)
        elif name == "reply_message":
            result = await _tool_reply_message(request, db_infra, arguments)
        else:
            return _rpc_error(rpc_id, -32601, f"Unknown tool: {name}")
    except HTTPException as exc:
        return _rpc_error(rpc_id, exc.status_code, str(exc.detail))
    except Exception:
        logger.exception("MCP tool call failed: %s", name)
        return _rpc_error(rpc_id, -32000, "Internal error")

    return _rpc_result(rpc_id, result)


async def _tool_register_agent(
    request: Request,
    redis: Redis,
    db_infra: DatabaseInfra,
    args: dict[str, Any],
) -> dict[str, Any]:
    workspace_id = str(args.get("workspace_id") or "").strip()
    alias = str(args.get("alias") or "").strip()
    human_name = str(args.get("human_name") or "").strip()
    program = str(args.get("program") or "").strip() or None
    model = str(args.get("model") or "").strip() or None
    role = str(args.get("role") or "").strip() or None

    if not workspace_id or not alias:
        raise HTTPException(status_code=422, detail="workspace_id and alias are required")

    project_id = await verify_workspace_access(request, workspace_id, db_infra)
    await update_agent_presence(
        redis,
        workspace_id=workspace_id,
        alias=alias,
        human_name=human_name,
        project_id=project_id,
        project_slug=None,
        repo_id=None,
        program=program,
        model=model,
        current_branch=None,
        role=role,
        ttl_seconds=1800,
    )
    return {"ok": True}


async def _tool_list_agents(
    request: Request,
    redis: Redis,
    db_infra: DatabaseInfra,
    args: dict[str, Any],
) -> dict[str, Any]:
    workspace_id = str(args.get("workspace_id") or "").strip()
    if not workspace_id:
        raise HTTPException(status_code=422, detail="workspace_id is required")
    project_id = await verify_workspace_access(request, workspace_id, db_infra)
    workspace_ids = await get_workspace_ids_by_project_id(redis, project_id)
    agents = await list_agent_presences_by_workspace_ids(redis, workspace_ids)
    return {"agents": agents}


async def _tool_status(
    request: Request,
    redis: Redis,
    db_infra: DatabaseInfra,
    args: dict[str, Any],
) -> dict[str, Any]:
    workspace_id = str(args.get("workspace_id") or "").strip()
    if not workspace_id:
        raise HTTPException(status_code=422, detail="workspace_id is required")
    await verify_workspace_access(request, workspace_id, db_infra)
    return await http_status(request, workspace_id=workspace_id, redis=redis, db_infra=db_infra)


async def _tool_get_ready_issues(
    request: Request,
    db_infra: DatabaseInfra,
    args: dict[str, Any],
) -> dict[str, Any]:
    workspace_id = str(args.get("workspace_id") or "").strip()
    repo = str(args.get("repo") or "").strip() or None
    branch = str(args.get("branch") or "").strip() or None
    limit_raw = args.get("limit")
    limit = 10
    if limit_raw is not None:
        try:
            limit = int(limit_raw)
        except (TypeError, ValueError):
            raise HTTPException(status_code=422, detail="limit must be an integer")
    if not workspace_id:
        raise HTTPException(status_code=422, detail="workspace_id is required")
    await verify_workspace_access(request, workspace_id, db_infra)
    return await http_beads_ready(
        request,
        workspace_id=workspace_id,
        repo=repo,
        branch=branch,
        limit=limit,
        db_infra=db_infra,
    )


async def _tool_get_issue(
    request: Request,
    db_infra: DatabaseInfra,
    args: dict[str, Any],
) -> dict[str, Any]:
    bead_id = str(args.get("bead_id") or "").strip()
    if not bead_id:
        raise HTTPException(status_code=422, detail="bead_id is required")
    # get_issue endpoint already enforces project scoping.
    return await http_get_issue(bead_id=bead_id, request=request, db_infra=db_infra)


async def _tool_subscribe_to_bead(
    request: Request,
    db_infra: DatabaseInfra,
    args: dict[str, Any],
) -> dict[str, Any]:
    workspace_id = str(args.get("workspace_id") or "").strip()
    bead_id = str(args.get("bead_id") or "").strip()
    repo = args.get("repo")
    event_types = args.get("event_types")
    if not workspace_id or not bead_id:
        raise HTTPException(status_code=422, detail="workspace_id and bead_id are required")
    project_id = await verify_workspace_access(request, workspace_id, db_infra)
    alias = await _get_workspace_alias_or_403(db_infra, project_id, workspace_id)
    payload_kwargs: dict[str, Any] = {
        "workspace_id": workspace_id,
        "alias": alias,
        "bead_id": bead_id,
        "repo": repo,
    }
    if isinstance(event_types, list):
        payload_kwargs["event_types"] = event_types
    payload = SubscribeRequest.model_validate(payload_kwargs)
    response = await http_subscribe(payload=payload, request=request, db_infra=db_infra)
    return response.model_dump()


async def _tool_list_subscriptions(
    request: Request,
    db_infra: DatabaseInfra,
    args: dict[str, Any],
) -> dict[str, Any]:
    workspace_id = str(args.get("workspace_id") or "").strip()
    if not workspace_id:
        raise HTTPException(status_code=422, detail="workspace_id is required")
    project_id = await verify_workspace_access(request, workspace_id, db_infra)
    alias = await _get_workspace_alias_or_403(db_infra, project_id, workspace_id)
    response = await http_list_subscriptions(
        request=request,
        workspace_id=workspace_id,
        alias=alias,
        db_infra=db_infra,
    )
    return response.model_dump()


async def _tool_unsubscribe(
    request: Request,
    db_infra: DatabaseInfra,
    args: dict[str, Any],
) -> dict[str, Any]:
    workspace_id = str(args.get("workspace_id") or "").strip()
    subscription_id = str(args.get("subscription_id") or "").strip()
    if not workspace_id or not subscription_id:
        raise HTTPException(status_code=422, detail="workspace_id and subscription_id are required")
    project_id = await verify_workspace_access(request, workspace_id, db_infra)
    alias = await _get_workspace_alias_or_403(db_infra, project_id, workspace_id)
    response = await http_unsubscribe(
        request=request,
        subscription_id=subscription_id,
        workspace_id=workspace_id,
        alias=alias,
        db_infra=db_infra,
    )
    return response.model_dump()


async def _get_workspace_alias_or_403(
    db_infra: DatabaseInfra, project_id: str, workspace_id: str
) -> str:
    server_db = db_infra.get_manager("server")
    row = await server_db.fetch_one(
        """
        SELECT alias
        FROM {{tables.workspaces}}
        WHERE workspace_id = $1 AND project_id = $2 AND deleted_at IS NULL
        """,
        UUID(workspace_id),
        UUID(project_id),
    )
    if not row:
        raise HTTPException(
            status_code=403, detail="Workspace not found or does not belong to your project"
        )
    return row["alias"]


async def _tool_escalate(
    request: Request,
    redis: Redis,
    db_infra: DatabaseInfra,
    args: dict[str, Any],
) -> dict[str, Any]:
    payload = CreateEscalationRequest.model_validate(args)
    response: CreateEscalationResponse = await create_escalation(
        request=request, payload=payload, redis=redis, db_infra=db_infra
    )
    return response.model_dump()


async def _tool_get_escalation(
    request: Request,
    db_infra: DatabaseInfra,
    args: dict[str, Any],
) -> dict[str, Any]:
    escalation_id = str(args.get("escalation_id") or "").strip()
    if not escalation_id:
        raise HTTPException(status_code=422, detail="escalation_id is required")
    return await http_get_escalation(
        escalation_id=escalation_id, request=request, db_infra=db_infra
    )


# ---------------------------------------------------------------------------
# Agent Mail-compatible messaging tools
# ---------------------------------------------------------------------------


async def _resolve_agent_id(db_infra: DatabaseInfra, project_id: str, alias: str) -> str:
    """Resolve an agent alias to its agent_id within a project."""
    aweb_db = db_infra.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT agent_id
        FROM {{tables.agents}}
        WHERE project_id = $1 AND alias = $2 AND deleted_at IS NULL
        """,
        UUID(project_id),
        alias,
    )
    if not row:
        raise HTTPException(status_code=404, detail=f"Agent '{alias}' not found")
    return str(row["agent_id"])


async def _enforce_actor_binding(
    identity: AuthIdentity, db_infra: DatabaseInfra, project_id: str, agent_name: str
) -> str:
    """Verify that agent_name matches the authenticated agent and return the agent_id."""
    if identity.agent_id is None:
        raise HTTPException(status_code=403, detail="No agent identity in auth context")
    agent_id = await _resolve_agent_id(db_infra, project_id, agent_name)
    if agent_id != identity.agent_id:
        raise HTTPException(status_code=403, detail="agent_name does not match authenticated agent")
    return agent_id


async def _tool_ensure_project(
    request: Request,
    db_infra: DatabaseInfra,
    args: dict[str, Any],
) -> dict[str, Any]:
    identity = await get_identity_from_auth(request, db_infra)
    project_id = identity.project_id
    project_key = args.get("project_key")

    server_db = db_infra.get_manager("server")
    row = await server_db.fetch_one(
        "SELECT id, slug, name FROM {{tables.projects}} WHERE id = $1",
        UUID(project_id),
    )
    if not row:
        raise HTTPException(status_code=404, detail="Project not found")

    if project_key and row["slug"] != project_key:
        raise HTTPException(
            status_code=403,
            detail="project_key does not match authenticated project",
        )

    return {
        "project_id": str(row["id"]),
        "slug": row["slug"],
        "name": row.get("name") or "",
    }


async def _validate_project_key(
    db_infra: DatabaseInfra, project_id: str, project_key: str | None
) -> None:
    """Validate project_key matches the authenticated project's slug, if provided."""
    if not project_key:
        return
    server_db = db_infra.get_manager("server")
    row = await server_db.fetch_one(
        "SELECT slug FROM {{tables.projects}} WHERE id = $1",
        UUID(project_id),
    )
    if not row or row["slug"] != project_key:
        raise HTTPException(
            status_code=403,
            detail="project_key does not match authenticated project",
        )


VALID_PRIORITIES = {"low", "normal", "high", "urgent"}


async def _tool_send_message(
    request: Request,
    db_infra: DatabaseInfra,
    args: dict[str, Any],
) -> dict[str, Any]:
    identity = await get_identity_from_auth(request, db_infra)
    project_id = identity.project_id
    project_key = args.get("project_key")
    sender_name = str(args.get("sender_name") or "").strip()
    to_list = args.get("to") or []
    subject = str(args.get("subject") or "").strip()
    body_md = str(args.get("body_md") or "").strip()
    importance = str(args.get("importance") or "normal").strip()
    thread_id = args.get("thread_id")

    await _validate_project_key(db_infra, project_id, project_key)

    if not sender_name or not to_list or not subject:
        raise HTTPException(status_code=422, detail="sender_name, to, and subject are required")
    if importance not in VALID_PRIORITIES:
        raise HTTPException(
            status_code=422,
            detail=f"importance must be one of: {sorted(VALID_PRIORITIES)}",
        )

    sender_agent_id = await _enforce_actor_binding(identity, db_infra, project_id, sender_name)

    deliveries: list[dict[str, Any]] = []
    for recipient_alias in to_list:
        recipient_alias = str(recipient_alias).strip()
        recipient_agent_id = await _resolve_agent_id(db_infra, project_id, recipient_alias)
        message_id, created_at = await deliver_message(
            db_infra,
            project_id=project_id,
            from_agent_id=sender_agent_id,
            from_alias=sender_name,
            to_agent_id=recipient_agent_id,
            subject=subject,
            body=body_md,
            priority=importance,
            thread_id=thread_id,
        )
        deliveries.append(
            {
                "to": recipient_alias,
                "message_id": str(message_id),
                "status": "delivered",
                "delivered_at": _utc_iso(created_at),
            }
        )

    return {"deliveries": deliveries, "count": len(deliveries)}


async def _tool_fetch_inbox(
    request: Request,
    db_infra: DatabaseInfra,
    args: dict[str, Any],
) -> Any:
    identity = await get_identity_from_auth(request, db_infra)
    project_id = identity.project_id
    project_key = args.get("project_key")
    agent_name = str(args.get("agent_name") or "").strip()
    limit = int(args.get("limit") or 50)
    urgent_only = bool(args.get("urgent_only", False))
    include_bodies = bool(args.get("include_bodies", True))
    since_ts = args.get("since_ts")

    await _validate_project_key(db_infra, project_id, project_key)

    if not agent_name:
        raise HTTPException(status_code=422, detail="agent_name is required")

    if since_ts is not None:
        since_ts = str(since_ts).strip()
        try:
            from datetime import datetime

            datetime.fromisoformat(since_ts.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            raise HTTPException(status_code=422, detail="Invalid since_ts format")

    agent_id = await _enforce_actor_binding(identity, db_infra, project_id, agent_name)

    aweb_db = db_infra.get_manager("aweb")

    query = """
        SELECT message_id, from_agent_id, from_alias, subject, body, priority,
               thread_id, read_at, created_at
        FROM {{tables.messages}}
        WHERE project_id = $1
          AND to_agent_id = $2
    """
    params: list[Any] = [UUID(project_id), UUID(agent_id)]
    param_idx = 3

    if urgent_only:
        query += f"  AND priority = ${param_idx}\n"
        params.append("urgent")
        param_idx += 1

    if since_ts:
        query += f"  AND created_at >= ${param_idx}::timestamptz\n"
        params.append(since_ts)
        param_idx += 1

    query += f"ORDER BY created_at DESC\nLIMIT ${param_idx}"
    params.append(limit)

    rows = await aweb_db.fetch_all(query, *params)

    messages = []
    for r in rows:
        msg: dict[str, Any] = {
            "message_id": str(r["message_id"]),
            "from_agent_id": str(r["from_agent_id"]),
            "from_alias": r["from_alias"],
            "subject": r["subject"],
            "priority": r["priority"],
            "thread_id": str(r["thread_id"]) if r["thread_id"] else None,
            "read": r["read_at"] is not None,
            "read_at": _utc_iso(r["read_at"]) if r["read_at"] else None,
            "created_at": _utc_iso(r["created_at"]),
        }
        if include_bodies:
            msg["body"] = r["body"]
        messages.append(msg)

    return messages


async def _tool_acknowledge_message(
    request: Request,
    db_infra: DatabaseInfra,
    args: dict[str, Any],
) -> dict[str, Any]:
    identity = await get_identity_from_auth(request, db_infra)
    project_id = identity.project_id
    project_key = args.get("project_key")
    agent_name = str(args.get("agent_name") or "").strip()
    message_id = str(args.get("message_id") or "").strip()

    await _validate_project_key(db_infra, project_id, project_key)

    if not agent_name or not message_id:
        raise HTTPException(status_code=422, detail="agent_name and message_id are required")

    agent_id = await _enforce_actor_binding(identity, db_infra, project_id, agent_name)
    return await _mark_message_read_impl(db_infra, project_id, agent_id, message_id, ack=True)


async def _tool_mark_message_read(
    request: Request,
    db_infra: DatabaseInfra,
    args: dict[str, Any],
) -> dict[str, Any]:
    identity = await get_identity_from_auth(request, db_infra)
    project_id = identity.project_id
    project_key = args.get("project_key")
    agent_name = str(args.get("agent_name") or "").strip()
    message_id = str(args.get("message_id") or "").strip()

    await _validate_project_key(db_infra, project_id, project_key)

    if not agent_name or not message_id:
        raise HTTPException(status_code=422, detail="agent_name and message_id are required")

    agent_id = await _enforce_actor_binding(identity, db_infra, project_id, agent_name)
    return await _mark_message_read_impl(db_infra, project_id, agent_id, message_id, ack=False)


async def _mark_message_read_impl(
    db_infra: DatabaseInfra,
    project_id: str,
    agent_id: str,
    message_id: str,
    *,
    ack: bool,
) -> dict[str, Any]:
    """Shared implementation for acknowledge_message and mark_message_read.

    In BeadHub's aweb model, both operations set read_at. The ``ack`` flag
    controls whether the response uses acknowledge-style fields.
    """
    try:
        message_uuid = UUID(message_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid message_id format")

    aweb_db = db_infra.get_manager("aweb")

    # Ownership check: distinguish 404 (message not found) from 403 (not yours)
    row = await aweb_db.fetch_one(
        """
        SELECT to_agent_id
        FROM {{tables.messages}}
        WHERE project_id = $1 AND message_id = $2
        """,
        UUID(project_id),
        message_uuid,
    )
    if not row:
        raise HTTPException(status_code=404, detail="Message not found")
    if str(row["to_agent_id"]) != agent_id:
        raise HTTPException(status_code=403, detail="Not authorized for this message")

    updated = await aweb_db.fetch_one(
        """
        UPDATE {{tables.messages}}
        SET read_at = COALESCE(read_at, NOW())
        WHERE project_id = $1 AND message_id = $2
        RETURNING read_at
        """,
        UUID(project_id),
        message_uuid,
    )
    read_at = _utc_iso(updated["read_at"]) if updated and updated["read_at"] else None

    if ack:
        return {
            "message_id": message_id,
            "acknowledged": True,
            "acknowledged_at": read_at,
            "read_at": read_at,
        }
    return {
        "message_id": message_id,
        "read": True,
        "read_at": read_at,
    }


async def _tool_reply_message(
    request: Request,
    db_infra: DatabaseInfra,
    args: dict[str, Any],
) -> dict[str, Any]:
    identity = await get_identity_from_auth(request, db_infra)
    project_id = identity.project_id
    project_key = args.get("project_key")
    original_message_id = str(args.get("message_id") or "").strip()
    sender_name = str(args.get("sender_name") or "").strip()
    body_md = str(args.get("body_md") or "").strip()
    to_override = args.get("to")
    subject_prefix = str(args.get("subject_prefix") or "Re:").strip()

    await _validate_project_key(db_infra, project_id, project_key)

    if not original_message_id or not sender_name or not body_md:
        raise HTTPException(
            status_code=422,
            detail="message_id, sender_name, and body_md are required",
        )

    sender_agent_id = await _enforce_actor_binding(identity, db_infra, project_id, sender_name)

    try:
        original_uuid = UUID(original_message_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid message_id format")

    aweb_db = db_infra.get_manager("aweb")
    original = await aweb_db.fetch_one(
        """
        SELECT from_agent_id, from_alias, subject, thread_id
        FROM {{tables.messages}}
        WHERE project_id = $1 AND message_id = $2
        """,
        UUID(project_id),
        original_uuid,
    )
    if not original:
        raise HTTPException(status_code=404, detail="Original message not found")

    # Determine thread: reuse existing or create from original message_id
    thread_id = str(original["thread_id"]) if original["thread_id"] else original_message_id

    # Determine recipients: override or reply to original sender
    if to_override and isinstance(to_override, list):
        recipient_aliases = [str(a).strip() for a in to_override]
    else:
        recipient_aliases = [original["from_alias"]]

    reply_subject = f"{subject_prefix} {original['subject']}"

    deliveries: list[dict[str, Any]] = []
    for recipient_alias in recipient_aliases:
        recipient_agent_id = await _resolve_agent_id(db_infra, project_id, recipient_alias)
        message_id, created_at = await deliver_message(
            db_infra,
            project_id=project_id,
            from_agent_id=sender_agent_id,
            from_alias=sender_name,
            to_agent_id=recipient_agent_id,
            subject=reply_subject,
            body=body_md,
            priority="normal",
            thread_id=thread_id,
        )
        deliveries.append(
            {
                "to": recipient_alias,
                "message_id": str(message_id),
                "status": "delivered",
                "delivered_at": _utc_iso(created_at),
            }
        )

    return {
        "thread_id": thread_id,
        "reply_to": original_message_id,
        "deliveries": deliveries,
        "count": len(deliveries),
    }
