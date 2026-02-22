"""MCP tools for distributed locks (reservations)."""

from __future__ import annotations

import json

from aweb.mcp.auth import get_auth
from aweb.service_errors import ServiceError
from aweb.reservations_service import (
    acquire_reservation,
    list_reservations,
    release_reservation,
)


async def lock_acquire(
    db_infra, *, resource_key: str, ttl_seconds: int = 60, metadata: str = ""
) -> str:
    """Acquire a distributed lock on a resource."""
    auth = get_auth()

    if not resource_key.strip():
        return json.dumps({"error": "resource_key must not be empty"})

    # Parse metadata JSON string from tool argument.
    meta_dict: dict = {}
    if metadata:
        try:
            parsed = json.loads(metadata)
            if isinstance(parsed, dict):
                meta_dict = parsed
        except Exception:
            return json.dumps({"error": "metadata must be a valid JSON object"})

    try:
        result = await acquire_reservation(
            db_infra,
            project_id=auth.project_id,
            agent_id=auth.agent_id,
            resource_key=resource_key.strip(),
            ttl_seconds=ttl_seconds,
            metadata=meta_dict,
        )
    except ServiceError as exc:
        return json.dumps({"error": exc.detail})

    if result["status"] == "conflict":
        return json.dumps(
            {
                "error": "Resource is already locked",
                "holder_agent_id": result["holder_agent_id"],
                "holder_alias": result["holder_alias"],
                "expires_at": result["expires_at"],
            }
        )

    return json.dumps(
        {
            "status": "acquired",
            "resource_key": result["resource_key"],
            "holder_alias": result["holder_alias"],
            "acquired_at": result["acquired_at"],
            "expires_at": result["expires_at"],
        }
    )


async def lock_release(db_infra, *, resource_key: str) -> str:
    """Release a distributed lock."""
    auth = get_auth()

    if not resource_key.strip():
        return json.dumps({"error": "resource_key must not be empty"})

    try:
        result = await release_reservation(
            db_infra,
            project_id=auth.project_id,
            agent_id=auth.agent_id,
            resource_key=resource_key.strip(),
        )
    except ServiceError as exc:
        if exc.status_code == 409:
            return json.dumps({"error": "Lock held by another agent"})
        return json.dumps({"error": exc.detail})

    return json.dumps({"status": "released", "resource_key": result["resource_key"]})


async def lock_list(db_infra, *, prefix: str = "") -> str:
    """List active locks in the project."""
    auth = get_auth()

    try:
        reservations = await list_reservations(
            db_infra,
            project_id=auth.project_id,
            prefix=prefix or None,
        )
    except ServiceError as exc:
        return json.dumps({"error": exc.detail})

    return json.dumps(
        {
            "reservations": [
                {
                    "resource_key": r["resource_key"],
                    "holder_agent_id": r["holder_agent_id"],
                    "holder_alias": r["holder_alias"],
                    "acquired_at": r["acquired_at"],
                    "expires_at": r["expires_at"],
                    "metadata": r["metadata"],
                }
                for r in reservations
            ]
        }
    )
