"""MCP tools for custodial arbitrary payload signing."""

from __future__ import annotations

import json
from typing import Any

from aweb.awid.custody import CustodyError, SelfCustodialError, sign_arbitrary_payload
from aweb.mcp.auth import get_auth


async def sign(db_infra, *, sign_payload: dict[str, Any]) -> str:
    """Sign an arbitrary JSON payload for the authenticated custodial agent."""
    if "timestamp" in sign_payload:
        return json.dumps({"error": "sign_payload must not include timestamp"})

    auth = get_auth()
    try:
        did_key, signature, timestamp = await sign_arbitrary_payload(
            auth.agent_id,
            sign_payload,
            db_infra,
        )
    except SelfCustodialError:
        return json.dumps({"error": "Only custodial agents may use this tool"})
    except ValueError as exc:
        return json.dumps({"error": str(exc)})
    except CustodyError as exc:
        return json.dumps({"error": str(exc)})

    return json.dumps(
        {
            "did_key": did_key,
            "signature": signature,
            "timestamp": timestamp,
        }
    )
