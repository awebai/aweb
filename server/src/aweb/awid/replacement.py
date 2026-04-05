"""Assigned-address continuity metadata for outgoing deliveries."""

from __future__ import annotations

import logging
from uuid import UUID

from aweb.awid.registry import RegistryError

logger = logging.getLogger(__name__)


async def get_sender_delivery_metadata(
    aweb_db,
    *,
    sender_ids: list[UUID],
    registry_client=None,
) -> dict[str, dict]:
    if not sender_ids:
        return {}

    rows = await aweb_db.fetch_all(
        """
        SELECT agent_id, stable_id
        FROM {{tables.agents}}
        WHERE agent_id = ANY($1::uuid[])
          AND deleted_at IS NULL
        ORDER BY agent_id
        """,
        sender_ids,
    )

    result: dict[str, dict] = {
        str(row["agent_id"]): {
            "from_address": None,
            "replacement_announcement": None,
        }
        for row in rows
    }

    if registry_client is None:
        return result

    for row in rows:
        stable_id = str(row.get("stable_id") or "").strip()
        if not stable_id:
            continue
        try:
            addresses = await registry_client.list_did_addresses(stable_id)
        except RegistryError:
            logger.warning(
                "Failed to list sender delivery addresses for stable_id=%s",
                stable_id,
                exc_info=True,
            )
            continue
        if not addresses:
            continue
        address = addresses[0]
        result[str(row["agent_id"])]["from_address"] = f"{address.domain}/{address.name}"

    return result
