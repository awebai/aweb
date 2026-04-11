from __future__ import annotations


def _aweb_db(db_or_manager):
    return db_or_manager.get_manager("aweb") if hasattr(db_or_manager, "get_manager") else db_or_manager


async def lookup_identity_metadata_by_did(db_or_manager, dids: list[str]) -> dict[str, dict[str, str]]:
    unique_dids = sorted({(did or "").strip() for did in dids if (did or "").strip()})
    if not unique_dids:
        return {}

    aweb_db = _aweb_db(db_or_manager)
    rows = await aweb_db.fetch_all(
        """
        SELECT did_aw, did_key, address
        FROM {{tables.agents}}
        WHERE deleted_at IS NULL
          AND (did_aw = ANY($1::text[]) OR did_key = ANY($1::text[]))
        """,
        unique_dids,
    )
    result: dict[str, dict[str, str]] = {}
    for did in unique_dids:
        if did.startswith("did:aw:"):
            result.setdefault(did, {})["stable_id"] = did
    for row in rows:
        stable_id = (row.get("did_aw") or "").strip()
        current_did = (row.get("did_key") or "").strip()
        address = (row.get("address") or "").strip()
        for did in (stable_id, current_did):
            if not did:
                continue
            meta = result.setdefault(did, {})
            if stable_id:
                meta["stable_id"] = stable_id
            if address:
                meta["address"] = address
    return result


async def lookup_identity_metadata_by_agent_id(
    db_or_manager, agent_ids: list[str]
) -> dict[str, dict[str, str]]:
    unique_agent_ids = sorted({(agent_id or "").strip() for agent_id in agent_ids if (agent_id or "").strip()})
    if not unique_agent_ids:
        return {}

    aweb_db = _aweb_db(db_or_manager)
    rows = await aweb_db.fetch_all(
        """
        SELECT agent_id::text AS agent_id, did_aw, did_key, address
        FROM {{tables.agents}}
        WHERE deleted_at IS NULL
          AND agent_id::text = ANY($1::text[])
        """,
        unique_agent_ids,
    )
    result: dict[str, dict[str, str]] = {}
    for row in rows:
        agent_id = (row.get("agent_id") or "").strip()
        if not agent_id:
            continue
        meta = result.setdefault(agent_id, {})
        stable_id = (row.get("did_aw") or "").strip()
        current_did = (row.get("did_key") or "").strip()
        address = (row.get("address") or "").strip()
        if stable_id:
            meta["stable_id"] = stable_id
        if current_did:
            meta["current_did"] = current_did
        if address:
            meta["address"] = address
    return result
