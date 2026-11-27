from __future__ import annotations

from aweb.team_registry import native_database_manager
from aweb.identity_binding import (
    IdentityProjectionField,
    verified_identity_field_sql,
    verified_key_sql,
)

from awid.team_ids import parse_team_id
from awid.signing import canonical_json_bytes
from aweb.human_channels.contract import (
    ContractError,
    decode_record,
)


def native_participant_reference(did: str) -> dict[str, str] | None:
    """Add a typed view without narrowing historical native DID projections.

    Old native storage accepted arbitrary strings. Preserve those old fields;
    omit this optional new field when they cannot form a P0 typed reference.
    A reference itself makes no claim of verified current identity.
    """
    try:
        return decode_record(
            "NativeParticipant", canonical_json_bytes(dict(kind="native", did=did))
        ).value
    except ContractError:
        return None


def routable_chat_address(
    meta: dict[str, str] | None, viewer_team_id: str | None, fallback_alias: str
) -> str:
    meta = meta or {}
    if meta.get("participant_kind") == "bridged":
        return ""  # Typed session/participant route only, never the display name.
    address = (meta.get("address") or "").strip()
    if address:
        return address

    if meta.get("identity_scope") == "global" and (meta.get("stable_id") or "").strip():
        return ""

    alias = (meta.get("alias") or "").strip() or (fallback_alias or "").strip()
    if not alias:
        return ""

    sender_team_id = (meta.get("team_id") or "").strip()
    viewer_team_id = (viewer_team_id or "").strip()
    if sender_team_id and viewer_team_id:
        try:
            sender_domain, sender_team_name = parse_team_id(sender_team_id)
            viewer_domain, viewer_team_name = parse_team_id(viewer_team_id)
        except ValueError:
            return alias
        if sender_domain == viewer_domain and sender_team_name != viewer_team_name:
            return f"{sender_team_name}~{alias}"

    return alias


async def lookup_identity_metadata_by_did(
    db_or_manager, dids: list[str]
) -> dict[str, dict[str, str]]:
    unique_dids = sorted({(did or "").strip() for did in dids if (did or "").strip()})
    if not unique_dids:
        return {}

    aweb_db = native_database_manager(db_or_manager)
    rows = await aweb_db.fetch_all(
        f"""
        SELECT {verified_identity_field_sql(IdentityProjectionField.STABLE_DID)} AS did_aw, did_key, {verified_identity_field_sql(IdentityProjectionField.ADDRESS)} AS address, team_id, alias, identity_scope
        FROM {{{{tables.agents}}}}
        WHERE deleted_at IS NULL
          AND ((did_aw = ANY($1::text[]) AND {verified_key_sql()}) OR did_key = ANY($1::text[]))
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
        team_id = (row.get("team_id") or "").strip()
        alias = (row.get("alias") or "").strip()
        for did in (stable_id, current_did):
            if not did:
                continue
            meta = result.setdefault(did, {})
            if row.get("identity_scope"):
                meta["identity_scope"] = row["identity_scope"]
            if stable_id:
                meta["stable_id"] = stable_id
            if address:
                meta["address"] = address
            if team_id:
                meta["team_id"] = team_id
            if alias:
                meta["alias"] = alias
    return result


async def lookup_identity_metadata_by_agent_id(
    db_or_manager, agent_ids: list[str]
) -> dict[str, dict[str, str]]:
    unique_agent_ids = sorted(
        {(agent_id or "").strip() for agent_id in agent_ids if (agent_id or "").strip()}
    )
    if not unique_agent_ids:
        return {}

    aweb_db = native_database_manager(db_or_manager)
    rows = await aweb_db.fetch_all(
        f"""
        SELECT agent_id::text AS agent_id, {verified_identity_field_sql(IdentityProjectionField.STABLE_DID)} AS did_aw, did_key, {verified_identity_field_sql(IdentityProjectionField.ADDRESS)} AS address
        FROM {{{{tables.agents}}}}
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
