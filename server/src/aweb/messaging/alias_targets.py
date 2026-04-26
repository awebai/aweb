from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from awid.team_ids import build_team_id, parse_team_id
from fastapi import HTTPException


MAX_ALIAS_PART_LENGTH = 64


@dataclass(frozen=True)
class AliasTarget:
    team_id: str
    alias: str


class AmbiguousLocalAddressError(Exception):
    pass


def resolve_alias_target(auth_team_id: str | None, raw_alias: str, *, field: str) -> AliasTarget:
    """Resolve plain aliases and same-org team~alias targets to a team-scoped alias."""
    if auth_team_id is None or not str(auth_team_id).strip():
        raise HTTPException(status_code=422, detail=f"{field} requires team context")

    alias = str(raw_alias or "").strip()
    if "~" not in alias:
        return AliasTarget(team_id=str(auth_team_id).strip(), alias=alias)
    if alias.count("~") != 1:
        raise HTTPException(status_code=422, detail=f"{field} team~alias must include exactly one '~'")

    team_name, alias_part = alias.split("~", 1)
    team_name = team_name.strip()
    alias_part = alias_part.strip()
    if not team_name or not alias_part:
        raise HTTPException(status_code=422, detail=f"{field} team~alias must include both team and alias")

    try:
        sender_domain, _ = parse_team_id(str(auth_team_id).strip())
    except Exception as exc:
        raise HTTPException(status_code=422, detail="authenticated team_id is invalid") from exc
    return AliasTarget(team_id=build_team_id(sender_domain, team_name), alias=alias_part)


def validate_alias_selector(raw_alias: str, *, field: str) -> str:
    alias = str(raw_alias or "").strip()
    if "~" not in alias:
        if len(alias) > MAX_ALIAS_PART_LENGTH:
            raise ValueError(f"{field} must be at most {MAX_ALIAS_PART_LENGTH} characters")
        return alias
    if alias.count("~") != 1:
        raise ValueError(f"{field} team~alias must include exactly one '~'")

    team_name, alias_part = alias.split("~", 1)
    team_name = team_name.strip()
    alias_part = alias_part.strip()
    if not team_name or not alias_part:
        raise ValueError(f"{field} team~alias must include both team and alias")
    if len(team_name) > MAX_ALIAS_PART_LENGTH or len(alias_part) > MAX_ALIAS_PART_LENGTH:
        raise ValueError(f"{field} team and alias must be at most {MAX_ALIAS_PART_LENGTH} characters")
    return alias


async def team_exists(db, team_id: str) -> bool:
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT 1
        FROM {{tables.teams}}
        WHERE team_id = $1
        """,
        team_id,
    )
    return row is not None


async def namespace_exists(db, namespace: str) -> bool:
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT 1
        FROM {{tables.teams}}
        WHERE namespace = $1
        LIMIT 1
        """,
        namespace,
    )
    return row is not None


def derive_team_address(team_id: str | None, alias: str | None) -> str:
    alias = str(alias or "").strip()
    if not alias:
        return ""
    try:
        namespace, _team_name = parse_team_id(str(team_id or "").strip())
    except Exception:
        return ""
    namespace = str(namespace or "").strip()
    if not namespace:
        return ""
    return f"{namespace}/{alias}"


async def get_agent_by_namespace_alias(db, *, namespace: str, alias: str) -> dict[str, Any] | None:
    aweb_db = db.get_manager("aweb")
    rows = await aweb_db.fetch_all(
        """
        SELECT a.agent_id, a.team_id, a.alias, a.did_key, a.did_aw, a.address,
               a.lifetime, a.messaging_policy, a.status, a.deleted_at
        FROM {{tables.agents}} a
        JOIN {{tables.teams}} t ON t.team_id = a.team_id
        WHERE t.namespace = $1
          AND a.alias = $2
          AND a.deleted_at IS NULL
        ORDER BY a.created_at DESC
        """,
        str(namespace or "").strip(),
        str(alias or "").strip(),
    )
    if len(rows) > 1:
        raise AmbiguousLocalAddressError(f"Address {namespace}/{alias} matches multiple local agents")
    return None if not rows else dict(rows[0])
