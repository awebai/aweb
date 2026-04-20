from __future__ import annotations

from dataclasses import dataclass

from awid.team_ids import build_team_id, parse_team_id
from fastapi import HTTPException


MAX_ALIAS_PART_LENGTH = 64


@dataclass(frozen=True)
class AliasTarget:
    team_id: str
    alias: str


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
