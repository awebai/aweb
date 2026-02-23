from __future__ import annotations

import hashlib
from uuid import UUID

import base58 as b58

from aweb.did import public_key_from_did

_STABLE_ID_PREFIX = "did:claw:"
_STABLE_ID_BYTES_LEN = 20


def stable_id_from_did_key(did_key: str) -> str:
    """Derive a stable identity (did:claw) from an initial did:key.

    Per clawdid addendum v2:
      did:claw = "did:claw:" + base58btc(sha256(pubkey32)[:20])
    """
    pubkey = public_key_from_did(did_key)
    digest = hashlib.sha256(pubkey).digest()[:_STABLE_ID_BYTES_LEN]
    suffix = b58.b58encode(digest).decode("ascii")
    return f"{_STABLE_ID_PREFIX}{suffix}"


def validate_stable_id(value: str) -> str:
    value = (value or "").strip()
    if not value:
        raise ValueError("stable_id must not be empty")
    if not value.startswith(_STABLE_ID_PREFIX):
        raise ValueError(f"stable_id must start with '{_STABLE_ID_PREFIX}'")
    suffix = value[len(_STABLE_ID_PREFIX) :]
    if not suffix:
        raise ValueError("stable_id suffix must not be empty")
    try:
        decoded = b58.b58decode(suffix)
    except Exception as exc:
        raise ValueError("stable_id suffix must be valid base58btc") from exc
    if len(decoded) != _STABLE_ID_BYTES_LEN:
        raise ValueError(f"stable_id suffix must decode to {_STABLE_ID_BYTES_LEN} bytes")
    return value


async def ensure_agent_stable_ids(
    aweb_db, *, project_id: str, agent_ids: list[str]
) -> dict[str, str]:
    """Ensure agents have stable_id populated when possible.

    This is an idempotent best-effort backfill:
    - If agents.stable_id is already set, use it.
    - Else, use earliest agent_log(create).new_did, falling back to agents.did.
    - If no did is available or did is invalid, leave stable_id unset.
    """
    if not agent_ids:
        return {}

    project_uuid = UUID(project_id)
    ids = [UUID(a) for a in agent_ids]

    rows = await aweb_db.fetch_all(
        """
        SELECT
            a.agent_id,
            a.stable_id,
            COALESCE(l.new_did, a.did) AS initial_did
        FROM {{tables.agents}} a
        LEFT JOIN LATERAL (
            SELECT new_did
            FROM {{tables.agent_log}}
            WHERE agent_id = a.agent_id AND operation = 'create'
            ORDER BY created_at ASC
            LIMIT 1
        ) l ON TRUE
        WHERE a.project_id = $1
          AND a.agent_id = ANY($2::uuid[])
          AND a.deleted_at IS NULL
        """,
        project_uuid,
        ids,
    )

    stable_by_id: dict[str, str] = {}
    to_update: list[tuple[UUID, str]] = []
    for r in rows:
        agent_id = str(r["agent_id"])
        stable = r.get("stable_id")
        if stable:
            stable_by_id[agent_id] = stable
            continue
        initial_did = r.get("initial_did")
        if not initial_did:
            continue
        try:
            stable = stable_id_from_did_key(initial_did)
        except Exception:
            continue
        stable_by_id[agent_id] = stable
        to_update.append((UUID(agent_id), stable))

    for agent_uuid, stable in to_update:
        await aweb_db.execute(
            """
            UPDATE {{tables.agents}}
            SET stable_id = $1
            WHERE agent_id = $2 AND project_id = $3 AND stable_id IS NULL
            """,
            stable,
            agent_uuid,
            project_uuid,
        )

    return stable_by_id


async def backfill_missing_stable_ids(aweb_db, *, batch_size: int = 500) -> int:
    """Backfill agents.stable_id for all projects (best-effort).

    Safe to run on every startup; only fills missing values.
    Returns the number of rows updated.
    """
    updated = 0
    while True:
        rows = await aweb_db.fetch_all(
            """
            SELECT
                a.agent_id,
                a.project_id,
                COALESCE(l.new_did, a.did) AS initial_did
            FROM {{tables.agents}} a
            LEFT JOIN LATERAL (
                SELECT new_did
                FROM {{tables.agent_log}}
                WHERE agent_id = a.agent_id AND operation = 'create'
                ORDER BY created_at ASC
                LIMIT 1
            ) l ON TRUE
            WHERE a.deleted_at IS NULL
              AND a.stable_id IS NULL
              AND a.did IS NOT NULL
            LIMIT $1
            """,
            int(batch_size),
        )
        if not rows:
            break

        updated_this_batch = 0
        for r in rows:
            agent_id = r["agent_id"]
            project_id = r["project_id"]
            initial_did = r.get("initial_did")
            if not initial_did:
                continue
            try:
                stable = stable_id_from_did_key(initial_did)
            except Exception:
                continue
            await aweb_db.execute(
                """
                UPDATE {{tables.agents}}
                SET stable_id = $1
                WHERE agent_id = $2 AND project_id = $3 AND stable_id IS NULL
                """,
                stable,
                UUID(str(agent_id)),
                UUID(str(project_id)),
            )
            updated_this_batch += 1
            updated += 1

        if updated_this_batch == 0:
            # Avoid an infinite loop if remaining rows have invalid/unusable dids.
            break

    return updated
