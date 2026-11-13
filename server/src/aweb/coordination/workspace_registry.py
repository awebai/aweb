from __future__ import annotations

from pgdbm import AsyncDatabaseManager

from .routes.repos import canonicalize_git_url, extract_repo_name


async def ensure_repo(
    aweb_db: AsyncDatabaseManager,
    team_id: str,
    origin_url: str,
) -> str:
    """Ensure a repo exists for the given team and origin.

    A soft-deleted repo row of the team is restored. `aweb_db` is the aweb
    manager or a transaction on it.
    """
    canonical_origin = canonicalize_git_url(origin_url)
    repo_name = extract_repo_name(canonical_origin)

    result = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.repos}} (team_id, origin_url, canonical_origin, name)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (team_id, canonical_origin)
        DO UPDATE SET origin_url = EXCLUDED.origin_url, deleted_at = NULL
        RETURNING id
        """,
        team_id,
        origin_url,
        canonical_origin,
        repo_name,
    )
    return result["id"]
