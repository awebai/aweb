from __future__ import annotations

from uuid import UUID


async def check_access(
    db, *, target_project_id: str, target_agent_id: str, sender_address: str
) -> bool:
    """Check whether sender_address is allowed to reach the target agent.

    Returns True if:
    - Target agent's access_mode is 'open', OR
    - Sender is in the same project as target, OR
    - Sender's address (exact or org-level) is in target project's contacts.
    """
    aweb_db = db.get_manager("aweb")

    # 1. Fetch target agent's access_mode.
    row = await aweb_db.fetch_one(
        """
        SELECT access_mode
        FROM {{tables.agents}}
        WHERE agent_id = $1 AND project_id = $2 AND deleted_at IS NULL
        """,
        UUID(target_agent_id),
        UUID(target_project_id),
    )
    if row is None:
        return False

    if row["access_mode"] == "open":
        return True

    # 2. Same-project bypass: extract org_slug from sender_address.
    org_slug = sender_address.split("/")[0] if "/" in sender_address else sender_address

    proj = await aweb_db.fetch_one(
        "SELECT project_id FROM {{tables.projects}} WHERE slug = $1 AND deleted_at IS NULL",
        org_slug,
    )
    if proj is not None and str(proj["project_id"]) == target_project_id:
        return True

    # 3. Check contacts for exact match or org-level match.
    contact = await aweb_db.fetch_one(
        """
        SELECT 1
        FROM {{tables.contacts}}
        WHERE project_id = $1 AND contact_address IN ($2, $3)
        """,
        UUID(target_project_id),
        sender_address,
        org_slug,
    )
    return contact is not None
