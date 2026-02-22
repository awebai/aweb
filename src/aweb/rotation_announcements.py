"""Rotation announcement storage, per-peer injection, and acknowledgment.

Per clawdid/sot.md §5.4: after key rotation, the first message sent with the
new key includes a rotation_announcement so receivers can auto-accept the new
DID without triggering IDENTITY_MISMATCH. The announcement is attached per-peer
until the peer responds OR 24 hours elapse, whichever comes first.
"""

from __future__ import annotations

from uuid import UUID


async def get_pending_announcements(
    aweb_db, *, sender_ids: list[UUID], recipient_id: UUID
) -> dict[str, dict]:
    """Return pending rotation announcements for the given sender→recipient pairs.

    Returns a dict keyed by sender agent_id (str) with the announcement payload,
    or empty dict if no announcements are pending.
    """
    if not sender_ids:
        return {}

    # Find the earliest unacknowledged rotation announcement per sender.
    # Delivers oldest first so TOFU chain is preserved: A→B before B→C.
    rows = await aweb_db.fetch_all(
        """
        SELECT DISTINCT ON (ra.agent_id)
            ra.agent_id,
            ra.announcement_id,
            ra.old_did,
            ra.new_did,
            ra.rotation_timestamp,
            ra.old_key_signature
        FROM {{tables.rotation_announcements}} ra
        WHERE ra.agent_id = ANY($1::uuid[])
          AND ra.created_at > NOW() - INTERVAL '24 hours'
          AND NOT EXISTS (
              SELECT 1 FROM {{tables.rotation_peer_acks}} rpa
              WHERE rpa.announcement_id = ra.announcement_id
                AND rpa.peer_agent_id = $2
                AND rpa.acknowledged_at IS NOT NULL
          )
        ORDER BY ra.agent_id, ra.created_at ASC
        """,
        sender_ids,
        recipient_id,
    )

    return {
        str(r["agent_id"]): {
            "old_did": r["old_did"],
            "new_did": r["new_did"],
            "timestamp": r["rotation_timestamp"],
            "old_key_signature": r["old_key_signature"],
        }
        for r in rows
    }


async def acknowledge_rotation(aweb_db, *, from_agent_id: UUID, to_agent_id: UUID) -> None:
    """Mark the earliest unacknowledged rotation announcement from
    to_agent_id as acknowledged by from_agent_id.

    Called when from_agent_id sends a message TO to_agent_id — meaning
    from_agent_id has implicitly acknowledged to_agent_id's rotation.
    Only acks one announcement at a time to preserve TOFU chain order:
    the peer must see A→B before B→C.
    """
    # The 24-hour filter mirrors get_pending_announcements: announcements
    # older than 24h are no longer delivered, so acking them is a no-op.
    await aweb_db.execute(
        """
        INSERT INTO {{tables.rotation_peer_acks}}
            (announcement_id, peer_agent_id, acknowledged_at)
        SELECT ra.announcement_id, $2, NOW()
        FROM {{tables.rotation_announcements}} ra
        WHERE ra.agent_id = $1
          AND ra.created_at > NOW() - INTERVAL '24 hours'
          AND NOT EXISTS (
              SELECT 1 FROM {{tables.rotation_peer_acks}} rpa
              WHERE rpa.announcement_id = ra.announcement_id
                AND rpa.peer_agent_id = $2
          )
        ORDER BY ra.created_at ASC
        LIMIT 1
        ON CONFLICT (announcement_id, peer_agent_id) DO NOTHING
        """,
        to_agent_id,
        from_agent_id,
    )
