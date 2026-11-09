"""Trusted hosted integration for same-account local human mail succession.

The caller MUST establish custody of both identities for the same account and
record that decision in its own transaction. OSS has no account authority and
exposes no HTTP writer. Historical keys below are target/read evidence inside
an affected mail thread, never authentication or current AWID binding evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from aweb.human_kind import is_verified_human
from aweb.service_errors import ConflictError, ValidationError


@dataclass(frozen=True)
class SuccessionResult:
    mapping_created: bool
    conversations_updated: int
    chat_sessions_updated: int = 0


@dataclass(frozen=True)
class MailSuccessionScope:
    # Each group binds historical identities to exactly their own threads.
    # Current participant keys are also thread-local read evidence.
    identity_threads: tuple[tuple[tuple[str, ...], tuple[UUID, ...]], ...] = ()


async def load_mail_succession_scope(
    db, *, viewer_dids: list[str]
) -> MailSuccessionScope:
    """Snapshot thread-local mail attribution once when opening a stream.

    This is read evidence, never a current identity binding or a wake address.
    New writes wake the resolved delivery identity. Reconnect/reconcile reloads
    this snapshot; ticks do not query participant or succession tables.
    """
    rows = await db.fetch_all(
        """SELECT own.conversation_id, own.current_did_key,
                  succession.predecessor_did, succession.predecessor_did_key
           FROM {{tables.conversation_participants}} own
           LEFT JOIN {{tables.conversation_participant_successions}} history
             ON history.conversation_id = own.conversation_id
           LEFT JOIN {{tables.local_human_successions}} succession
             ON succession.predecessor_did = history.predecessor_did
            AND succession.successor_did = own.did
           WHERE own.did = ANY($1::text[])
             AND ((NULLIF(own.current_did_key, '') IS NOT NULL
                   AND own.current_did_key <> ALL($1::text[]))
                  OR succession.predecessor_did IS NOT NULL)""",
        viewer_dids,
    )
    identities_by_thread: dict[UUID, set[str]] = {}
    viewer = set(viewer_dids)
    for row in rows:
        identities = identities_by_thread.setdefault(row["conversation_id"], set())
        for field in ("current_did_key", "predecessor_did", "predecessor_did_key"):
            value = str(row.get(field) or "").strip()
            if value and value not in viewer:
                identities.add(value)
    threads_by_identities: dict[tuple[str, ...], list[UUID]] = {}
    for cid, identities in identities_by_thread.items():
        if identities:
            threads_by_identities.setdefault(tuple(sorted(identities)), []).append(cid)
    return MailSuccessionScope(
        tuple(
            (identities, tuple(sorted(cids)))
            for identities, cids in sorted(threads_by_identities.items())
        )
    )


async def succeed_local_human_participant_on(
    tx, *, predecessor_did: str, successor_did: str
) -> SuccessionResult:
    """Use the caller's native transaction; never commit or open another one.

    Call after the successor's live projection and predecessor retirement are
    visible in this transaction. Rerun for backfill through this same boundary.
    Chat participants/read receipts and all signed message rows stay untouched.
    """
    if (
        not predecessor_did
        or not successor_did.startswith("did:aw:")
        or predecessor_did == successor_did
    ):
        raise ValidationError(
            "Human succession requires distinct predecessor and successor identities"
        )
    old_rows = await tx.fetch_all(
        """SELECT * FROM {{tables.agents}}
           WHERE did_key=$1 OR (did_aw=$1 AND did_aw_verified_key=did_key)
           ORDER BY agent_id FOR UPDATE""",
        predecessor_did,
    )
    if (
        not old_rows
        or any(r["agent_type"] != "human" or r["deleted_at"] is None for r in old_rows)
        or any(str(r.get("address") or "").strip() for r in old_rows)
    ):
        raise ValidationError(
            "Succession requires an unaddressed retired local human identity"
        )
    old_keys = {r.get("did_key") for r in old_rows}
    if len(old_keys) != 1 or not str(next(iter(old_keys)) or "").startswith("did:key:"):
        raise ValidationError("Predecessor key evidence is ambiguous")
    old_key = next(iter(old_keys))
    stable_ids = {
        r["did_aw"]
        for r in old_rows
        if r.get("did_aw") and r.get("did_aw_verified_key") == old_key
    }
    if len(stable_ids) > 1:
        raise ValidationError("Predecessor stable identity evidence is ambiguous")
    predecessor_did = next(iter(stable_ids)) if stable_ids else old_key
    if predecessor_did == successor_did:
        raise ValidationError("Human succession requires distinct identities")
    # Both recorded spellings refer to the same historical identity; callers
    # cannot create competing mappings by alternating its stable DID and key.
    await tx.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
        "human-succession:" + old_key,
    )
    successors = await tx.fetch_all(
        """SELECT * FROM {{tables.agents}} WHERE did_aw=$1 AND deleted_at IS NULL
           ORDER BY agent_id FOR SHARE""",
        successor_did,
    )
    if (
        not successors
        or any(
            not is_verified_human(r)
            or r.get("did_aw_verified_key") != r.get("did_key")
            or not str(r.get("did_key") or "").startswith("did:key:")
            or r.get("did_key") == old_key
            for r in successors
        )
        or len({r.get("did_key") for r in successors}) != 1
    ):
        raise ValidationError(
            "Succession requires an unambiguous live human successor binding"
        )
    mapping = await tx.fetch_one(
        "SELECT * FROM {{tables.local_human_successions}} WHERE predecessor_did=$1",
        predecessor_did,
    )
    if mapping and (
        mapping["successor_did"] != successor_did
        or mapping["predecessor_did_key"] != old_key
    ):
        raise ConflictError(
            "Human succession is already recorded for another identity binding"
        )
    threads = await tx.fetch_all(
        """SELECT c.conversation_id,c.team_id FROM {{tables.conversations}} c
           WHERE c.conversation_type='mail' AND EXISTS (
               SELECT 1 FROM {{tables.conversation_participants}} p
               WHERE p.conversation_id=c.conversation_id AND p.did=ANY($1::text[]))
           ORDER BY c.conversation_id FOR UPDATE""",
        list({predecessor_did, old_key}),
    )
    # Validate every affected thread before writing any participant. The seam
    # cannot reconcile a peer's remote copy and must not invent that authority.
    participants = {}
    for thread in threads:
        rows = await tx.fetch_all(
            "SELECT * FROM {{tables.conversation_participants}} WHERE conversation_id=$1 ORDER BY participant_id FOR UPDATE",
            thread["conversation_id"],
        )
        if any(
            r.get("delivery_origin")
            or str(r.get("transport_hint") or "").startswith(
                ("federation:", "federated:")
            )
            for r in rows
        ):
            raise ValidationError(
                "Human succession cannot change a thread with a foreign route"
            )
        participants[thread["conversation_id"]] = rows
    if not mapping:
        await tx.execute(
            """INSERT INTO {{tables.local_human_successions}}
               (predecessor_did,predecessor_did_key,successor_did) VALUES ($1,$2,$3)""",
            predecessor_did,
            old_key,
            successor_did,
        )
    for thread in threads:
        cid = thread["conversation_id"]
        rows = participants[cid]
        prior = [r for r in rows if r["did"] in {predecessor_did, old_key}]
        current = next((r for r in rows if r["did"] == successor_did), None)
        retained = current or prior[0]
        successor = next(
            (r for r in successors if r["team_id"] == thread["team_id"]), successors[0]
        )
        merged = prior + ([current] if current else [])
        await tx.execute(
            """INSERT INTO {{tables.conversation_participant_successions}}
               (conversation_id,predecessor_did,predecessor_alias)
               VALUES ($1,$2,$3) ON CONFLICT DO NOTHING""",
            cid,
            predecessor_did,
            next(
                (r["alias"] for r in prior if r["did"] == predecessor_did),
                prior[0]["alias"],
            ),
        )
        # Removing a duplicate participant never touches signed messages. Mail
        # has no participant-DID foreign keys or separate per-actor read cursor.
        for row in merged:
            if row["participant_id"] != retained["participant_id"]:
                await tx.execute(
                    "DELETE FROM {{tables.conversation_participants}} WHERE conversation_id=$1 AND participant_id=$2",
                    cid,
                    row["participant_id"],
                )
        await tx.execute(
            """UPDATE {{tables.conversation_participants}}
               SET did=$3,agent_id=$4,alias=$5,address=$6,current_did_key=$7,
                   joined_at=$8,role=$9,delivery_origin=NULL,transport_hint='local'
               WHERE conversation_id=$1 AND participant_id=$2""",
            cid,
            retained["participant_id"],
            successor_did,
            successor["agent_id"],
            successor["alias"],
            successor.get("address"),
            successor["did_key"],
            min(r["joined_at"] for r in merged),
            "initiator"
            if any(r["role"] == "initiator" for r in merged)
            else "participant",
        )
    return SuccessionResult(
        mapping_created=mapping is None, conversations_updated=len(threads)
    )


async def predecessor_target_for_mail(
    db, *, conversation_id: str, successor_did: str, signed: dict
) -> dict | None:
    """Return an old validation projection only for explicit signed DID evidence."""
    rows = await db.get_manager("aweb").fetch_all(
        """SELECT s.*,p.predecessor_alias FROM {{tables.conversation_participant_successions}} p
           JOIN {{tables.local_human_successions}} s USING (predecessor_did)
           WHERE p.conversation_id=$1 AND s.successor_did=$2""",
        UUID(str(conversation_id)),
        successor_did,
    )
    for row in rows:
        old_did, old_key = row["predecessor_did"], row["predecessor_did_key"]
        identities = {old_did, old_key}
        signed_did = next(
            (
                signed[field]
                for field in ("to_stable_id", "to_did", "to")
                if isinstance(signed.get(field), str) and signed[field] in identities
            ),
            None,
        )
        if signed_did is None:
            continue
        return dict(
            signed_did=signed_did,
            did_aw=old_did if old_did.startswith("did:aw:") else None,
            did_key=old_key,
            alias=row["predecessor_alias"],
            address=None,
        )
    return None
