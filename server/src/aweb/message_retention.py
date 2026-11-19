"""Native per-party interests and preview-bound message retention.

Operators own policy and ownership classification. Missing native coverage or
classification is UNKNOWN and retains the message. No operation here enables
retention or changes participant/read authority.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from uuid import UUID, uuid4

from awid.team_ids import parse_team_id
from aweb.service_errors import ConflictError, ValidationError


class RetentionPartyClassification(StrEnum):
    UNKNOWN = "unknown"
    KNOWN = "known"


@dataclass(frozen=True)
class MessageReference:
    kind: str
    message_id: UUID

    def __post_init__(self):
        if self.kind not in {"mail", "chat"}:
            raise ValidationError("Unknown message kind. Select a native mail or chat message, then retry.")
        try:
            object.__setattr__(self, "message_id", UUID(str(self.message_id)))
        except (ValueError, TypeError) as exc:
            raise ValidationError("Invalid message ID. Select an existing native message, then retry.") from exc


@dataclass(frozen=True)
class RetentionSweepScope:
    team_id: str
    cutoff: datetime

    def __post_init__(self):
        try:
            parse_team_id(self.team_id)
        except ValueError as exc:
            raise ValidationError("Invalid retention team. Use a canonical <team>:<namespace> team ID, then retry.") from exc
        if not isinstance(self.cutoff, datetime) or self.cutoff.tzinfo is None or self.cutoff.utcoffset() is None:
            raise ValidationError("Invalid retention cutoff. Use a timezone-aware UTC cutoff, then retry.")
        object.__setattr__(self, "cutoff", self.cutoff.astimezone(timezone.utc))


@dataclass(frozen=True)
class MessageRetentionPreview:
    preview_id: UUID
    scope: RetentionSweepScope
    mail_interests_expiring: int
    chat_interests_expiring: int
    mail_would_delete: int
    chat_would_delete: int
    unclassified_retained: int
    batch_count: int
    next_after: MessageReference | None
    _token: str = field(repr=False)


@dataclass(frozen=True)
class MessageRetentionResult:
    preview_id: UUID
    mail_interests_expired: int = 0
    chat_interests_expired: int = 0
    mail_deleted: int = 0
    chat_deleted: int = 0
    unclassified_retained: int = 0


@dataclass
class _State:
    ref: MessageReference
    received_at: datetime
    parties: set[str | None]
    classifications: dict[str, str]
    interests: list[dict]
    coverage_complete: bool
    pending_delivery: bool

    @property
    def unknown(self) -> bool:
        return (
            not self.coverage_complete or not self.parties or None in self.parties
            or any(
                self.classifications.get(party) != RetentionPartyClassification.KNOWN
                or not any(item["party_did"] == party for item in self.interests)
                for party in self.parties
            )
        )


def _metadata_query(kind: str) -> str:
    if kind == "mail":
        return "SELECT message_id,created_at,conversation_id AS container_id,team_id FROM {{tables.messages}} WHERE message_id=$1"
    return "SELECT m.message_id,m.created_at,m.session_id AS container_id,s.team_id " \
        "FROM {{tables.chat_messages}} m JOIN {{tables.chat_sessions}} s USING (session_id) WHERE m.message_id=$1"


async def _load(db, ref: MessageReference, *, lock: bool = False) -> _State | None:
    meta = await db.fetch_one(_metadata_query(ref.kind), ref.message_id)
    if meta is None:
        return None
    if lock:
        # Federation replay takes its receipt before touching a conversation.
        # Retain that order; the receipt itself is never deleted.
        await db.fetch_one(
            "SELECT message_id FROM {{tables.message_ingress_receipts}} WHERE message_id=$1 FOR UPDATE", ref.message_id,
        )
        if meta["container_id"]:
            await db.fetch_one(
                "SELECT conversation_id FROM {{tables.conversations}} WHERE conversation_id=$1 FOR UPDATE", meta["container_id"],
            )
            if ref.kind == "chat":
                await db.fetch_one("SELECT session_id FROM {{tables.chat_sessions}} WHERE session_id=$1 FOR UPDATE", meta["container_id"])
        table = "messages" if ref.kind == "mail" else "chat_messages"
        live = await db.fetch_value(f"SELECT message_id FROM {{{{tables.{table}}}}} WHERE message_id=$1 FOR UPDATE", ref.message_id)
        if live is None:
            return None
    parties = await db.fetch_all(
        "SELECT party_did FROM aweb.retention_current_parties($1,$2) UNION "
        "SELECT party_did FROM {{tables.message_retention_parties}} WHERE storage_kind=$1 AND message_id=$2",
        ref.kind, ref.message_id,
    )
    coverage = await db.fetch_value(
        "SELECT party_coverage_complete FROM {{tables.message_retention_coverage}} WHERE storage_kind=$1 AND message_id=$2",
        ref.kind, ref.message_id,
    )
    classifications = await db.fetch_all(
        "SELECT party_did,classification FROM {{tables.message_retention_parties}} WHERE storage_kind=$1 AND message_id=$2",
        ref.kind, ref.message_id,
    )
    interests = await db.fetch_all(
        "SELECT party_did,owner_team_id,expired_at FROM {{tables.message_retention_interests}} "
        "WHERE storage_kind=$1 AND message_id=$2" + (" FOR UPDATE" if lock else ""), ref.kind, ref.message_id,
    )
    pending = await db.fetch_value(
        "SELECT EXISTS (SELECT 1 FROM {{tables.federation_mutation_outbox}} WHERE message_id=$1 AND delivered_at IS NULL)", ref.message_id,
    )
    return _State(
        ref, meta["created_at"], {row["party_did"] for row in parties},
        {row["party_did"]: row["classification"] for row in classifications},
        [dict(row) for row in interests], bool(coverage), bool(pending),
    )


def _eligible(state: _State, expiring: set[tuple[str, str]]) -> bool:
    """The one physical-deletion rule used by preview and locked apply."""
    return not state.unknown and not state.pending_delivery and all(
        item["expired_at"] is not None or (item["party_did"], item["owner_team_id"]) in expiring
        for item in state.interests
    )


async def record_message_retention_owners(
    db, *, message: MessageReference, party_did: str, owner_team_ids: frozenset[str],
) -> None:
    """Record host-established historical ownership for one actual party.

    A missing adapter leaves UNKNOWN without affecting message acceptance.
    This function never infers ownership from a current roster and cannot
    replace an owner's live interest. A legacy coverage gap stays UNKNOWN.
    """
    owners = frozenset(owner_team_ids)
    if not owners:
        raise ValidationError("Ownership is unknown. Supply a nonempty established owner-team set, or leave the party unclassified.")
    try:
        for owner in owners:
            parse_team_id(owner)
    except ValueError as exc:
        raise ValidationError("Invalid owner team. Use canonical <team>:<namespace> owner-team IDs, then retry.") from exc
    async with db.transaction() as tx:
        state = await _load(tx, message, lock=True)
        if state is None or party_did not in state.parties:
            raise ValidationError("Message party not found. Select a party from this message's native delivery or history, then retry.")
        found = await tx.fetch_all("SELECT team_id FROM {{tables.teams}} WHERE team_id=ANY($1::text[]) FOR SHARE", sorted(owners))
        if {row["team_id"] for row in found} != owners:
            raise ValidationError("Owner team not admitted. Admit every established owner team before recording message ownership.")
        previous = {item["owner_team_id"] for item in state.interests if item["party_did"] == party_did}
        if state.classifications.get(party_did) == RetentionPartyClassification.KNOWN:
            if previous == owners:
                return
            raise ConflictError("Message retention ownership conflicts. Resolve the ownership transfer explicitly before retrying classification.")
        await tx.execute(
            "INSERT INTO {{tables.message_retention_coverage}} (storage_kind,message_id) VALUES ($1,$2) ON CONFLICT DO NOTHING",
            message.kind, message.message_id,
        )
        await tx.execute(
            "INSERT INTO {{tables.message_retention_parties}} (storage_kind,message_id,party_did,classification) "
            "VALUES ($1,$2,$3,'known') ON CONFLICT (storage_kind,message_id,party_did) DO UPDATE SET classification='known'",
            message.kind, message.message_id, party_did,
        )
        await tx.execute(
            "INSERT INTO {{tables.message_retention_interests}} (storage_kind,message_id,party_did,owner_team_id) "
            "SELECT $1,$2,$3,unnest($4::text[]) ON CONFLICT DO NOTHING",
            message.kind, message.message_id, party_did, sorted(owners),
        )


async def preview_team_message_retention(
    db, *, scope: RetentionSweepScope, limit: int = 200, after: MessageReference | None = None,
) -> MessageRetentionPreview:
    """Preview a bounded batch without expiring interests or deleting content.

    The only write is the native preview receipt/candidate snapshot. Counts
    describe this batch. Pass next_after into the next preview to continue.
    """
    if not 1 <= limit <= 1000:
        raise ValidationError("Invalid retention batch size. Choose a limit from 1 through 1000, then retry.")
    async with db.transaction() as tx:
        now = await tx.fetch_value("SELECT transaction_timestamp()")
        if scope.cutoff > now:
            raise ValidationError("Retention cutoff is in the future. Use a UTC cutoff no later than current database time, then retry.")
        if not await tx.fetch_value("SELECT EXISTS (SELECT 1 FROM {{tables.teams}} WHERE team_id=$1)", scope.team_id):
            raise ValidationError("Retention team is not admitted. Select an admitted native team, then retry.")
        rows = await tx.fetch_all(
            """WITH messages AS (
                SELECT 'mail'::text AS kind,message_id,created_at,team_id FROM {{tables.messages}}
                UNION ALL SELECT 'chat',m.message_id,m.created_at,s.team_id
                    FROM {{tables.chat_messages}} m JOIN {{tables.chat_sessions}} s USING (session_id)
            ) SELECT kind,message_id FROM messages m WHERE created_at<$2
              AND (team_id=$1 OR EXISTS (SELECT 1 FROM {{tables.message_retention_interests}} i
                    WHERE i.storage_kind=m.kind AND i.message_id=m.message_id AND i.owner_team_id=$1))
              AND ($3::text IS NULL OR (kind,message_id)>($3,$4::uuid))
              ORDER BY kind,message_id LIMIT $5""",
            scope.team_id, scope.cutoff, after.kind if after else None, after.message_id if after else None, limit + 1,
        )
        candidates, counts = [], dict(mail_interests_expiring=0, chat_interests_expiring=0, mail_would_delete=0, chat_would_delete=0, unclassified_retained=0)
        for row in rows[:limit]:
            ref = MessageReference(row["kind"], row["message_id"])
            state = await _load(tx, ref)
            if state is None:
                continue
            expiring = {(item["party_did"], item["owner_team_id"]) for item in state.interests
                        if item["owner_team_id"] == scope.team_id and item["expired_at"] is None}
            deletable = _eligible(state, expiring)
            counts[f"{ref.kind}_interests_expiring"] += len(expiring)
            counts[f"{ref.kind}_would_delete"] += int(deletable)
            counts["unclassified_retained"] += int(state.unknown)
            candidates.append(dict(kind=ref.kind, message_id=str(ref.message_id), expire=sorted(expiring), delete=deletable))
        next_after = MessageReference(rows[limit - 1]["kind"], rows[limit - 1]["message_id"]) if len(rows) > limit else None
        preview_id, token = uuid4(), secrets.token_urlsafe(32)
        snapshot = dict(candidates=candidates, counts=counts, batch_count=len(candidates),
                        next_after=[next_after.kind, str(next_after.message_id)] if next_after else None)
        await tx.execute(
            "INSERT INTO {{tables.message_retention_previews}} (preview_id,scope_team_id,cutoff,token_fingerprint,snapshot) "
            "VALUES ($1,$2,$3,$4,$5::jsonb)", preview_id, scope.team_id, scope.cutoff, hashlib.sha256(token.encode()).hexdigest(), json.dumps(snapshot),
        )
        return MessageRetentionPreview(preview_id, scope, **counts, batch_count=len(candidates), next_after=next_after, _token=token)


def _invalid_preview() -> ConflictError:
    return ConflictError("Retention preview is not usable. Run a new retention preview for this team and cutoff, then try again.")


async def apply_team_message_retention(db, *, preview: MessageRetentionPreview) -> MessageRetentionResult:
    """Consume/recheck a real preview; mutate no unpreviewed interest or row.

    Counts are actual affected rows in the caller's transaction. When supplying
    an outer transaction, report commitment only after that transaction commits.
    """
    if (type(preview) is not MessageRetentionPreview or type(preview.scope) is not RetentionSweepScope
            or not isinstance(preview._token, str) or not isinstance(preview.preview_id, UUID)):
        raise _invalid_preview()
    async with db.transaction() as tx:
        receipt = await tx.fetch_one(
            "SELECT * FROM {{tables.message_retention_previews}} WHERE preview_id=$1 FOR UPDATE", preview.preview_id,
        )
        if (receipt is None or receipt["scope_team_id"] != preview.scope.team_id or receipt["cutoff"] != preview.scope.cutoff
                or not hmac.compare_digest(receipt["token_fingerprint"], hashlib.sha256(preview._token.encode()).hexdigest())):
            raise _invalid_preview()
        snapshot = json.loads(receipt["snapshot"]) if isinstance(receipt["snapshot"], str) else receipt["snapshot"]
        if (any(getattr(preview, key) != value for key, value in snapshot["counts"].items())
                or preview.batch_count != snapshot["batch_count"]
                or ([preview.next_after.kind, str(preview.next_after.message_id)] if preview.next_after else None) != snapshot["next_after"]):
            raise _invalid_preview()
        if receipt["consumed_at"] is not None:
            unknown = 0
            for item in snapshot["candidates"]:
                current = await _load(tx, MessageReference(item["kind"], item["message_id"]))
                unknown += int(current is not None and current.unknown)
            return MessageRetentionResult(preview.preview_id, unclassified_retained=unknown)
        counts = dict(mail_interests_expired=0, chat_interests_expired=0, mail_deleted=0, chat_deleted=0, unclassified_retained=0)
        # Stable container order for overlapping opposite-team sweeps.
        ordered = []
        for item in snapshot["candidates"]:
            ref = MessageReference(item["kind"], item["message_id"])
            meta = await tx.fetch_one(_metadata_query(ref.kind), ref.message_id)
            if meta is not None:
                ordered.append((ref.kind, str(meta["container_id"] or ""), str(ref.message_id), ref, item))
        for _, _, _, ref, candidate in sorted(ordered, key=lambda row: row[:3]):
            state = await _load(tx, ref, lock=True)
            if state is None or state.received_at >= preview.scope.cutoff:
                continue
            for party, owner in candidate["expire"]:
                if owner != preview.scope.team_id:
                    raise _invalid_preview()
                changed = await tx.fetch_value(
                    "UPDATE {{tables.message_retention_interests}} SET expired_at=clock_timestamp() "
                    "WHERE storage_kind=$1 AND message_id=$2 AND party_did=$3 AND owner_team_id=$4 AND expired_at IS NULL RETURNING 1",
                    ref.kind, ref.message_id, party, owner,
                )
                counts[f"{ref.kind}_interests_expired"] += int(changed is not None)
            # Re-read under the same locks, including newly retained history.
            state = await _load(tx, ref, lock=True)
            if state is None:
                continue
            counts["unclassified_retained"] += int(state.unknown)
            if candidate["delete"] and _eligible(state, set()):
                if ref.kind == "chat":
                    await tx.execute(
                        "UPDATE {{tables.chat_read_receipts}} SET last_read_message_id=NULL WHERE last_read_message_id=$1", ref.message_id,
                    )
                table = "messages" if ref.kind == "mail" else "chat_messages"
                deleted = await tx.fetch_value(f"DELETE FROM {{{{tables.{table}}}}} WHERE message_id=$1 RETURNING 1", ref.message_id)
                counts[f"{ref.kind}_deleted"] += int(deleted is not None)
        await tx.execute("UPDATE {{tables.message_retention_previews}} SET consumed_at=clock_timestamp() WHERE preview_id=$1", preview.preview_id)
        return MessageRetentionResult(preview.preview_id, **counts)
