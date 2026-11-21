from __future__ import annotations

from aweb.event_types import MutationEventType
from aweb.hook_contexts import (
    TaskAssigneeChangedContext,
    TaskClaimReplacedContext,
    TaskCommentAddedContext,
    TaskCreatedContext,
    TaskDeletedContext,
    TaskDependencyAddedContext,
    TaskDependencyRemovedContext,
    TaskStatusChangedContext,
    TaskUpdatedContext,
)
from aweb.member_team_key import current_member_sql

import logging
import re
import hashlib
import json
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Literal, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from awid.team_ids import team_slug
from ..task_refs import format_task_ref, task_ref_suffix
from ..claims import (
    acquire_task_claim_on,
    lock_task_claim_workspaces_on,
    release_task_claims_on,
)
from ..hooks import MutationCallback, MutationDeliveryStatus, fire_mutation_callback
from ..service_errors import (
    ConflictError,
    ForbiddenError,
    NotFoundError,
    ServiceError,
    ValidationError,
)
from ..team_auth_deps import TeamIdentity
from ..identity_binding import verified_principal_did_sql
from ..workspace_activity import workspace_activity_by_id
from ..grant_liveness_policy import GrantLivenessFailurePolicy

logger = logging.getLogger(__name__)

_UNSET = object()

# The functions that change a task on a member's behalf (create_task,
# update_task, soft_delete_task, add_dependency, remove_dependency,
# add_comment) take the acting member and the on_mutation callback, and fire
# the change's events through that callback after their own write commits. A
# caller that runs one inside its own transaction passes the record method of
# a HeldMutationEvents (aweb.hooks) and fires it after that transaction commits.


class CreateTaskRequest(BaseModel):
    """What a member may supply to create a task, for every transport."""

    model_config = ConfigDict(extra="forbid")

    title: str = Field(..., min_length=1, max_length=4096)
    description: str = Field("", max_length=65536)
    notes: str = Field("", max_length=65536)
    priority: int = Field(2, ge=0, le=4)
    task_type: Literal["task", "bug", "feature", "epic", "chore"] = "task"
    labels: list[str] = Field(default_factory=list)
    parent_task_id: Optional[str] = None
    assignee_alias: Optional[str] = None


class UpdateTaskRequest(BaseModel):
    """What a member may supply to change a task, for every transport."""

    model_config = ConfigDict(extra="forbid")

    title: Optional[str] = Field(None, min_length=1, max_length=4096)
    description: Optional[str] = Field(None, max_length=65536)
    notes: Optional[str] = Field(None, max_length=65536)
    status: Optional[Literal["open", "in_progress", "closed"]] = None
    priority: Optional[int] = Field(None, ge=0, le=4)
    task_type: Optional[Literal["task", "bug", "feature", "epic", "chore"]] = None
    labels: Optional[list[str]] = None
    assignee_alias: Optional[str] = None
    parent_task_id: Optional[str] = None

    def changes(self) -> dict[str, Any]:
        """The fields to change, as update_task arguments.

        A null assignee or parent clears it; any other null field is left alone.
        """
        clearable = {"assignee_alias", "parent_task_id"}
        return {
            name: getattr(self, name)
            for name in self.model_fields_set
            if name in clearable or getattr(self, name) is not None
        }


class AddCommentRequest(BaseModel):
    """What a member may supply to comment on a task, for every transport."""

    model_config = ConfigDict(extra="forbid")

    body: str = Field(..., min_length=1, max_length=65536)


def answer_comment_projection(*, body_md: str, answer_sha256: str) -> str:
    """Juan's C2 ruling: every task answer preserves its exact text."""
    if (
        isinstance(body_md, str)
        and 1 <= len(body_md) <= 20000
        and hashlib.sha256(body_md.encode("utf-8")).hexdigest() == answer_sha256
    ):
        return body_md
    raise ValidationError("schema_invalid")


def _answer_receipt(
    row, *, current_question_rev: int, cancelled: bool = False
) -> dict[str, Any]:
    return {
        "task_answer_ref": str(row["receipt_id"]),
        "task_id": str(row["task_id"]),
        "task_rev": row["task_rev"],
        "question_rev": row["question_rev"],
        "answer_key": row["answer_key"],
        "answer_sha256": row["answer_sha256"],
        "choice": row["choice"],
        "proposal_rev": row["proposal_rev"],
        "proposal_sha256": row["proposal_sha256"],
        "answered_by": {
            "principal_did": row["answered_by_did"],
            "certificate_id": row["certificate_id"],
        },
        "answered_at": row["answered_at"]
        .astimezone(timezone.utc)
        .strftime("%Y-%m-%dT%H:%M:%SZ"),
        "current": row["question_rev"] == current_question_rev and not cancelled,
    }


def _task_request_metadata(value):
    return json.loads(value) if isinstance(value, str) else value or {}


def _eligible_task_condition(index: int) -> str:
    # Absence/null retains single-assignee authority for ordinary/intent tasks.
    # A present array is authoritative, including an empty array (fail closed).
    return (
        f"((jsonb_typeof(app_request->'eligible_dids') = 'array' AND (app_request->'eligible_dids') ? ${index}) OR "
        f"((app_request->'eligible_dids' IS NULL OR app_request->'eligible_dids' = 'null'::jsonb) "
        f"AND assignee_did = ${index}))"
    )


def _task_list_contract(row):
    return {
        "assignee_did": row["assignee_did"],
        "app_request": _task_request_metadata(row["app_request"]) or None,
        "rev": row["rev"],
        "question_rev": row["question_rev"],
    }


async def get_task_answer_on(
    tx, *, team_id: str, task_id: UUID, answer_key: str
) -> dict[str, Any]:
    """Read an immutable receipt inside the caller's authorization transaction.

    The caller enforces member or installation receipt-read authority first.
    Holding the task row stable makes `current` consistent with this read.
    """
    task = await tx.fetch_one(
        """SELECT question_rev, cancellation FROM {{tables.tasks}}
           WHERE task_id = $1 AND team_id = $2 AND deleted_at IS NULL FOR SHARE""",
        task_id,
        team_id,
    )
    if not task:
        raise NotFoundError("Task not found")
    row = await tx.fetch_one(
        "SELECT * FROM {{tables.task_answers}} WHERE task_id = $1 AND answer_key = $2",
        task_id,
        answer_key,
    )
    if not row:
        raise NotFoundError("Answer not found")
    return _answer_receipt(
        row,
        current_question_rev=task["question_rev"],
        cancelled=task["cancellation"] is not None,
    )


async def _read_answer_member_principal_on(tx, *, agent_id: str, team_id: str):
    """Read the answer actor under the existing shared member lock."""
    return await tx.fetch_one(
        f"""SELECT {verified_principal_did_sql(agent="a")} AS principal_did, a.certificate_id
           FROM {{{{tables.agents}}}} a WHERE a.agent_id = $1 AND a.team_id = $2
             AND {current_member_sql("a")} FOR SHARE OF a""",
        UUID(agent_id),
        team_id,
    )


async def _read_claimant_principal_on(tx, *, team_id: str, alias: str):
    """Read a claim's principal under the existing shared member lock."""
    return await tx.fetch_one(
        f"""SELECT {verified_principal_did_sql(agent="a")} AS principal_did
           FROM {{{{tables.agents}}}} a
           WHERE a.team_id = $1 AND a.alias = $2 AND {current_member_sql("a")}
           FOR SHARE OF a""",
        team_id,
        alias,
    )


async def answer_task_on(
    tx,
    *,
    team_id: str,
    task_id: UUID,
    actor: TeamIdentity,
    expected_task_rev: int,
    answer_key: str,
    answer_sha256: str,
    body_md: str,
    choice: str | None = None,
    proposal_rev: int | None = None,
    proposal_sha256: str | None = None,
    stage_receipt: dict | None = None,
    outcome: dict | None = None,
) -> dict[str, Any]:
    """Commit an answer using the caller's transaction and verified identity.

    The caller authenticates current certificate authority before entry. The
    local member projection must still match that certificate and principal.
    This function never opens/commits a transaction or delivers external mail.
    """
    if (
        not isinstance(answer_key, str)
        or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", answer_key)
        or not isinstance(answer_sha256, str)
        or not re.fullmatch(r"[0-9a-f]{64}", answer_sha256)
        or type(expected_task_rev) is not int
        or not 1 <= expected_task_rev <= 2**53 - 1
        or (
            proposal_rev is not None
            and (type(proposal_rev) is not int or not 0 <= proposal_rev <= 2**53 - 1)
        )
        or (
            proposal_sha256 is not None
            and (
                not isinstance(proposal_sha256, str)
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", proposal_sha256)
            )
        )
    ):
        raise ValidationError("schema_invalid")
    comment_body = answer_comment_projection(
        body_md=body_md, answer_sha256=answer_sha256
    )
    # Installation -> task is F6 retirement's lock order. Keep it identical
    # here, including when the member API (rather than app transport) answers.
    source = await tx.fetch_one(
        "SELECT * FROM {{tables.task_app_requests}} WHERE task_id=$1 AND team_id=$2",
        task_id,
        team_id,
    )
    installation = None
    if source:
        from aweb.app_registry import get_installation_on

        installation = await get_installation_on(
            tx, team_id=team_id, app_id=source["app_id"], for_update=True
        )
    task = await tx.fetch_one(
        """SELECT task_id, rev, question_rev, status, assignee_did, app_request, cancellation,
                  task_ref_suffix, title, assignee_alias
           FROM {{tables.tasks}} WHERE task_id = $1 AND team_id = $2
             AND deleted_at IS NULL FOR UPDATE""",
        task_id,
        team_id,
    )
    if not task:
        raise NotFoundError("Task not found")
    await lock_task_claim_workspaces_on(
        tx,
        team_id=team_id,
        task_refs=[
            format_task_ref(
                team_slug=_get_team_slug(team_id),
                task_ref_suffix=task["task_ref_suffix"],
            )
        ],
    )
    principal = actor.did_aw or actor.did_key
    member = await _read_answer_member_principal_on(
        tx, agent_id=actor.agent_id, team_id=team_id
    )
    if (
        actor.team_id != team_id
        or not member
        or member["principal_did"] != principal
        or not actor.certificate_id
        or member["certificate_id"] != actor.certificate_id
    ):
        raise ForbiddenError("target_mismatch")
    existing = await tx.fetch_one(
        "SELECT * FROM {{tables.task_answers}} WHERE task_id = $1 AND answer_key = $2",
        task_id,
        answer_key,
    )
    if existing:
        if existing["answered_by_did"] != principal:
            raise ForbiddenError("target_mismatch")
        if any(
            existing[k] != v
            for k, v in {
                "answer_sha256": answer_sha256,
                "choice": choice,
                "proposal_rev": proposal_rev,
                "proposal_sha256": proposal_sha256,
            }.items()
        ):
            raise ConflictError("idempotency_conflict")
        if outcome is not None:
            outcome["created"] = False
        return _answer_receipt(
            existing,
            current_question_rev=task["question_rev"],
            cancelled=task["cancellation"] is not None,
        )
    metadata = _task_request_metadata(task["app_request"])
    eligible = metadata.get("eligible_dids")
    answerers = [task["assignee_did"]] if eligible is None else eligible
    if not isinstance(answerers, list) or principal not in answerers:
        raise ForbiddenError("target_mismatch")
    if metadata.get("proposal_rev") is not None:
        from .app_tasks import verify_answer_stage_on

        await verify_answer_stage_on(
            tx,
            stage=stage_receipt,
            source=source,
            installation=installation,
            task=task,
            principal=principal,
            answer_key=answer_key,
            answer_sha256=answer_sha256,
            choice=choice,
            proposal_rev=proposal_rev,
            proposal_sha256=proposal_sha256,
        )
    elif stage_receipt is not None:
        raise ValidationError("schema_invalid")
    if (
        task["rev"] != expected_task_rev
        or task["status"] != "open"
        or task["cancellation"] is not None
    ):
        raise ConflictError("revision_conflict")
    if proposal_rev != metadata.get("proposal_rev") or proposal_sha256 != metadata.get(
        "proposal_sha256"
    ):
        raise ConflictError("approval_changed")
    choices = metadata.get("choices")
    choice_values = (
        [entry["value"] for entry in choices] if choices is not None else None
    )
    if (choice_values is not None and choice not in choice_values) or (
        choices is None and choice is not None
    ):
        raise ValidationError("schema_invalid")
    receipt_id = uuid4()
    if await tx.fetch_value(
        "SELECT 1 FROM {{tables.task_answers}} WHERE task_id = $1 AND question_rev = $2",
        task_id,
        task["question_rev"],
    ):
        raise ConflictError("revision_conflict")
    comment = await tx.fetch_one(
        """INSERT INTO {{tables.task_comments}} (task_id, team_id, author_alias, body)
           VALUES ($1, $2, $3, $4) RETURNING comment_id""",
        task_id,
        team_id,
        actor.alias,
        comment_body,
    )
    updated = await tx.fetch_one(
        """UPDATE {{tables.tasks}} SET status = 'closed', closed_by_alias = $2,
               closed_by_did = $3, closed_at = NOW(), updated_at = NOW()
           WHERE task_id = $1 RETURNING rev""",
        task_id,
        actor.alias,
        principal,
    )
    task_ref = format_task_ref(
        team_slug=_get_team_slug(team_id), task_ref_suffix=task["task_ref_suffix"]
    )
    released_claim_workspace_ids = await release_task_claims_on(
        tx, team_id=team_id, task_ref=task_ref
    )
    row = await tx.fetch_one(
        """INSERT INTO {{tables.task_answers}}
               (task_id, question_rev, task_rev, answer_key, answer_sha256, answered_by_did, certificate_id,
                receipt_id, choice, proposal_rev, proposal_sha256, stage_receipt)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb) RETURNING *""",
        task_id,
        task["question_rev"],
        updated["rev"],
        answer_key,
        answer_sha256,
        principal,
        actor.certificate_id,
        receipt_id,
        choice,
        proposal_rev,
        proposal_sha256,
        json.dumps(stage_receipt) if stage_receipt else None,
    )
    if stage_receipt is not None:
        await tx.execute(
            """INSERT INTO {{tables.task_answer_stage_nonces}} (team_id,app_id,installation_id,nonce,receipt_id)
               VALUES ($1,$2,$3,$4,$5)""",
            team_id,
            source["app_id"],
            source["installation_id"],
            stage_receipt["payload"]["nonce"],
            receipt_id,
        )
    if outcome is not None:
        outcome["created"] = True
        outcome["comment_id"] = str(comment["comment_id"])
        outcome.update(
            task_ref=task_ref,
            title=task["title"],
            assignee_alias=task["assignee_alias"],
            released_claim_workspace_ids=released_claim_workspace_ids,
        )
    return _answer_receipt(row, current_question_rev=task["question_rev"])


def _encode_alpha_component(value: int, *, minimum_width: int = 4) -> str:
    if value < 1:
        raise ValueError("value must be >= 1")

    remaining = value - 1
    result = ""
    while True:
        result = chr(ord("a") + (remaining % 26)) + result
        remaining //= 26
        if remaining == 0:
            break

    if len(result) < minimum_width:
        result = ("a" * (minimum_width - len(result))) + result
    return result


async def _allocate_task_number_on(manager, *, team_id: str) -> int:
    row = await manager.fetch_one(
        """
        INSERT INTO {{tables.task_counters}} (team_id, next_number)
        VALUES ($1, 2)
        ON CONFLICT (team_id) DO UPDATE SET next_number = {{tables.task_counters}}.next_number + 1
        RETURNING next_number - 1 AS task_number
        """,
        team_id,
    )
    return row["task_number"]


async def _allocate_root_task_seq_on(manager, *, team_id: str) -> int:
    row = await manager.fetch_one(
        """
        INSERT INTO {{tables.task_root_counters}} (team_id, next_number)
        VALUES ($1, 2)
        ON CONFLICT (team_id) DO UPDATE
        SET next_number = {{tables.task_root_counters}}.next_number + 1
        RETURNING next_number - 1 AS root_task_seq
        """,
        team_id,
    )
    return row["root_task_seq"]


def _get_team_slug(team_id: str) -> str:
    return team_slug(team_id)


async def _log_resolution_miss(
    aweb_db,
    *,
    team_id: str,
    ref: str,
    ref_suffix: str,
    lookup: str,
    task_uuid: UUID | None = None,
) -> None:
    """Log a task ref resolution miss with enough context to diagnose it.

    Production has shown misses for tasks that exist and resolve on
    immediate retry (default-aagh). The diagnostics use separate pool
    acquires, which at low concurrency usually return the same underlying
    connection that served the miss (asyncpg pools are LIFO). A match for
    the requesting team that is not soft-deleted therefore proves the miss
    was a visibility anomaly; an empty match list is ambiguous and does
    not prove the row was absent. Match tuples carry the row xmin so a
    positive match can be compared against the logged snapshot post hoc.
    """
    try:
        if task_uuid is not None:
            matches = await aweb_db.fetch_all(
                """
                SELECT team_id, deleted_at IS NOT NULL AS deleted, xmin::text AS row_xmin
                FROM {{tables.tasks}}
                WHERE task_id = $1
                LIMIT 5
                """,
                task_uuid,
            )
        else:
            matches = await aweb_db.fetch_all(
                """
                SELECT team_id, deleted_at IS NOT NULL AS deleted, xmin::text AS row_xmin
                FROM {{tables.tasks}}
                WHERE task_ref_suffix = $1
                LIMIT 5
                """,
                ref_suffix,
            )
        conn_info = await aweb_db.fetch_one(
            "SELECT pg_backend_pid() AS backend_pid, pg_current_snapshot()::text AS snapshot"
        )
        logger.warning(
            "task ref resolution miss: team_id=%r ref=%r suffix=%r lookup=%s "
            "matches=%s backend_pid=%s snapshot=%s",
            team_id,
            ref,
            ref_suffix,
            lookup,
            [(r["team_id"], r["deleted"], r["row_xmin"]) for r in matches],
            conn_info["backend_pid"],
            conn_info["snapshot"],
        )
    except Exception:
        logger.warning(
            "task ref resolution miss: team_id=%r ref=%r suffix=%r lookup=%s (diagnostics unavailable)",
            team_id,
            ref,
            ref_suffix,
            lookup,
            exc_info=True,
        )


class TaskVisibility(StrEnum):
    ACTIVE = "active"
    INCLUDING_DELETED = "including_deleted"


class TaskDeletionIncompleteError(ServiceError):
    status_code = 503


async def resolve_task_ref(
    db, *, team_id: str, ref: str, visibility: TaskVisibility = TaskVisibility.ACTIVE
) -> UUID:
    """Resolve an ID or task reference within the explicit native team scope."""
    aweb_db = db.get_manager("aweb")
    if type(visibility) is not TaskVisibility:
        raise TypeError("Expected TaskVisibility")
    active_clause = (
        " AND deleted_at IS NULL" if visibility is TaskVisibility.ACTIVE else ""
    )

    try:
        task_uuid = UUID(ref)
    except ValueError:
        task_uuid = None

    if task_uuid is not None:
        row = await aweb_db.fetch_one(
            "SELECT task_id FROM {{tables.tasks}} WHERE task_id = $1 AND team_id = $2"
            + active_clause,
            task_uuid,
            team_id,
        )
        if not row:
            await _log_resolution_miss(
                aweb_db,
                team_id=team_id,
                ref=ref,
                ref_suffix="",
                lookup="task_id",
                task_uuid=task_uuid,
            )
            raise NotFoundError("Task not found")
        return row["task_id"]

    ref_suffix = task_ref_suffix(team_id=team_id, ref=ref)

    if not ref_suffix:
        raise NotFoundError("Task not found")

    row = await aweb_db.fetch_one(
        "SELECT task_id FROM {{tables.tasks}} WHERE team_id = $1 AND task_ref_suffix = $2"
        + active_clause,
        team_id,
        ref_suffix,
    )
    if row:
        return row["task_id"]

    await _log_resolution_miss(
        aweb_db,
        team_id=team_id,
        ref=ref,
        ref_suffix=ref_suffix,
        lookup="task_ref_suffix",
    )
    raise NotFoundError("Task not found")


async def _lock_task_hierarchy_on(tx, *, team_id: str) -> None:
    await tx.fetch_value(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
        f"task-parent-hierarchy:{team_id}",
    )


async def create_task(
    db,
    *,
    actor: TeamIdentity,
    on_mutation: MutationCallback | None,
    title: str,
    description: str = "",
    notes: str = "",
    priority: int = 2,
    task_type: str = "task",
    labels: list[str] | None = None,
    parent_task_id: str | None = None,
    assignee_alias: str | None = None,
) -> dict[str, Any]:
    """Create a task for the acting member and publish its committed mutation."""
    team_id = actor.team_id
    created_by_alias = actor.alias
    created_by_did = actor.did_aw or actor.did_key
    slug = _get_team_slug(team_id)
    aweb_db = db.get_manager("aweb")
    resolved_parent_task_id: UUID | None = None
    task_ref_suffix: str | None = None

    async with aweb_db.transaction() as tx:
        if parent_task_id:
            await _lock_task_hierarchy_on(tx, team_id=team_id)
        assignee_did = None
        if assignee_alias:
            assignee_alias, assignee_did = await _resolve_assignee_on(
                tx,
                team_id=team_id,
                assignee_ref=assignee_alias,
            )
        task_number = await _allocate_task_number_on(tx, team_id=team_id)
        root_task_seq: int

        if parent_task_id:
            try:
                resolved_parent_task_id = await resolve_task_ref(
                    db,
                    team_id=team_id,
                    ref=parent_task_id,
                )
            except NotFoundError as exc:
                raise ValidationError("Parent task not found in this team") from exc

            parent_row = await tx.fetch_one(
                """
                SELECT task_id, task_ref_suffix, root_task_seq
                FROM {{tables.tasks}}
                WHERE task_id = $1 AND team_id = $2 AND deleted_at IS NULL
                FOR UPDATE
                """,
                resolved_parent_task_id,
                team_id,
            )
            if not parent_row:
                raise ValidationError("Parent task not found in this team")

            # References survive reparenting and soft deletion. Reserve every
            # direct numeric suffix in this parent's namespace, wherever its
            # task now lives; imported children must not affect the sequence.
            child_ref_prefix = f"{parent_row['task_ref_suffix']}."
            max_sibling_index = await tx.fetch_value(
                """
                SELECT COALESCE(MAX(CASE WHEN suffix ~ '^[0-9]+$'
                                        THEN CAST(suffix AS INTEGER) END), 0)
                FROM (
                    SELECT SUBSTRING(task_ref_suffix FROM LENGTH($2) + 1) AS suffix
                    FROM {{tables.tasks}}
                    WHERE team_id = $1 AND LEFT(task_ref_suffix, LENGTH($2)) = $2
                ) AS child_refs
                """,
                team_id,
                child_ref_prefix,
            )
            root_task_seq = parent_row["root_task_seq"]
            task_ref_suffix = (
                f"{parent_row['task_ref_suffix']}.{int(max_sibling_index) + 1}"
            )
        else:
            root_task_seq = await _allocate_root_task_seq_on(tx, team_id=team_id)
            task_ref_suffix = _encode_alpha_component(root_task_seq)

        row = await tx.fetch_one(
            """
            INSERT INTO {{tables.tasks}}
                (team_id, task_number, root_task_seq, task_ref_suffix, title, description, notes, priority, task_type,
                 labels, parent_task_id, assignee_alias, created_by_alias, assignee_did, created_by_did)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
            RETURNING task_id, created_at, updated_at
            """,
            team_id,
            task_number,
            root_task_seq,
            task_ref_suffix,
            title,
            description,
            notes,
            priority,
            task_type,
            labels or [],
            resolved_parent_task_id,
            assignee_alias,
            created_by_alias,
            assignee_did,
            created_by_did,
        )

    result = {
        "task_id": str(row["task_id"]),
        "task_ref": format_task_ref(team_slug=slug, task_ref_suffix=task_ref_suffix),
        "task_number": task_number,
        "team_id": team_id,
        "title": title,
        "description": description,
        "notes": notes,
        "status": "open",
        "priority": priority,
        "task_type": task_type,
        "labels": labels or [],
        "parent_task_id": str(resolved_parent_task_id)
        if resolved_parent_task_id
        else None,
        "assignee_alias": assignee_alias,
        "created_by_alias": created_by_alias,
        "closed_by_alias": None,
        "created_at": row["created_at"].isoformat(),
        "updated_at": row["updated_at"].isoformat() if row.get("updated_at") else None,
        "closed_at": None,
        "rev": 1,
        "question_rev": 1,
        "assignee_did": assignee_did,
        "created_by_did": created_by_did,
        "closed_by_did": None,
    }
    await fire_mutation_callback(
        on_mutation,
        MutationEventType.TASK_CREATED.value,
        TaskCreatedContext(
            task_id=result["task_id"],
            team_id=team_id,
            task_ref=result["task_ref"],
            title=result["title"],
            parent_task_id=result["parent_task_id"],
            assignee_alias=result["assignee_alias"],
            actor_agent_id=actor.agent_id,
            actor_alias=actor.alias,
            actor_did_aw=actor.did_aw,
        ).to_context(),
    )
    return result


async def _resolve_assignee_on(
    manager, *, team_id: str, assignee_ref: str
) -> tuple[str, str]:
    """Resolve display alias and immutable principal together, on the write tx."""
    try:
        agent_id = UUID(assignee_ref)
    except ValueError:
        agent_id = None
    row = await manager.fetch_one(
        f"""
        SELECT a.alias, {verified_principal_did_sql(agent="a")} AS principal_did
        FROM {{{{tables.agents}}}} a
        WHERE a.team_id = $1 AND {current_member_sql("a")}
          AND (($2::uuid IS NOT NULL AND a.agent_id = $2)
               OR ($2::uuid IS NULL AND a.alias = $3))
        FOR SHARE OF a
        """,
        team_id,
        agent_id,
        assignee_ref.strip(),
    )
    if not row:
        raise ValidationError("Assignee agent not found in this team")
    return row["alias"], row["principal_did"]


async def _resolve_assignee_alias(
    db,
    *,
    team_id: str,
    assignee_ref: str,
) -> str:
    """Resolve the same current member used by the transaction's assignee check."""
    alias, _ = await _resolve_assignee_on(
        db.get_manager("aweb"), team_id=team_id, assignee_ref=assignee_ref
    )
    return alias


async def get_task(db, *, team_id: str, ref: str) -> dict[str, Any]:
    """Read a task projection within the explicit native team scope."""
    task_id = await resolve_task_ref(db, team_id=team_id, ref=ref)
    slug = _get_team_slug(team_id)
    aweb_db = db.get_manager("aweb")

    row = await aweb_db.fetch_one(
        """
        SELECT task_id, team_id, task_number, title, description, notes,
               task_ref_suffix, status, priority, task_type, labels, parent_task_id,
               assignee_alias, created_by_alias, closed_by_alias,
               created_at, updated_at, closed_at, rev, question_rev,
               assignee_did, created_by_did, closed_by_did, app_request, cancellation, picked_up
        FROM {{tables.tasks}}
        WHERE task_id = $1 AND deleted_at IS NULL
        """,
        task_id,
    )
    if not row:
        raise NotFoundError("Task not found")

    blocked_by_rows = await aweb_db.fetch_all(
        """
        SELECT t.task_id, t.task_number, t.title, t.status
             , t.task_ref_suffix
        FROM {{tables.task_dependencies}} d
        JOIN {{tables.tasks}} t ON t.task_id = d.depends_on_id
        WHERE d.task_id = $1 AND t.deleted_at IS NULL
        """,
        task_id,
    )
    blocks_rows = await aweb_db.fetch_all(
        """
        SELECT t.task_id, t.task_number, t.title, t.status
             , t.task_ref_suffix
        FROM {{tables.task_dependencies}} d
        JOIN {{tables.tasks}} t ON t.task_id = d.task_id
        WHERE d.depends_on_id = $1 AND t.deleted_at IS NULL
        """,
        task_id,
    )

    def _dep_view(r):
        return {
            "task_id": str(r["task_id"]),
            "task_ref": format_task_ref(
                team_slug=slug, task_ref_suffix=r["task_ref_suffix"]
            ),
            "title": r["title"],
            "status": r["status"],
        }

    answer = await aweb_db.fetch_one(
        "SELECT * FROM {{tables.task_answers}} WHERE task_id = $1 AND question_rev = $2",
        task_id,
        row["question_rev"],
    )

    def json_value(value):
        """Decode a stored JSON projection while retaining already decoded values."""
        return json.loads(value) if isinstance(value, str) else value

    return {
        "task_id": str(row["task_id"]),
        "task_ref": format_task_ref(
            team_slug=slug, task_ref_suffix=row["task_ref_suffix"]
        ),
        "task_number": row["task_number"],
        "team_id": row["team_id"],
        "title": row["title"],
        "description": row["description"],
        "notes": row["notes"],
        "status": row["status"],
        "priority": row["priority"],
        "task_type": row["task_type"],
        "labels": list(row["labels"]) if row["labels"] else [],
        "parent_task_id": str(row["parent_task_id"]) if row["parent_task_id"] else None,
        "assignee_alias": row["assignee_alias"],
        "created_by_alias": row["created_by_alias"],
        "closed_by_alias": row["closed_by_alias"],
        "created_at": row["created_at"].isoformat(),
        "updated_at": row["updated_at"].isoformat() if row.get("updated_at") else None,
        "closed_at": row["closed_at"].isoformat() if row["closed_at"] else None,
        "blocked_by": [_dep_view(r) for r in blocked_by_rows],
        "blocks": [_dep_view(r) for r in blocks_rows],
        "rev": row["rev"],
        "question_rev": row["question_rev"],
        "assignee_did": row["assignee_did"],
        "created_by_did": row["created_by_did"],
        "closed_by_did": row["closed_by_did"],
        "app_request": json_value(row["app_request"]),
        "cancellation": json_value(row["cancellation"]),
        "picked_up": row["picked_up"],
        "answer": _answer_receipt(
            answer,
            current_question_rev=row["question_rev"],
            cancelled=row["cancellation"] is not None,
        )
        if answer
        else None,
    }


async def list_tasks(
    db,
    *,
    team_id: str,
    status: str | None = None,
    assignee_alias: str | None = None,
    eligible_did: str | None = None,
    task_type: str | None = None,
    priority: int | None = None,
    labels: list[str] | None = None,
    q: str | None = None,
    parent_task_id: str | None = None,
) -> list[dict[str, Any]]:
    """Read task projections using the explicit team and requested filters."""
    slug = _get_team_slug(team_id)
    aweb_db = db.get_manager("aweb")

    conditions = ["team_id = $1", "deleted_at IS NULL"]
    params: list[Any] = [team_id]
    idx = 2

    if status is not None:
        statuses = [s.strip() for s in status.split(",") if s.strip()]
        if len(statuses) == 1:
            conditions.append(f"status = ${idx}")
            params.append(statuses[0])
        else:
            conditions.append(f"status = ANY(${idx})")
            params.append(statuses)
        idx += 1
    if assignee_alias is not None:
        resolved_alias = await _resolve_assignee_alias(
            db,
            team_id=team_id,
            assignee_ref=assignee_alias,
        )
        conditions.append(f"assignee_alias = ${idx}")
        params.append(resolved_alias)
        idx += 1
    if eligible_did is not None:
        conditions.append(_eligible_task_condition(idx))
        params.append(eligible_did)
        idx += 1
    if task_type is not None:
        conditions.append(f"task_type = ${idx}")
        params.append(task_type)
        idx += 1
    if priority is not None:
        conditions.append(f"priority = ${idx}")
        params.append(priority)
        idx += 1
    if labels:
        conditions.append(f"labels @> ${idx}")
        params.append(labels)
        idx += 1
    if parent_task_id is not None:
        resolved_parent_task_id = await resolve_task_ref(
            db,
            team_id=team_id,
            ref=parent_task_id,
        )
        conditions.append(f"parent_task_id = ${idx}")
        params.append(resolved_parent_task_id)
        idx += 1
    if q is not None:
        q_escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        q_pattern = f"%{q_escaped}%"
        conditions.append(
            f"(title ILIKE ${idx} OR (${idx + 1} || '-' || task_ref_suffix) ILIKE ${idx})"
        )
        params.append(q_pattern)
        params.append(slug)
        idx += 2

    rows = await aweb_db.fetch_all(
        f"""
        SELECT task_id, task_number, task_ref_suffix, title, status, priority, task_type,
               assignee_alias, created_by_alias, parent_task_id, labels,
               created_at, updated_at, assignee_did, app_request, rev, question_rev
        FROM {{{{tables.tasks}}}}
        WHERE {" AND ".join(conditions)}
        ORDER BY task_number ASC
        """,
        *params,
    )
    return [
        {
            **_task_list_contract(r),
            "task_id": str(r["task_id"]),
            "task_ref": format_task_ref(
                team_slug=slug, task_ref_suffix=r["task_ref_suffix"]
            ),
            "task_number": r["task_number"],
            "title": r["title"],
            "status": r["status"],
            "priority": r["priority"],
            "task_type": r["task_type"],
            "assignee_alias": r["assignee_alias"],
            "created_by_alias": r["created_by_alias"],
            "parent_task_id": str(r["parent_task_id"]) if r["parent_task_id"] else None,
            "labels": list(r["labels"]) if r["labels"] else [],
            "created_at": r["created_at"].isoformat(),
            "updated_at": r["updated_at"].isoformat() if r["updated_at"] else None,
        }
        for r in rows
    ]


async def list_tasks_paginated(
    db,
    *,
    team_id: str,
    status: str | None = None,
    assignee_alias: str | None = None,
    eligible_did: str | None = None,
    task_type: str | None = None,
    priority: int | None = None,
    labels: list[str] | None = None,
    q: str | None = None,
    limit: int = 50,
    created_before: datetime | None = None,
    task_id_before: UUID | None = None,
) -> list[dict[str, Any]]:
    """Read a bounded task page and its continuation within the explicit team."""
    slug = _get_team_slug(team_id)
    aweb_db = db.get_manager("aweb")

    conditions = ["team_id = $1", "deleted_at IS NULL"]
    params: list[Any] = [team_id]
    idx = 2

    if status is not None:
        statuses = [s.strip() for s in status.split(",") if s.strip()]
        if len(statuses) == 1:
            conditions.append(f"status = ${idx}")
            params.append(statuses[0])
        else:
            conditions.append(f"status = ANY(${idx})")
            params.append(statuses)
        idx += 1
    if assignee_alias is not None:
        resolved_alias = await _resolve_assignee_alias(
            db,
            team_id=team_id,
            assignee_ref=assignee_alias,
        )
        conditions.append(f"assignee_alias = ${idx}")
        params.append(resolved_alias)
        idx += 1
    if eligible_did is not None:
        conditions.append(_eligible_task_condition(idx))
        params.append(eligible_did)
        idx += 1
    if task_type is not None:
        conditions.append(f"task_type = ${idx}")
        params.append(task_type)
        idx += 1
    if priority is not None:
        conditions.append(f"priority = ${idx}")
        params.append(priority)
        idx += 1
    if labels:
        conditions.append(f"labels @> ${idx}")
        params.append(labels)
        idx += 1
    if q is not None:
        q_escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        q_pattern = f"%{q_escaped}%"
        conditions.append(
            f"(title ILIKE ${idx} ESCAPE '\\' OR description ILIKE ${idx + 1} ESCAPE '\\')"
        )
        params.append(q_pattern)
        params.append(q_pattern)
        idx += 2
    if created_before is not None and task_id_before is not None:
        conditions.append(
            f"(created_at < ${idx} OR (created_at = ${idx} AND task_id < ${idx + 1}))"
        )
        params.append(created_before)
        params.append(task_id_before)
        idx += 2

    params.append(limit)
    rows = await aweb_db.fetch_all(
        f"""
        SELECT t.task_id, t.task_number, t.task_ref_suffix, t.title, t.description, t.status,
               t.priority, t.task_type, t.assignee_alias, t.created_by_alias, t.parent_task_id,
               t.labels, t.created_at, t.updated_at, t.assignee_did, t.app_request, t.rev, t.question_rev,
               (
                   SELECT COUNT(*)
                   FROM {{{{tables.task_dependencies}}}} d
                   JOIN {{{{tables.tasks}}}} blocker ON blocker.task_id = d.depends_on_id
                   WHERE d.task_id = t.task_id
                     AND blocker.deleted_at IS NULL
               ) AS blocker_count
        FROM {{{{tables.tasks}}}} t
        WHERE {" AND ".join(conditions)}
        ORDER BY t.created_at DESC, t.task_id DESC
        LIMIT ${idx}
        """,
        *params,
    )
    return [
        {
            **_task_list_contract(r),
            "task_id": str(r["task_id"]),
            "task_ref": format_task_ref(
                team_slug=slug, task_ref_suffix=r["task_ref_suffix"]
            ),
            "task_number": r["task_number"],
            "title": r["title"],
            "description": r["description"],
            "status": r["status"],
            "priority": r["priority"],
            "task_type": r["task_type"],
            "assignee_alias": r["assignee_alias"],
            "created_by_alias": r["created_by_alias"],
            "parent_task_id": str(r["parent_task_id"]) if r["parent_task_id"] else None,
            "labels": list(r["labels"]) if r["labels"] else [],
            "created_at": r["created_at"].isoformat(),
            "updated_at": r["updated_at"].isoformat() if r["updated_at"] else None,
            "blocker_count": r["blocker_count"],
        }
        for r in rows
    ]


async def list_active_work(
    db, *, team_id: str, redis, registry_client, request=None
) -> list[dict[str, Any]]:
    """Read active claims and associated tasks within the explicit team."""
    slug = _get_team_slug(team_id)
    aweb_db = db.get_manager("aweb")

    task_rows = await aweb_db.fetch_all(
        """
        SELECT task_id, task_number, task_ref_suffix, title, status, priority, task_type,
               assignee_alias, created_by_alias, parent_task_id, labels,
               created_at, updated_at
        FROM {{tables.tasks}}
        WHERE team_id = $1
          AND status = 'in_progress'
          AND deleted_at IS NULL
        ORDER BY priority ASC, task_number ASC
        """,
        team_id,
    )
    if not task_rows:
        return []

    task_refs = {
        format_task_ref(team_slug=slug, task_ref_suffix=row["task_ref_suffix"])
        for row in task_rows
    }

    claim_rows = await aweb_db.fetch_all(
        """
        SELECT task_ref, workspace_id, alias, claimed_at
        FROM {{tables.task_claims}}
        WHERE team_id = $1
        ORDER BY claimed_at DESC
        """,
        team_id,
    )

    latest_claim_by_ref: dict[str, dict[str, Any]] = {}
    for row in claim_rows:
        task_ref = row["task_ref"]
        if task_ref not in task_refs or task_ref in latest_claim_by_ref:
            continue
        latest_claim_by_ref[task_ref] = {
            "workspace_id": str(row["workspace_id"]),
            "alias": row["alias"],
            "claimed_at": row["claimed_at"].isoformat(),
        }

    claim_workspace_ids: list[str] = []
    seen_claim_workspace_ids: set[str] = set()
    for row in task_rows:
        task_ref = format_task_ref(
            team_slug=slug, task_ref_suffix=row["task_ref_suffix"]
        )
        claim = latest_claim_by_ref.get(task_ref)
        if claim is not None:
            workspace_id = claim["workspace_id"]
            if workspace_id not in seen_claim_workspace_ids:
                seen_claim_workspace_ids.add(workspace_id)
                claim_workspace_ids.append(workspace_id)

    workspace_meta_by_id: dict[str, dict[str, Any]] = {}
    if claim_workspace_ids:
        workspace_params: list[Any] = [team_id]
        workspace_placeholders: list[str] = []
        for raw_id in claim_workspace_ids:
            workspace_params.append(UUID(raw_id))
            workspace_placeholders.append(f"${len(workspace_params)}")
        workspace_rows = await aweb_db.fetch_all(
            f"""
            SELECT w.workspace_id, w.alias, r.canonical_origin
            FROM {{{{tables.workspaces}}}} w
            LEFT JOIN {{{{tables.repos}}}} r ON w.repo_id = r.id AND r.deleted_at IS NULL
            WHERE w.team_id = $1
              AND w.deleted_at IS NULL
              AND w.workspace_id IN ({", ".join(workspace_placeholders)})
            """,
            *workspace_params,
        )
        activity = await workspace_activity_by_id(
            aweb_db,
            redis,
            workspace_ids=[str(row["workspace_id"]) for row in workspace_rows],
            registry_client=registry_client,
            request=request,
            failure_policy=GrantLivenessFailurePolicy.OMIT_UNPROVEN,
        )
        for row in workspace_rows:
            workspace_id = str(row["workspace_id"])
            observed = activity.get(workspace_id)
            workspace_meta_by_id[workspace_id] = {
                "alias": row["alias"],
                "last_seen_at": observed.last_seen_at.isoformat()
                if observed and observed.last_seen_at
                else None,
                "canonical_origin": row["canonical_origin"],
                "branch": (observed.presence or {}).get("current_branch")
                if observed
                else None,
            }

    items: list[dict[str, Any]] = []
    for row in task_rows:
        task_ref = format_task_ref(
            team_slug=slug, task_ref_suffix=row["task_ref_suffix"]
        )
        claim = latest_claim_by_ref.get(task_ref)
        owner_workspace_id = None
        owner_alias = None
        claimed_at = None

        if claim is not None:
            owner_workspace_id = claim["workspace_id"]
            owner_alias = claim["alias"]
            claimed_at = claim["claimed_at"]
        elif row["assignee_alias"]:
            owner_alias = row["assignee_alias"]

        workspace_meta = (
            workspace_meta_by_id.get(owner_workspace_id or "")
            if owner_workspace_id
            else None
        ) or {}
        if owner_alias is None:
            owner_alias = workspace_meta.get("alias")

        items.append(
            {
                "task_id": str(row["task_id"]),
                "task_ref": task_ref,
                "task_number": row["task_number"],
                "title": row["title"],
                "status": row["status"],
                "priority": row["priority"],
                "task_type": row["task_type"],
                "assignee_alias": row["assignee_alias"],
                "created_by_alias": row["created_by_alias"],
                "parent_task_id": str(row["parent_task_id"])
                if row["parent_task_id"]
                else None,
                "labels": list(row["labels"]) if row["labels"] else [],
                "created_at": row["created_at"].isoformat(),
                "updated_at": row["updated_at"].isoformat()
                if row.get("updated_at")
                else None,
                "workspace_id": owner_workspace_id,
                "owner_alias": owner_alias,
                "claimed_at": claimed_at,
                "owner_last_seen_at": workspace_meta.get("last_seen_at"),
                "canonical_origin": workspace_meta.get("canonical_origin"),
                "branch": workspace_meta.get("branch"),
            }
        )

    items.sort(
        key=lambda item: (
            item.get("canonical_origin") or "~",
            item["priority"],
            item["task_ref"],
        )
    )
    return items


async def list_ready_tasks(
    db, *, team_id: str, unclaimed: bool = False
) -> list[dict[str, Any]]:
    """Read unblocked task candidates within the explicit team."""
    slug = _get_team_slug(team_id)
    aweb_db = db.get_manager("aweb")
    unclaimed_filter = "AND t.assignee_alias IS NULL" if unclaimed else ""

    rows = await aweb_db.fetch_all(
        f"""
        SELECT t.task_id, t.task_number, t.task_ref_suffix, t.title, t.status, t.priority, t.task_type,
               t.assignee_alias, t.created_by_alias, t.parent_task_id, t.labels,
               t.created_at, t.updated_at
        FROM {{{{tables.tasks}}}} t
        WHERE t.team_id = $1
          AND t.status = 'open'
          AND t.deleted_at IS NULL
          {unclaimed_filter}
          AND NOT EXISTS (
              SELECT 1 FROM {{{{tables.task_dependencies}}}} d
              JOIN {{{{tables.tasks}}}} blocker ON blocker.task_id = d.depends_on_id
              WHERE d.task_id = t.task_id
                AND blocker.status != 'closed'
                AND blocker.deleted_at IS NULL
          )
        ORDER BY t.priority ASC, t.task_number ASC
        """,
        team_id,
    )
    return [
        {
            "task_id": str(r["task_id"]),
            "task_ref": format_task_ref(
                team_slug=slug, task_ref_suffix=r["task_ref_suffix"]
            ),
            "task_number": r["task_number"],
            "title": r["title"],
            "status": r["status"],
            "priority": r["priority"],
            "task_type": r["task_type"],
            "assignee_alias": r["assignee_alias"],
            "created_by_alias": r["created_by_alias"],
            "parent_task_id": str(r["parent_task_id"]) if r["parent_task_id"] else None,
            "labels": list(r["labels"]) if r["labels"] else [],
            "created_at": r["created_at"].isoformat(),
            "updated_at": r["updated_at"].isoformat() if r.get("updated_at") else None,
        }
        for r in rows
    ]


async def list_blocked_tasks(db, *, team_id: str) -> list[dict[str, Any]]:
    """Read tasks blocked by dependencies within the explicit team."""
    slug = _get_team_slug(team_id)
    aweb_db = db.get_manager("aweb")

    rows = await aweb_db.fetch_all(
        """
        SELECT t.task_id, t.task_number, t.task_ref_suffix, t.title, t.status, t.priority, t.task_type,
               t.assignee_alias, t.created_by_alias, t.parent_task_id, t.labels,
               t.created_at, t.updated_at
        FROM {{tables.tasks}} t
        WHERE t.team_id = $1
          AND t.status IN ('open', 'in_progress')
          AND t.deleted_at IS NULL
          AND EXISTS (
              SELECT 1 FROM {{tables.task_dependencies}} d
              JOIN {{tables.tasks}} blocker ON blocker.task_id = d.depends_on_id
              WHERE d.task_id = t.task_id
                AND blocker.status != 'closed'
                AND blocker.deleted_at IS NULL
          )
        ORDER BY t.priority ASC, t.task_number ASC
        """,
        team_id,
    )
    return [
        {
            "task_id": str(r["task_id"]),
            "task_ref": format_task_ref(
                team_slug=slug, task_ref_suffix=r["task_ref_suffix"]
            ),
            "task_number": r["task_number"],
            "title": r["title"],
            "status": r["status"],
            "priority": r["priority"],
            "task_type": r["task_type"],
            "assignee_alias": r["assignee_alias"],
            "created_by_alias": r["created_by_alias"],
            "parent_task_id": str(r["parent_task_id"]) if r["parent_task_id"] else None,
            "labels": list(r["labels"]) if r["labels"] else [],
            "created_at": r["created_at"].isoformat(),
            "updated_at": r["updated_at"].isoformat() if r.get("updated_at") else None,
        }
        for r in rows
    ]


async def update_task(
    db,
    *,
    actor: TeamIdentity,
    on_mutation: MutationCallback | None,
    ref: str,
    title: str | None = None,
    description: str | None = None,
    notes: str | None = None,
    status: str | None = None,
    priority: int | None = None,
    task_type: str | None = None,
    labels: list[str] | None = None,
    assignee_alias: str | None | object = _UNSET,
    parent_task_id: str | None | object = _UNSET,
) -> dict[str, Any]:
    """Apply an authorized task update and publish the resulting committed transitions."""
    team_id = actor.team_id
    actor_alias = actor.alias
    task_id = await resolve_task_ref(db, team_id=team_id, ref=ref)
    slug = _get_team_slug(team_id)
    aweb_db = db.get_manager("aweb")
    now = datetime.now(timezone.utc)
    resolved_assignee_alias: str | None | object = _UNSET
    resolved_parent_task_id: UUID | None | object = _UNSET
    claim_workspace_id = None
    released_claim_workspace_ids: list[str] = []

    if parent_task_id is not _UNSET:
        if parent_task_id:
            try:
                resolved_parent_task_id = await resolve_task_ref(
                    db,
                    team_id=team_id,
                    ref=str(parent_task_id),
                )
            except NotFoundError as exc:
                raise ValidationError("Parent task not found in this team") from exc
        else:
            resolved_parent_task_id = None

    async with aweb_db.transaction() as tx:
        if resolved_parent_task_id is not _UNSET or status == "closed":
            # Keep the subtree stable while locking it, and serialize cycle checks.
            await _lock_task_hierarchy_on(tx, team_id=team_id)

        # Every task row this mutation may touch is locked before its first
        # workspace lock. In particular, a child writer can finish even when
        # it shares the parent's claimant workspace.
        parent_id = (
            resolved_parent_task_id if isinstance(resolved_parent_task_id, UUID) else None
        )
        locked_tasks = await tx.fetch_all(
            """
            WITH RECURSIVE subtree AS (
                SELECT task_id FROM {{tables.tasks}}
                WHERE task_id = $1 AND team_id = $2 AND deleted_at IS NULL
                UNION
                SELECT t.task_id FROM {{tables.tasks}} t
                JOIN subtree s ON t.parent_task_id = s.task_id
                WHERE $3 AND t.team_id = $2 AND t.deleted_at IS NULL
            )
            SELECT task_id, status, assignee_alias, task_ref_suffix, assignee_did,
                   app_request, parent_task_id, title
            FROM {{tables.tasks}}
            WHERE team_id = $2 AND deleted_at IS NULL
              AND (task_id IN (SELECT task_id FROM subtree) OR task_id = $4)
            ORDER BY task_id FOR UPDATE
            """,
            task_id,
            team_id,
            status == "closed",
            parent_id,
        )
        current = next((row for row in locked_tasks if row["task_id"] == task_id), None)
        if current is None:
            raise NotFoundError("Task not found")
        if parent_id is not None and not any(
            row["task_id"] == parent_id for row in locked_tasks
        ):
            raise ValidationError("Parent task not found in this team")

        descendants_to_close = []
        if status == "closed":
            open_children: dict[UUID | None, list[Any]] = {}
            for row in locked_tasks:
                if row["task_id"] != task_id and row["status"] != "closed":
                    open_children.setdefault(row["parent_task_id"], []).append(row)
            descendants_to_close.extend(open_children.get(task_id, []))
            for row in descendants_to_close:
                descendants_to_close.extend(open_children.get(row["task_id"], []))
        current_ref = format_task_ref(
            team_slug=slug, task_ref_suffix=current["task_ref_suffix"]
        )
        auto_closed = [
            {
                "task_id": str(row["task_id"]),
                "task_ref": format_task_ref(
                    team_slug=slug, task_ref_suffix=row["task_ref_suffix"]
                ),
                "title": row["title"],
            }
            for row in descendants_to_close
        ]

        sets: list[str] = ["updated_at = $2"]
        params: list[Any] = [task_id, now]
        idx = 3

        if title is not None:
            sets.append(f"title = ${idx}")
            params.append(title)
            idx += 1
        if description is not None:
            sets.append(f"description = ${idx}")
            params.append(description)
            idx += 1
        if notes is not None:
            sets.append(f"notes = ${idx}")
            params.append(notes)
            idx += 1
        if priority is not None:
            sets.append(f"priority = ${idx}")
            params.append(priority)
            idx += 1
        if task_type is not None:
            sets.append(f"task_type = ${idx}")
            params.append(task_type)
            idx += 1
        if labels is not None:
            sets.append(f"labels = ${idx}")
            params.append(labels)
            idx += 1
        if resolved_parent_task_id is not _UNSET:
            if resolved_parent_task_id is not None:
                if resolved_parent_task_id == task_id:
                    raise ValidationError("Parent relationship would create a cycle")
                cycle = await tx.fetch_one(
                    """
                    WITH RECURSIVE descendants AS (
                        SELECT task_id
                        FROM {{tables.tasks}}
                        WHERE parent_task_id = $1 AND team_id = $2 AND deleted_at IS NULL
                        UNION ALL
                        SELECT t.task_id
                        FROM {{tables.tasks}} t
                        JOIN descendants d ON t.parent_task_id = d.task_id
                        WHERE t.team_id = $2 AND t.deleted_at IS NULL
                    )
                    SELECT 1 FROM descendants WHERE task_id = $3
                    """,
                    task_id,
                    team_id,
                    resolved_parent_task_id,
                )
                if cycle:
                    raise ValidationError("Parent relationship would create a cycle")
            if status == "in_progress":
                # Claim apex resolution below must observe a parent changed by
                # the same request; the transaction rolls this back on error.
                await tx.execute(
                    "UPDATE {{tables.tasks}} SET parent_task_id = $2 WHERE task_id = $1",
                    task_id,
                    resolved_parent_task_id,
                )
            else:
                sets.append(f"parent_task_id = ${idx}")
                params.append(resolved_parent_task_id)
                idx += 1

        if status == "in_progress":
            claim_workspace_id = await acquire_task_claim_on(
                tx,
                team_id=team_id,
                actor_agent_id=actor.agent_id,
                task_ref=current_ref,
                now=now,
                released_workspace_ids=released_claim_workspace_ids,
            )
        elif status is not None:
            await lock_task_claim_workspaces_on(
                tx,
                team_id=team_id,
                task_refs=[current_ref, *(row["task_ref"] for row in auto_closed)],
            )

        if assignee_alias is not _UNSET:
            resolved_assignee_alias, resolved_assignee_did = (
                await _resolve_assignee_on(
                    tx, team_id=team_id, assignee_ref=str(assignee_alias)
                )
                if assignee_alias
                else (None, None)
            )
            if status != "in_progress":
                if (
                    current["app_request"] is not None
                    and resolved_assignee_did != current["assignee_did"]
                ):
                    raise ForbiddenError("target_mismatch")
                sets.append(f"assignee_alias = ${idx}")
                params.append(resolved_assignee_alias)
                idx += 1
                sets.append(f"assignee_did = ${idx}")
                params.append(resolved_assignee_did)
                idx += 1

        descendant_claim_releases: list[list[str]] = []
        if status is not None:
            if status == "in_progress":
                claimant = await _read_claimant_principal_on(
                    tx, team_id=team_id, alias=actor_alias
                )

                sets.append(f"assignee_alias = ${idx}")
                params.append(actor_alias)
                idx += 1
                if current["app_request"] is not None and (
                    not claimant or claimant["principal_did"] != current["assignee_did"]
                ):
                    raise ForbiddenError("target_mismatch")
                sets.append(f"assignee_did = ${idx}")
                params.append(claimant["principal_did"] if claimant else None)
                idx += 1
                sets.append("picked_up = TRUE")

            sets.append(f"status = ${idx}")
            params.append(status)
            idx += 1

            if status == "closed":
                sets.append(f"closed_by_alias = ${idx}")
                params.append(actor_alias)
                idx += 1
                sets.append(f"closed_at = ${idx}")
                params.append(now)
                idx += 1

                if descendants_to_close:
                    await tx.execute(
                        """
                        UPDATE {{tables.tasks}}
                        SET status = 'closed', closed_by_alias = $2, closed_at = $3, updated_at = $3
                        WHERE task_id = ANY($1::uuid[])
                        """,
                        [row["task_id"] for row in descendants_to_close],
                        actor_alias,
                        now,
                    )
        written = await tx.fetch_one(
            f"""UPDATE {{{{tables.tasks}}}} SET {", ".join(sets)} WHERE task_id = $1
                RETURNING task_id, task_ref_suffix, title, status, assignee_alias, parent_task_id""",
            *params,
        )
        if written is None:
            raise NotFoundError("Task not found")

        # A status change to anything but in_progress ends every claim on the
        # task, in this transaction. The release follows the status write
        # because a released workspace keeps its focus only on an open task.
        for row in auto_closed:
            descendant_claim_releases.append(
                await release_task_claims_on(tx, team_id=team_id, task_ref=row["task_ref"])
            )
        if (
            status is not None
            and status != current["status"]
            and status != "in_progress"
        ):
            released_claim_workspace_ids = await release_task_claims_on(
                tx,
                team_id=team_id,
                task_ref=current_ref,
            )

    # RETURNING freezes exactly what this transaction committed. A later writer
    # may change or delete the response projection; it cannot replace these
    # facts or suppress the callbacks for the completed mutation.
    written_task_id = str(written["task_id"])
    written_ref = format_task_ref(
        team_slug=slug, task_ref_suffix=written["task_ref_suffix"]
    )
    new_assignee = written["assignee_alias"]
    old_status = current["status"]
    status_changed = status is not None and status != old_status
    if status_changed or released_claim_workspace_ids:
        context_type = TaskStatusChangedContext if status_changed else TaskClaimReplacedContext
        await fire_mutation_callback(
            on_mutation,
            context_type.event_type.value,
            context_type(
                task_id=written_task_id,
                team_id=team_id,
                task_ref=written_ref,
                title=written["title"],
                old_status=old_status,
                new_status=written["status"],
                assignee_alias=new_assignee,
                parent_task_id=str(written["parent_task_id"])
                if written["parent_task_id"] is not None
                else None,
                actor_agent_id=actor.agent_id,
                actor_alias=actor.alias,
                actor_did_aw=actor.did_aw,
                claim_preacquired=claim_workspace_id is not None,
                actor_workspace_id=str(claim_workspace_id)
                if claim_workspace_id is not None
                else "",
                released_claim_workspace_ids=released_claim_workspace_ids,
            ).to_context(),
        )
    else:
        await fire_mutation_callback(
            on_mutation,
            MutationEventType.TASK_UPDATED.value,
            TaskUpdatedContext(
                task_id=written_task_id,
                task_ref=written_ref,
                actor_agent_id=actor.agent_id,
                actor_did_aw=actor.did_aw,
            ).to_context(),
        )
    if new_assignee != current["assignee_alias"]:
        await fire_mutation_callback(
            on_mutation,
            MutationEventType.TASK_ASSIGNEE_CHANGED.value,
            TaskAssigneeChangedContext(
                task_id=written_task_id,
                team_id=team_id,
                task_ref=written_ref,
                title=written["title"],
                actor_agent_id=actor.agent_id,
                actor_alias=actor.alias,
                actor_did_aw=actor.did_aw,
                old_assignee_alias=current["assignee_alias"],
                assignee_alias=new_assignee,
            ).to_context(),
        )
    for row, closed, released in zip(
        descendants_to_close, auto_closed, descendant_claim_releases, strict=True
    ):
        await fire_mutation_callback(
            on_mutation,
            MutationEventType.TASK_STATUS_CHANGED.value,
            TaskStatusChangedContext(
                task_id=closed["task_id"],
                team_id=team_id,
                task_ref=closed["task_ref"],
                title=closed["title"],
                old_status=row["status"],
                new_status="closed",
                assignee_alias=row["assignee_alias"],
                parent_task_id=str(row["parent_task_id"]),
                actor_agent_id=actor.agent_id,
                actor_alias=actor.alias,
                actor_did_aw=actor.did_aw,
                released_claim_workspace_ids=released,
            ).to_context(),
        )
    result = await get_task(db, team_id=team_id, ref=str(task_id))
    if auto_closed:
        result["auto_closed"] = auto_closed
    return result


async def soft_delete_task(
    db,
    *,
    actor: TeamIdentity,
    on_mutation: MutationCallback | None,
    ref: str,
) -> dict[str, Any]:
    """Commit deletion and claim release together, then announce the release."""
    team_id = actor.team_id
    task_id = await resolve_task_ref(
        db,
        team_id=team_id,
        ref=ref,
        visibility=TaskVisibility.INCLUDING_DELETED,
    )
    aweb_db = db.get_manager("aweb")
    now = datetime.now(timezone.utc)
    async with aweb_db.transaction() as tx:
        row = await tx.fetch_one(
            """SELECT task_id, task_ref_suffix, title, deleted_at FROM {{tables.tasks}}
               WHERE task_id=$1 AND team_id=$2 FOR UPDATE""",
            task_id,
            team_id,
        )
        if not row:
            raise NotFoundError("Task not found")
        task_ref = format_task_ref(
            team_slug=_get_team_slug(team_id), task_ref_suffix=row["task_ref_suffix"]
        )
        if row["deleted_at"] is None:
            await tx.execute(
                "UPDATE {{tables.tasks}} SET deleted_at=$2, updated_at=$2 WHERE task_id=$1",
                task_id,
                now,
            )
        # Also reconcile any claim retained by an older server's delete path.
        released_claim_workspace_ids = await release_task_claims_on(
            tx, team_id=team_id, task_ref=task_ref
        )
    result = {
        "status": "deleted",
        "task_id": str(task_id),
        "task_ref": task_ref,
    }
    outcome = await fire_mutation_callback(
        on_mutation,
        MutationEventType.TASK_DELETED.value,
        TaskDeletedContext(
            task_id=result["task_id"],
            team_id=team_id,
            task_ref=result["task_ref"],
            title=row["title"],
            actor_agent_id=actor.agent_id,
            actor_did_aw=actor.did_aw,
            released_claim_workspace_ids=released_claim_workspace_ids,
        ).to_context(),
    )
    if outcome.status is MutationDeliveryStatus.DEFERRED:
        return {**result, "notification_status": MutationDeliveryStatus.DEFERRED.value}
    if outcome.status is MutationDeliveryStatus.FAILED:
        raise TaskDeletionIncompleteError(
            {
                **result,
                "code": "task_deleted_notification_failed",
                "remaining_claims": 0,
                "message": "Task deletion and claim cleanup committed; mutation notification failed. Inspect the serving callback logs.",
                "failed_stages": [stage.value for stage in outcome.failed_stages],
            }
        )
    return result


async def add_dependency(
    db,
    *,
    actor: TeamIdentity,
    on_mutation: MutationCallback | None,
    task_ref: str,
    depends_on_ref: str,
) -> dict[str, Any]:
    """Add a team-local dependency after checking that it introduces no cycle."""
    team_id = actor.team_id
    task_id = await resolve_task_ref(db, team_id=team_id, ref=task_ref)
    depends_on_id = await resolve_task_ref(db, team_id=team_id, ref=depends_on_ref)
    if task_id == depends_on_id:
        raise ValidationError("A task cannot depend on itself")

    aweb_db = db.get_manager("aweb")
    cycle_row = await aweb_db.fetch_one(
        """
        WITH RECURSIVE reach AS (
            SELECT depends_on_id AS id
            FROM {{tables.task_dependencies}}
            WHERE task_id = $2
            UNION ALL
            SELECT d.depends_on_id
            FROM {{tables.task_dependencies}} d
            JOIN reach r ON d.task_id = r.id
        )
        SELECT 1 FROM reach WHERE id = $1
        """,
        task_id,
        depends_on_id,
    )
    if cycle_row:
        raise ValidationError("Dependency would create a cycle")

    try:
        await aweb_db.execute(
            """
            INSERT INTO {{tables.task_dependencies}} (task_id, depends_on_id, team_id)
            VALUES ($1, $2, $3)
            """,
            task_id,
            depends_on_id,
            team_id,
        )
    except Exception as exc:
        if "duplicate key" not in str(exc).lower():
            raise

    await fire_mutation_callback(
        on_mutation,
        MutationEventType.TASK_DEPENDENCY_ADDED.value,
        TaskDependencyAddedContext(
            task_id=str(task_id),
            depends_on_task_id=str(depends_on_id),
            actor_agent_id=actor.agent_id,
            actor_did_aw=actor.did_aw,
        ).to_context(),
    )
    return {"task_id": str(task_id), "depends_on_id": str(depends_on_id)}


async def remove_dependency(
    db,
    *,
    actor: TeamIdentity,
    on_mutation: MutationCallback | None,
    task_ref: str,
    dep_ref: str,
) -> dict[str, Any]:
    """Remove a team-local dependency and publish the resulting mutation."""
    team_id = actor.team_id
    task_id = await resolve_task_ref(db, team_id=team_id, ref=task_ref)
    dep_id = await resolve_task_ref(db, team_id=team_id, ref=dep_ref)
    aweb_db = db.get_manager("aweb")
    await aweb_db.execute(
        "DELETE FROM {{tables.task_dependencies}} WHERE task_id = $1 AND depends_on_id = $2",
        task_id,
        dep_id,
    )
    await fire_mutation_callback(
        on_mutation,
        MutationEventType.TASK_DEPENDENCY_REMOVED.value,
        TaskDependencyRemovedContext(
            task_id=str(task_id),
            removed_depends_on_task_id=str(dep_id),
            actor_agent_id=actor.agent_id,
            actor_did_aw=actor.did_aw,
        ).to_context(),
    )
    return {"task_id": str(task_id), "removed_depends_on_id": str(dep_id)}


async def add_comment(
    db,
    *,
    actor: TeamIdentity,
    on_mutation: MutationCallback | None,
    ref: str,
    body: str,
) -> dict[str, Any]:
    """Append an attributed task comment and publish its committed mutation."""
    team_id = actor.team_id
    author_alias = actor.alias
    task_id = await resolve_task_ref(db, team_id=team_id, ref=ref)
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.task_comments}} (task_id, team_id, author_alias, body)
        VALUES ($1, $2, $3, $4)
        RETURNING comment_id, created_at
        """,
        task_id,
        team_id,
        author_alias,
        body,
    )
    result = {
        "comment_id": str(row["comment_id"]),
        "task_id": str(task_id),
        "author_alias": author_alias,
        "body": body,
        "created_at": row["created_at"].isoformat(),
    }
    await fire_mutation_callback(
        on_mutation,
        MutationEventType.TASK_COMMENT_ADDED.value,
        TaskCommentAddedContext(
            task_id=result["task_id"],
            comment_id=result["comment_id"],
            actor_agent_id=actor.agent_id,
            actor_did_aw=actor.did_aw,
        ).to_context(),
    )
    return result


async def list_comments(db, *, team_id: str, ref: str) -> list[dict[str, Any]]:
    """Read the attributed comments of a task in the explicit team scope."""
    task_id = await resolve_task_ref(db, team_id=team_id, ref=ref)
    aweb_db = db.get_manager("aweb")
    rows = await aweb_db.fetch_all(
        """
        SELECT comment_id, task_id, author_alias, body, created_at
        FROM {{tables.task_comments}}
        WHERE task_id = $1
        ORDER BY created_at ASC
        """,
        task_id,
    )
    return [
        {
            "comment_id": str(r["comment_id"]),
            "task_id": str(r["task_id"]),
            "author_alias": r["author_alias"],
            "body": r["body"],
            "created_at": r["created_at"].isoformat(),
        }
        for r in rows
    ]
