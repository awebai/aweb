from __future__ import annotations

import logging
import re
import hashlib
import json
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from awid.team_ids import team_slug
from ..claims import claim_focus_task_ref, resolve_task_claim_apex_on
from ..service_errors import ConflictError, ForbiddenError, NotFoundError, ValidationError
from ..team_auth_deps import TeamIdentity

logger = logging.getLogger(__name__)

_UNSET = object()


def answer_comment_projection(*, body_md: str, answer_sha256: str) -> str:
    """Juan's C2 ruling: every task answer preserves its exact text."""
    if (isinstance(body_md, str) and 1 <= len(body_md) <= 20000
            and hashlib.sha256(body_md.encode("utf-8")).hexdigest() == answer_sha256):
        return body_md
    raise ValidationError("schema_invalid")


def _answer_receipt(row, *, current_question_rev: int, cancelled: bool = False) -> dict[str, Any]:
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
        "answered_by": {"principal_did": row["answered_by_did"], "certificate_id": row["certificate_id"]},
        "answered_at": row["answered_at"].astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "current": row["question_rev"] == current_question_rev and not cancelled,
    }


def _task_request_metadata(value):
    return json.loads(value) if isinstance(value, str) else value or {}


def _eligible_task_condition(index: int) -> str:
    # Absence/null retains single-assignee authority for ordinary/intent tasks.
    # A present array is authoritative, including an empty array (fail closed).
    return (f"((jsonb_typeof(app_request->'eligible_dids') = 'array' AND (app_request->'eligible_dids') ? ${index}) OR "
            f"((app_request->'eligible_dids' IS NULL OR app_request->'eligible_dids' = 'null'::jsonb) "
            f"AND assignee_did = ${index}))")


def _task_list_contract(row):
    return {"assignee_did": row["assignee_did"], "app_request": _task_request_metadata(row["app_request"]) or None,
            "rev": row["rev"], "question_rev": row["question_rev"]}


async def get_task_answer_on(tx, *, team_id: str, task_id: UUID, answer_key: str) -> dict[str, Any]:
    """Read an immutable receipt inside the caller's authorization transaction.

    The caller enforces member or installation receipt-read authority first.
    Holding the task row stable makes `current` consistent with this read.
    """
    task = await tx.fetch_one(
        """SELECT question_rev, cancellation FROM {{tables.tasks}}
           WHERE task_id = $1 AND team_id = $2 AND deleted_at IS NULL FOR SHARE""",
        task_id, team_id,
    )
    if not task:
        raise NotFoundError("Task not found")
    row = await tx.fetch_one(
        "SELECT * FROM {{tables.task_answers}} WHERE task_id = $1 AND answer_key = $2",
        task_id, answer_key,
    )
    if not row:
        raise NotFoundError("Answer not found")
    return _answer_receipt(row, current_question_rev=task["question_rev"], cancelled=task["cancellation"] is not None)


async def answer_task_on(
    tx, *, team_id: str, task_id: UUID, actor: TeamIdentity,
    expected_task_rev: int, answer_key: str, answer_sha256: str,
    body_md: str, choice: str | None = None, proposal_rev: int | None = None,
    proposal_sha256: str | None = None, outcome: dict | None = None,
) -> dict[str, Any]:
    """Commit an answer using the caller's transaction and verified identity.

    The caller authenticates current certificate authority before entry. The
    local member projection must still match that certificate and principal.
    This function never opens/commits a transaction or delivers external mail.
    """
    if (not isinstance(answer_key, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", answer_key)
            or not isinstance(answer_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", answer_sha256)
            or type(expected_task_rev) is not int or not 1 <= expected_task_rev <= 2**53 - 1
            or (proposal_rev is not None and (type(proposal_rev) is not int or not 0 <= proposal_rev <= 2**53 - 1))
            or (proposal_sha256 is not None and (not isinstance(proposal_sha256, str)
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", proposal_sha256)))):
        raise ValidationError("schema_invalid")
    comment_body = answer_comment_projection(body_md=body_md, answer_sha256=answer_sha256)
    principal = actor.did_aw or actor.did_key
    member = await tx.fetch_one(
        """SELECT COALESCE(NULLIF(did_aw, ''), did_key) AS principal_did, certificate_id
           FROM {{tables.agents}} WHERE agent_id = $1 AND team_id = $2
             AND deleted_at IS NULL AND status = 'active' FOR SHARE""",
        UUID(actor.agent_id), team_id,
    )
    if (actor.team_id != team_id or not member or member["principal_did"] != principal
            or not actor.certificate_id or member["certificate_id"] != actor.certificate_id):
        raise ForbiddenError("target_mismatch")
    task = await tx.fetch_one(
        """SELECT task_id, rev, question_rev, status, assignee_did, app_request, cancellation,
                  task_ref_suffix, title, assignee_alias
           FROM {{tables.tasks}} WHERE task_id = $1 AND team_id = $2
             AND deleted_at IS NULL FOR UPDATE""",
        task_id, team_id,
    )
    if not task:
        raise NotFoundError("Task not found")
    existing = await tx.fetch_one(
        "SELECT * FROM {{tables.task_answers}} WHERE task_id = $1 AND answer_key = $2",
        task_id, answer_key,
    )
    if existing:
        if existing["answered_by_did"] != principal:
            raise ForbiddenError("target_mismatch")
        if any(existing[k] != v for k, v in {
            "answer_sha256": answer_sha256, "choice": choice,
            "proposal_rev": proposal_rev, "proposal_sha256": proposal_sha256,
        }.items()):
            raise ConflictError("idempotency_conflict")
        if outcome is not None:
            outcome["created"] = False
        return _answer_receipt(existing, current_question_rev=task["question_rev"], cancelled=task["cancellation"] is not None)
    metadata = _task_request_metadata(task["app_request"])
    eligible = metadata.get("eligible_dids")
    answerers = [task["assignee_did"]] if eligible is None else eligible
    if not isinstance(answerers, list) or principal not in answerers:
        raise ForbiddenError("target_mismatch")
    if task["rev"] != expected_task_rev or task["status"] != "open" or task["cancellation"] is not None:
        raise ConflictError("revision_conflict")
    if proposal_rev != metadata.get("proposal_rev") or proposal_sha256 != metadata.get("proposal_sha256"):
        raise ConflictError("approval_changed")
    choices = metadata.get("choices")
    if (choices is not None and choice not in choices) or (choices is None and choice is not None):
        raise ValidationError("schema_invalid")
    receipt_id = uuid4()
    if await tx.fetch_value(
        "SELECT 1 FROM {{tables.task_answers}} WHERE task_id = $1 AND question_rev = $2",
        task_id, task["question_rev"],
    ):
        raise ConflictError("revision_conflict")
    comment = await tx.fetch_one(
        """INSERT INTO {{tables.task_comments}} (task_id, team_id, author_alias, body)
           VALUES ($1, $2, $3, $4) RETURNING comment_id""",
        task_id, team_id, actor.alias, comment_body,
    )
    updated = await tx.fetch_one(
        """UPDATE {{tables.tasks}} SET status = 'closed', closed_by_alias = $2,
               closed_by_did = $3, closed_at = NOW(), updated_at = NOW()
           WHERE task_id = $1 RETURNING rev""",
        task_id, actor.alias, principal,
    )
    row = await tx.fetch_one(
        """INSERT INTO {{tables.task_answers}}
               (task_id, question_rev, task_rev, answer_key, answer_sha256, answered_by_did, certificate_id,
                receipt_id, choice, proposal_rev, proposal_sha256)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING *""",
        task_id, task["question_rev"], updated["rev"], answer_key, answer_sha256, principal, actor.certificate_id,
        receipt_id, choice, proposal_rev, proposal_sha256,
    )
    if outcome is not None:
        outcome["created"] = True
        outcome["comment_id"] = str(comment["comment_id"])
        outcome.update(task_ref=format_task_ref(_get_team_slug(team_id), task["task_ref_suffix"]),
                       title=task["title"], assignee_alias=task["assignee_alias"])
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


def format_task_ref(team_slug: str, task_ref_suffix: str) -> str:
    return f"{team_slug}-{task_ref_suffix}"


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


async def allocate_task_number(db, *, team_id: str) -> int:
    aweb_db = db.get_manager("aweb")
    return await _allocate_task_number_on(aweb_db, team_id=team_id)


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


async def resolve_task_ref(db, *, team_id: str, ref: str) -> UUID:
    aweb_db = db.get_manager("aweb")

    try:
        task_uuid = UUID(ref)
    except ValueError:
        task_uuid = None

    if task_uuid is not None:
        row = await aweb_db.fetch_one(
            "SELECT task_id FROM {{tables.tasks}} WHERE task_id = $1 AND team_id = $2 AND deleted_at IS NULL",
            task_uuid,
            team_id,
        )
        if not row:
            await _log_resolution_miss(
                aweb_db, team_id=team_id, ref=ref, ref_suffix="", lookup="task_id", task_uuid=task_uuid
            )
            raise NotFoundError("Task not found")
        return row["task_id"]

    slug = _get_team_slug(team_id)
    prefix = slug + "-"
    ref_suffix = ref[len(prefix) :] if ref.startswith(prefix) else ref
    ref_suffix = ref_suffix.strip()

    if not ref_suffix:
        raise NotFoundError("Task not found")

    row = await aweb_db.fetch_one(
        "SELECT task_id FROM {{tables.tasks}} WHERE team_id = $1 AND task_ref_suffix = $2 AND deleted_at IS NULL",
        team_id,
        ref_suffix,
    )
    if row:
        return row["task_id"]

    await _log_resolution_miss(aweb_db, team_id=team_id, ref=ref, ref_suffix=ref_suffix, lookup="task_ref_suffix")
    raise NotFoundError("Task not found")


async def create_task(
    db,
    *,
    team_id: str,
    created_by_alias: str,
    title: str,
    description: str = "",
    notes: str = "",
    priority: int = 2,
    task_type: str = "task",
    labels: list[str] | None = None,
    parent_task_id: str | None = None,
    assignee_alias: str | None = None,
    created_by_did: str | None = None,
) -> dict[str, Any]:
    slug = _get_team_slug(team_id)
    aweb_db = db.get_manager("aweb")
    resolved_parent_task_id: UUID | None = None
    task_ref_suffix: str | None = None

    async with aweb_db.transaction() as tx:
        if created_by_did is None:
            creator = await tx.fetch_one(
                """SELECT COALESCE(NULLIF(did_aw, ''), did_key) AS principal_did
                   FROM {{tables.agents}} WHERE team_id=$1 AND alias=$2 AND deleted_at IS NULL FOR SHARE""",
                team_id, created_by_alias,
            )
            created_by_did = creator["principal_did"] if creator else None
        assignee_did = None
        if assignee_alias:
            assignee_alias, assignee_did = await _resolve_assignee_on(
                tx, team_id=team_id, assignee_ref=assignee_alias,
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
            task_ref_suffix = f"{parent_row['task_ref_suffix']}.{int(max_sibling_index) + 1}"
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

    return {
        "task_id": str(row["task_id"]),
        "task_ref": format_task_ref(slug, task_ref_suffix),
        "task_number": task_number,
        "team_id": team_id,
        "title": title,
        "description": description,
        "notes": notes,
        "status": "open",
        "priority": priority,
        "task_type": task_type,
        "labels": labels or [],
        "parent_task_id": str(resolved_parent_task_id) if resolved_parent_task_id else None,
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


async def _resolve_assignee_on(manager, *, team_id: str, assignee_ref: str) -> tuple[str, str]:
    """Resolve display alias and immutable principal together, on the write tx."""
    try:
        agent_id = UUID(assignee_ref)
    except ValueError:
        agent_id = None
    row = await manager.fetch_one(
        """
        SELECT alias, COALESCE(NULLIF(did_aw, ''), did_key) AS principal_did
        FROM {{tables.agents}}
        WHERE team_id = $1 AND deleted_at IS NULL
          AND (($2::uuid IS NOT NULL AND agent_id = $2)
               OR ($2::uuid IS NULL AND alias = $3))
        FOR SHARE
        """,
        team_id, agent_id, assignee_ref.strip(),
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
    """Resolve a nondeleted team member, including humans hidden from the roster."""
    aweb_db = db.get_manager("aweb")

    try:
        agent_uuid = UUID(assignee_ref)
        agent_row = await aweb_db.fetch_one(
            "SELECT alias FROM {{tables.agents}} WHERE agent_id = $1 AND team_id = $2 AND deleted_at IS NULL",
            agent_uuid,
            team_id,
        )
        if not agent_row:
            raise ValidationError("Assignee agent not found in this team")
        return agent_row["alias"]
    except ValueError:
        pass

    agent_row = await aweb_db.fetch_one(
        "SELECT alias FROM {{tables.agents}} WHERE alias = $1 AND team_id = $2 AND deleted_at IS NULL",
        assignee_ref.strip(),
        team_id,
    )
    if not agent_row:
        raise ValidationError("Assignee agent not found in this team")
    return agent_row["alias"]


async def get_task(db, *, team_id: str, ref: str) -> dict[str, Any]:
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
            "task_ref": format_task_ref(slug, r["task_ref_suffix"]),
            "title": r["title"],
            "status": r["status"],
        }

    answer = await aweb_db.fetch_one(
        "SELECT * FROM {{tables.task_answers}} WHERE task_id = $1 AND question_rev = $2",
        task_id, row["question_rev"],
    )
    def json_value(value):
        return json.loads(value) if isinstance(value, str) else value

    return {
        "task_id": str(row["task_id"]),
        "task_ref": format_task_ref(slug, row["task_ref_suffix"]),
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
        "answer": _answer_receipt(answer, current_question_rev=row["question_rev"],
                                  cancelled=row["cancellation"] is not None) if answer else None,
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
            db, team_id=team_id, assignee_ref=assignee_alias,
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
            db, team_id=team_id, ref=parent_task_id,
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
        WHERE {' AND '.join(conditions)}
        ORDER BY task_number ASC
        """,
        *params,
    )
    return [
        {
            **_task_list_contract(r),
            "task_id": str(r["task_id"]),
            "task_ref": format_task_ref(slug, r["task_ref_suffix"]),
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
            db, team_id=team_id, assignee_ref=assignee_alias,
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
        WHERE {' AND '.join(conditions)}
        ORDER BY t.created_at DESC, t.task_id DESC
        LIMIT ${idx}
        """,
        *params,
    )
    return [
        {
            **_task_list_contract(r),
            "task_id": str(r["task_id"]),
            "task_ref": format_task_ref(slug, r["task_ref_suffix"]),
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


async def list_active_work(db, *, team_id: str) -> list[dict[str, Any]]:
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

    task_refs = {format_task_ref(slug, row["task_ref_suffix"]) for row in task_rows}

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
        task_ref = format_task_ref(slug, row["task_ref_suffix"])
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
            SELECT w.workspace_id, w.alias, w.last_seen_at, r.canonical_origin
            FROM {{{{tables.workspaces}}}} w
            LEFT JOIN {{{{tables.repos}}}} r ON w.repo_id = r.id AND r.deleted_at IS NULL
            WHERE w.team_id = $1
              AND w.deleted_at IS NULL
              AND w.workspace_id IN ({", ".join(workspace_placeholders)})
            """,
            *workspace_params,
        )
        workspace_meta_by_id = {
            str(row["workspace_id"]): {
                "alias": row["alias"],
                "last_seen_at": row["last_seen_at"].isoformat() if row["last_seen_at"] else None,
                "canonical_origin": row["canonical_origin"],
            }
            for row in workspace_rows
        }

    items: list[dict[str, Any]] = []
    for row in task_rows:
        task_ref = format_task_ref(slug, row["task_ref_suffix"])
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
                "parent_task_id": str(row["parent_task_id"]) if row["parent_task_id"] else None,
                "labels": list(row["labels"]) if row["labels"] else [],
                "created_at": row["created_at"].isoformat(),
                "updated_at": row["updated_at"].isoformat() if row.get("updated_at") else None,
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


async def list_ready_tasks(db, *, team_id: str, unclaimed: bool = False) -> list[dict[str, Any]]:
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
            "task_ref": format_task_ref(slug, r["task_ref_suffix"]),
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
            "task_ref": format_task_ref(slug, r["task_ref_suffix"]),
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
    team_id: str,
    ref: str,
    actor_alias: str,
    title: str | None = None,
    description: str | None = None,
    notes: str | None = None,
    status: str | None = None,
    priority: int | None = None,
    task_type: str | None = None,
    labels: list[str] | None = None,
    assignee_alias: str | None | object = _UNSET,
    parent_task_id: str | None | object = _UNSET,
    assignment_change: dict[str, Any] | None = None,
) -> dict[str, Any]:
    task_id = await resolve_task_ref(db, team_id=team_id, ref=ref)
    slug = _get_team_slug(team_id)
    aweb_db = db.get_manager("aweb")
    now = datetime.now(timezone.utc)
    resolved_assignee_alias: str | None | object = _UNSET
    resolved_parent_task_id: UUID | None | object = _UNSET
    claim_preacquired = False

    if parent_task_id is not _UNSET:
        if parent_task_id:
            try:
                resolved_parent_task_id = await resolve_task_ref(
                    db, team_id=team_id, ref=str(parent_task_id),
                )
            except NotFoundError as exc:
                raise ValidationError("Parent task not found in this team") from exc
        else:
            resolved_parent_task_id = None

    async with aweb_db.transaction() as tx:
        if resolved_parent_task_id is not _UNSET:
            # Parent mutations form one integrity domain per team. Serialize
            # check-and-write so concurrent valid snapshots cannot commit a cycle.
            await tx.fetch_value(
                "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                f"task-parent-hierarchy:{team_id}",
            )

        current = await tx.fetch_one(
            """
            SELECT task_id, status, assignee_alias, task_ref_suffix, assignee_did, app_request
            FROM {{tables.tasks}}
            WHERE task_id = $1 AND deleted_at IS NULL
            FOR UPDATE
            """,
            task_id,
        )
        if not current:
            raise NotFoundError("Task not found")

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

        if assignee_alias is not _UNSET:
            resolved_assignee_alias, resolved_assignee_did = (
                await _resolve_assignee_on(tx, team_id=team_id, assignee_ref=str(assignee_alias))
                if assignee_alias else (None, None)
            )
            if status != "in_progress":
                if current["app_request"] is not None and resolved_assignee_did != current["assignee_did"]:
                    raise ForbiddenError("target_mismatch")
                sets.append(f"assignee_alias = ${idx}")
                params.append(resolved_assignee_alias)
                idx += 1
                sets.append(f"assignee_did = ${idx}")
                params.append(resolved_assignee_did)
                idx += 1

        auto_closed: list[dict[str, Any]] = []
        if status is not None:
            if status == "in_progress":
                task_ref = format_task_ref(slug, current["task_ref_suffix"])
                apex_task_ref = await resolve_task_claim_apex_on(tx, team_id, task_ref)
                workspace = await tx.fetch_one(
                    """
                    SELECT workspace_id, alias, human_name
                    FROM {{tables.workspaces}}
                    WHERE alias = $1 AND team_id = $2 AND deleted_at IS NULL
                    """,
                    actor_alias,
                    team_id,
                )
                if workspace is not None:
                    conflicting_claim = await tx.fetch_one(
                        """
                        SELECT workspace_id, alias
                        FROM {{tables.task_claims}}
                        WHERE team_id = $1 AND task_ref = $2 AND workspace_id != $3
                        LIMIT 1
                        """,
                        team_id,
                        task_ref,
                        workspace["workspace_id"],
                    )
                    if conflicting_claim:
                        raise ConflictError("Task is already in progress by another agent")

                    await tx.execute(
                        """
                        INSERT INTO {{tables.task_claims}} (
                            team_id, workspace_id, alias, human_name, task_ref,
                            apex_task_ref, claimed_at
                        )
                        VALUES ($1, $2, $3, $4, $5, $6, $7)
                        ON CONFLICT (team_id, task_ref, workspace_id)
                        DO UPDATE SET
                            alias = EXCLUDED.alias,
                            human_name = EXCLUDED.human_name,
                            apex_task_ref = EXCLUDED.apex_task_ref,
                            claimed_at = EXCLUDED.claimed_at
                        """,
                        team_id,
                        workspace["workspace_id"],
                        workspace["alias"],
                        workspace["human_name"] or "",
                        task_ref,
                        apex_task_ref,
                        now,
                    )

                    await tx.execute(
                        """
                        UPDATE {{tables.workspaces}}
                        SET focus_task_ref = $1,
                            focus_updated_at = $2,
                            updated_at = $2
                        WHERE team_id = $3 AND workspace_id = $4
                        """,
                        claim_focus_task_ref(task_ref, apex_task_ref),
                        now,
                        team_id,
                        workspace["workspace_id"],
                    )
                    claim_preacquired = True

                sets.append(f"assignee_alias = ${idx}")
                params.append(actor_alias)
                idx += 1
                actor = await tx.fetch_one(
                    """SELECT COALESCE(NULLIF(did_aw, ''), did_key) AS principal_did
                       FROM {{tables.agents}}
                       WHERE team_id = $1 AND alias = $2 AND deleted_at IS NULL
                       FOR SHARE""",
                    team_id, actor_alias,
                )
                if current["app_request"] is not None and (not actor or actor["principal_did"] != current["assignee_did"]):
                    raise ForbiddenError("target_mismatch")
                sets.append(f"assignee_did = ${idx}")
                params.append(actor["principal_did"] if actor else None)
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

                descendant_rows = await tx.fetch_all(
                    """
                    WITH RECURSIVE descendants AS (
                        SELECT task_id FROM {{tables.tasks}}
                        WHERE parent_task_id = $1 AND deleted_at IS NULL AND status != 'closed'
                        UNION ALL
                        SELECT t.task_id FROM {{tables.tasks}} t
                        JOIN descendants d ON t.parent_task_id = d.task_id
                        WHERE t.deleted_at IS NULL AND t.status != 'closed'
                    )
                    SELECT task_id FROM descendants
                    """,
                    task_id,
                )

                if descendant_rows:
                    desc_ids = [r["task_id"] for r in descendant_rows]
                    await tx.execute(
                        """
                        UPDATE {{tables.tasks}}
                        SET status = 'closed', closed_by_alias = $2, closed_at = $3, updated_at = $3
                        WHERE task_id = ANY($1::uuid[])
                        """,
                        desc_ids,
                        actor_alias,
                        now,
                    )
                    closed_rows = await tx.fetch_all(
                        "SELECT task_id, task_number, task_ref_suffix, title FROM {{tables.tasks}} WHERE task_id = ANY($1::uuid[])",
                        desc_ids,
                    )
                    for cr in closed_rows:
                        auto_closed.append(
                            {
                                "task_id": str(cr["task_id"]),
                                "task_ref": format_task_ref(slug, cr["task_ref_suffix"]),
                                "title": cr["title"],
                            }
                        )

        await tx.execute(
            f"UPDATE {{{{tables.tasks}}}} SET {', '.join(sets)} WHERE task_id = $1",
            *params,
        )

    # Capture the actual write, including implicit claim assignment, from the
    # locked row and resolved input. A post-commit read may see a later writer.
    # Keep this hook metadata out of the public task response and MCP results.
    new_assignee = (
        actor_alias if status == "in_progress"
        else resolved_assignee_alias if resolved_assignee_alias is not _UNSET
        else current["assignee_alias"]
    )
    if assignment_change is not None and new_assignee != current["assignee_alias"]:
        assignment_change.update(
            old_assignee_alias=current["assignee_alias"],
            assignee_alias=new_assignee,
        )
    old_status = current["status"]
    result = await get_task(db, team_id=team_id, ref=str(task_id))
    if auto_closed:
        result["auto_closed"] = auto_closed
    if status is not None and status != old_status:
        result["old_status"] = old_status
    if claim_preacquired:
        result["claim_preacquired"] = True
    return result


async def soft_delete_task(db, *, team_id: str, ref: str) -> dict[str, Any]:
    task_id = await resolve_task_ref(db, team_id=team_id, ref=ref)
    slug = _get_team_slug(team_id)
    aweb_db = db.get_manager("aweb")
    now = datetime.now(timezone.utc)

    async with aweb_db.transaction() as tx:
        row = await tx.fetch_one(
            """
            UPDATE {{tables.tasks}} SET deleted_at = $2, updated_at = $2
            WHERE task_id = $1 AND deleted_at IS NULL
            RETURNING task_id, task_ref_suffix
            """,
            task_id,
            now,
        )
        if not row:
            raise NotFoundError("Task not found")

    return {"status": "deleted", "task_id": str(task_id), "task_ref": format_task_ref(slug, row["task_ref_suffix"])}


async def add_dependency(db, *, team_id: str, task_ref: str, depends_on_ref: str) -> dict[str, Any]:
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

    return {"task_id": str(task_id), "depends_on_id": str(depends_on_id)}


async def remove_dependency(db, *, team_id: str, task_ref: str, dep_ref: str) -> dict[str, Any]:
    task_id = await resolve_task_ref(db, team_id=team_id, ref=task_ref)
    dep_id = await resolve_task_ref(db, team_id=team_id, ref=dep_ref)
    aweb_db = db.get_manager("aweb")
    await aweb_db.execute(
        "DELETE FROM {{tables.task_dependencies}} WHERE task_id = $1 AND depends_on_id = $2",
        task_id,
        dep_id,
    )
    return {"task_id": str(task_id), "removed_depends_on_id": str(dep_id)}


async def add_comment(db, *, team_id: str, ref: str, author_alias: str, body: str) -> dict[str, Any]:
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
    return {
        "comment_id": str(row["comment_id"]),
        "task_id": str(task_id),
        "author_alias": author_alias,
        "body": body,
        "created_at": row["created_at"].isoformat(),
    }


async def list_comments(db, *, team_id: str, ref: str) -> list[dict[str, Any]]:
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
