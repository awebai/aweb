from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from aweb.service_errors import ConflictError, NotFoundError, ValidationError

_UNSET = object()


def format_task_ref(project_slug: str, task_number: int) -> str:
    return f"{project_slug}-{task_number:03d}"


async def _get_project_slug(db, *, project_id: str) -> str:
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        "SELECT slug FROM {{tables.projects}} WHERE project_id = $1 AND deleted_at IS NULL",
        UUID(project_id),
    )
    if not row:
        raise NotFoundError("Project not found")
    return row["slug"]


async def allocate_task_number(db, *, project_id: str) -> int:
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.task_counters}} (project_id, next_number)
        VALUES ($1, 2)
        ON CONFLICT (project_id) DO UPDATE SET next_number = {{tables.task_counters}}.next_number + 1
        RETURNING next_number - 1 AS task_number
        """,
        UUID(project_id),
    )
    return row["task_number"]


async def resolve_task_ref(db, *, project_id: str, ref: str) -> UUID:
    """Resolve a task reference (UUID, integer, or slug-NNN) to a task_id UUID."""
    aweb_db = db.get_manager("aweb")

    # Try UUID
    try:
        task_uuid = UUID(ref)
        row = await aweb_db.fetch_one(
            "SELECT task_id FROM {{tables.tasks}} WHERE task_id = $1 AND project_id = $2 AND deleted_at IS NULL",
            task_uuid,
            UUID(project_id),
        )
        if not row:
            raise NotFoundError("Task not found")
        return row["task_id"]
    except ValueError:
        pass

    # Try integer
    try:
        task_number = int(ref)
        row = await aweb_db.fetch_one(
            "SELECT task_id FROM {{tables.tasks}} WHERE project_id = $1 AND task_number = $2 AND deleted_at IS NULL",
            UUID(project_id),
            task_number,
        )
        if not row:
            raise NotFoundError("Task not found")
        return row["task_id"]
    except ValueError:
        pass

    # Try slug-NNN
    slug = await _get_project_slug(db, project_id=project_id)
    prefix = slug + "-"
    if not ref.startswith(prefix):
        raise NotFoundError("Task not found")
    try:
        task_number = int(ref[len(prefix) :])
    except ValueError:
        raise NotFoundError("Task not found")

    row = await aweb_db.fetch_one(
        "SELECT task_id FROM {{tables.tasks}} WHERE project_id = $1 AND task_number = $2 AND deleted_at IS NULL",
        UUID(project_id),
        task_number,
    )
    if not row:
        raise NotFoundError("Task not found")
    return row["task_id"]


async def create_task(
    db,
    *,
    project_id: str,
    created_by_agent_id: str,
    title: str,
    description: str = "",
    notes: str = "",
    priority: int = 2,
    task_type: str = "task",
    labels: list[str] | None = None,
    parent_task_id: str | None = None,
    assignee_agent_id: str | None = None,
) -> dict[str, Any]:
    slug = await _get_project_slug(db, project_id=project_id)
    task_number = await allocate_task_number(db, project_id=project_id)

    aweb_db = db.get_manager("aweb")

    if parent_task_id:
        parent_row = await aweb_db.fetch_one(
            "SELECT task_id FROM {{tables.tasks}} WHERE task_id = $1 AND project_id = $2 AND deleted_at IS NULL",
            UUID(parent_task_id),
            UUID(project_id),
        )
        if not parent_row:
            raise ValidationError("Parent task not found in this project")

    if assignee_agent_id:
        agent_row = await aweb_db.fetch_one(
            "SELECT agent_id FROM {{tables.agents}} WHERE agent_id = $1 AND project_id = $2 AND deleted_at IS NULL",
            UUID(assignee_agent_id),
            UUID(project_id),
        )
        if not agent_row:
            raise ValidationError("Assignee agent not found in this project")

    parent_uuid = UUID(parent_task_id) if parent_task_id else None
    assignee_uuid = UUID(assignee_agent_id) if assignee_agent_id else None
    row = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.tasks}}
            (project_id, task_number, title, description, notes, priority, task_type,
             labels, parent_task_id, assignee_agent_id, created_by_agent_id)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        RETURNING task_id, created_at, updated_at
        """,
        UUID(project_id),
        task_number,
        title,
        description,
        notes,
        priority,
        task_type,
        labels or [],
        parent_uuid,
        assignee_uuid,
        UUID(created_by_agent_id),
    )

    return {
        "task_id": str(row["task_id"]),
        "task_ref": format_task_ref(slug, task_number),
        "task_number": task_number,
        "project_id": project_id,
        "title": title,
        "description": description,
        "notes": notes,
        "status": "open",
        "priority": priority,
        "task_type": task_type,
        "labels": labels or [],
        "parent_task_id": parent_task_id,
        "assignee_agent_id": assignee_agent_id,
        "created_by_agent_id": created_by_agent_id,
        "closed_by_agent_id": None,
        "created_at": row["created_at"].isoformat(),
        "updated_at": row["updated_at"].isoformat(),
        "closed_at": None,
    }


async def get_task(db, *, project_id: str, ref: str) -> dict[str, Any]:
    task_id = await resolve_task_ref(db, project_id=project_id, ref=ref)
    slug = await _get_project_slug(db, project_id=project_id)
    aweb_db = db.get_manager("aweb")

    row = await aweb_db.fetch_one(
        """
        SELECT task_id, project_id, task_number, title, description, notes,
               status, priority, task_type, labels, parent_task_id,
               assignee_agent_id, created_by_agent_id, closed_by_agent_id,
               created_at, updated_at, closed_at
        FROM {{tables.tasks}}
        WHERE task_id = $1 AND deleted_at IS NULL
        """,
        task_id,
    )
    if not row:
        raise NotFoundError("Task not found")

    # blocked_by: tasks this task depends on
    blocked_by_rows = await aweb_db.fetch_all(
        """
        SELECT t.task_id, t.task_number, t.title, t.status
        FROM {{tables.task_dependencies}} d
        JOIN {{tables.tasks}} t ON t.task_id = d.depends_on_task_id
        WHERE d.task_id = $1 AND t.deleted_at IS NULL
        """,
        task_id,
    )

    # blocks: tasks that depend on this task
    blocks_rows = await aweb_db.fetch_all(
        """
        SELECT t.task_id, t.task_number, t.title, t.status
        FROM {{tables.task_dependencies}} d
        JOIN {{tables.tasks}} t ON t.task_id = d.task_id
        WHERE d.depends_on_task_id = $1 AND t.deleted_at IS NULL
        """,
        task_id,
    )

    def _dep_view(r):
        return {
            "task_id": str(r["task_id"]),
            "task_ref": format_task_ref(slug, r["task_number"]),
            "title": r["title"],
            "status": r["status"],
        }

    return {
        "task_id": str(row["task_id"]),
        "task_ref": format_task_ref(slug, row["task_number"]),
        "task_number": row["task_number"],
        "project_id": str(row["project_id"]),
        "title": row["title"],
        "description": row["description"],
        "notes": row["notes"],
        "status": row["status"],
        "priority": row["priority"],
        "task_type": row["task_type"],
        "labels": list(row["labels"]) if row["labels"] else [],
        "parent_task_id": str(row["parent_task_id"]) if row["parent_task_id"] else None,
        "assignee_agent_id": str(row["assignee_agent_id"]) if row["assignee_agent_id"] else None,
        "created_by_agent_id": (
            str(row["created_by_agent_id"]) if row["created_by_agent_id"] else None
        ),
        "closed_by_agent_id": str(row["closed_by_agent_id"]) if row["closed_by_agent_id"] else None,
        "created_at": row["created_at"].isoformat(),
        "updated_at": row["updated_at"].isoformat(),
        "closed_at": row["closed_at"].isoformat() if row["closed_at"] else None,
        "blocked_by": [_dep_view(r) for r in blocked_by_rows],
        "blocks": [_dep_view(r) for r in blocks_rows],
    }


async def list_tasks(
    db,
    *,
    project_id: str,
    status: str | None = None,
    assignee_agent_id: str | None = None,
    task_type: str | None = None,
    priority: int | None = None,
    labels: list[str] | None = None,
) -> list[dict[str, Any]]:
    slug = await _get_project_slug(db, project_id=project_id)
    aweb_db = db.get_manager("aweb")

    conditions = ["project_id = $1", "deleted_at IS NULL"]
    params: list[Any] = [UUID(project_id)]
    idx = 2

    if status is not None:
        conditions.append(f"status = ${idx}")
        params.append(status)
        idx += 1

    if assignee_agent_id is not None:
        conditions.append(f"assignee_agent_id = ${idx}")
        params.append(UUID(assignee_agent_id))
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

    where = " AND ".join(conditions)
    rows = await aweb_db.fetch_all(
        f"""
        SELECT task_id, task_number, title, status, priority, task_type,
               assignee_agent_id, created_by_agent_id, parent_task_id, labels,
               created_at, updated_at
        FROM {{{{tables.tasks}}}}
        WHERE {where}
        ORDER BY task_number ASC
        """,
        *params,
    )

    return [
        {
            "task_id": str(r["task_id"]),
            "task_ref": format_task_ref(slug, r["task_number"]),
            "task_number": r["task_number"],
            "title": r["title"],
            "status": r["status"],
            "priority": r["priority"],
            "task_type": r["task_type"],
            "assignee_agent_id": str(r["assignee_agent_id"]) if r["assignee_agent_id"] else None,
            "created_by_agent_id": (
                str(r["created_by_agent_id"]) if r["created_by_agent_id"] else None
            ),
            "parent_task_id": str(r["parent_task_id"]) if r["parent_task_id"] else None,
            "labels": list(r["labels"]) if r["labels"] else [],
            "created_at": r["created_at"].isoformat(),
            "updated_at": r["updated_at"].isoformat(),
        }
        for r in rows
    ]


async def list_ready_tasks(db, *, project_id: str) -> list[dict[str, Any]]:
    """Open tasks with no unresolved (non-closed) blockers."""
    slug = await _get_project_slug(db, project_id=project_id)
    aweb_db = db.get_manager("aweb")

    rows = await aweb_db.fetch_all(
        """
        SELECT t.task_id, t.task_number, t.title, t.status, t.priority, t.task_type,
               t.assignee_agent_id, t.created_by_agent_id, t.parent_task_id, t.labels,
               t.created_at, t.updated_at
        FROM {{tables.tasks}} t
        WHERE t.project_id = $1
          AND t.status = 'open'
          AND t.deleted_at IS NULL
          AND NOT EXISTS (
              SELECT 1 FROM {{tables.task_dependencies}} d
              JOIN {{tables.tasks}} blocker ON blocker.task_id = d.depends_on_task_id
              WHERE d.task_id = t.task_id
                AND blocker.status != 'closed'
                AND blocker.deleted_at IS NULL
          )
        ORDER BY t.priority ASC, t.task_number ASC
        """,
        UUID(project_id),
    )

    return [
        {
            "task_id": str(r["task_id"]),
            "task_ref": format_task_ref(slug, r["task_number"]),
            "task_number": r["task_number"],
            "title": r["title"],
            "status": r["status"],
            "priority": r["priority"],
            "task_type": r["task_type"],
            "assignee_agent_id": str(r["assignee_agent_id"]) if r["assignee_agent_id"] else None,
            "created_by_agent_id": (
                str(r["created_by_agent_id"]) if r["created_by_agent_id"] else None
            ),
            "parent_task_id": str(r["parent_task_id"]) if r["parent_task_id"] else None,
            "labels": list(r["labels"]) if r["labels"] else [],
            "created_at": r["created_at"].isoformat(),
            "updated_at": r["updated_at"].isoformat(),
        }
        for r in rows
    ]


async def list_blocked_tasks(db, *, project_id: str) -> list[dict[str, Any]]:
    """Open or in-progress tasks that have at least one unresolved (non-closed) dependency."""
    slug = await _get_project_slug(db, project_id=project_id)
    aweb_db = db.get_manager("aweb")

    rows = await aweb_db.fetch_all(
        """
        SELECT t.task_id, t.task_number, t.title, t.status, t.priority, t.task_type,
               t.assignee_agent_id, t.created_by_agent_id, t.parent_task_id, t.labels,
               t.created_at, t.updated_at
        FROM {{tables.tasks}} t
        WHERE t.project_id = $1
          AND t.status IN ('open', 'in_progress')
          AND t.deleted_at IS NULL
          AND EXISTS (
              SELECT 1 FROM {{tables.task_dependencies}} d
              JOIN {{tables.tasks}} blocker ON blocker.task_id = d.depends_on_task_id
              WHERE d.task_id = t.task_id
                AND blocker.status != 'closed'
                AND blocker.deleted_at IS NULL
          )
        ORDER BY t.priority ASC, t.task_number ASC
        """,
        UUID(project_id),
    )

    return [
        {
            "task_id": str(r["task_id"]),
            "task_ref": format_task_ref(slug, r["task_number"]),
            "task_number": r["task_number"],
            "title": r["title"],
            "status": r["status"],
            "priority": r["priority"],
            "task_type": r["task_type"],
            "assignee_agent_id": str(r["assignee_agent_id"]) if r["assignee_agent_id"] else None,
            "created_by_agent_id": (
                str(r["created_by_agent_id"]) if r["created_by_agent_id"] else None
            ),
            "parent_task_id": str(r["parent_task_id"]) if r["parent_task_id"] else None,
            "labels": list(r["labels"]) if r["labels"] else [],
            "created_at": r["created_at"].isoformat(),
            "updated_at": r["updated_at"].isoformat(),
        }
        for r in rows
    ]


async def update_task(
    db,
    *,
    project_id: str,
    ref: str,
    actor_agent_id: str,
    title: str | None = None,
    description: str | None = None,
    notes: str | None = None,
    status: str | None = None,
    priority: int | None = None,
    task_type: str | None = None,
    labels: list[str] | None = None,
    assignee_agent_id: str | None | object = _UNSET,
) -> dict[str, Any]:
    task_id = await resolve_task_ref(db, project_id=project_id, ref=ref)
    aweb_db = db.get_manager("aweb")
    now = datetime.now(timezone.utc)

    async with aweb_db.transaction() as tx:
        current = await tx.fetch_one(
            """
            SELECT task_id, status, assignee_agent_id
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

        # assignee_agent_id uses sentinel to distinguish "not provided" from "set to null"
        if assignee_agent_id is not _UNSET:
            sets.append(f"assignee_agent_id = ${idx}")
            params.append(UUID(str(assignee_agent_id)) if assignee_agent_id else None)
            idx += 1

        auto_closed: list[dict[str, Any]] = []

        if status is not None:
            if status == "in_progress":
                cur_assignee = current["assignee_agent_id"]
                if cur_assignee is None:
                    # Auto-assign to actor
                    sets.append(f"assignee_agent_id = ${idx}")
                    params.append(UUID(actor_agent_id))
                    idx += 1
                elif str(cur_assignee) != actor_agent_id:
                    raise ConflictError("Task is assigned to another agent")

            sets.append(f"status = ${idx}")
            params.append(status)
            idx += 1

            if status == "closed":
                sets.append(f"closed_by_agent_id = ${idx}")
                params.append(UUID(actor_agent_id))
                idx += 1
                sets.append(f"closed_at = ${idx}")
                params.append(now)
                idx += 1

                # Cascade close to all descendants
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

                    # Batch close all descendants
                    await tx.execute(
                        """
                        UPDATE {{tables.tasks}}
                        SET status = 'closed', closed_by_agent_id = $2, closed_at = $3, updated_at = $3
                        WHERE task_id = ANY($1::uuid[])
                        """,
                        desc_ids,
                        UUID(actor_agent_id),
                        now,
                    )

                    # Batch fetch for response
                    slug = await _get_project_slug(db, project_id=project_id)
                    closed_rows = await tx.fetch_all(
                        "SELECT task_id, task_number, title FROM {{tables.tasks}} WHERE task_id = ANY($1::uuid[])",
                        desc_ids,
                    )
                    for cr in closed_rows:
                        auto_closed.append(
                            {
                                "task_id": str(cr["task_id"]),
                                "task_ref": format_task_ref(slug, cr["task_number"]),
                                "title": cr["title"],
                            }
                        )

        set_clause = ", ".join(sets)
        await tx.execute(
            f"UPDATE {{{{tables.tasks}}}} SET {set_clause} WHERE task_id = $1",
            *params,
        )

    old_status = current["status"]

    result = await get_task(db, project_id=project_id, ref=str(task_id))
    if auto_closed:
        result["auto_closed"] = auto_closed
    if status is not None and status != old_status:
        result["old_status"] = old_status
    return result


async def soft_delete_task(db, *, project_id: str, ref: str) -> dict[str, Any]:
    task_id = await resolve_task_ref(db, project_id=project_id, ref=ref)
    slug = await _get_project_slug(db, project_id=project_id)
    aweb_db = db.get_manager("aweb")
    now = datetime.now(timezone.utc)

    async with aweb_db.transaction() as tx:
        row = await tx.fetch_one(
            """
            UPDATE {{tables.tasks}} SET deleted_at = $2, updated_at = $2
            WHERE task_id = $1 AND deleted_at IS NULL
            RETURNING task_id, task_number
            """,
            task_id,
            now,
        )
        if not row:
            raise NotFoundError("Task not found")

    return {
        "status": "deleted",
        "task_id": str(task_id),
        "task_ref": format_task_ref(slug, row["task_number"]),
    }


async def add_dependency(
    db, *, project_id: str, task_ref: str, depends_on_ref: str
) -> dict[str, Any]:
    task_id = await resolve_task_ref(db, project_id=project_id, ref=task_ref)
    depends_on_id = await resolve_task_ref(db, project_id=project_id, ref=depends_on_ref)

    if task_id == depends_on_id:
        raise ValidationError("A task cannot depend on itself")

    aweb_db = db.get_manager("aweb")

    # Cycle detection: check if task_id is reachable from depends_on_id
    cycle_row = await aweb_db.fetch_one(
        """
        WITH RECURSIVE reach AS (
            SELECT depends_on_task_id AS id
            FROM {{tables.task_dependencies}}
            WHERE task_id = $2
            UNION ALL
            SELECT d.depends_on_task_id
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
            INSERT INTO {{tables.task_dependencies}} (task_id, depends_on_task_id, project_id)
            VALUES ($1, $2, $3)
            """,
            task_id,
            depends_on_id,
            UUID(project_id),
        )
    except Exception as exc:
        if "duplicate key" in str(exc).lower():
            pass  # Idempotent
        else:
            raise

    return {"task_id": str(task_id), "depends_on_task_id": str(depends_on_id)}


async def remove_dependency(db, *, project_id: str, task_ref: str, dep_ref: str) -> dict[str, Any]:
    task_id = await resolve_task_ref(db, project_id=project_id, ref=task_ref)
    dep_id = await resolve_task_ref(db, project_id=project_id, ref=dep_ref)

    aweb_db = db.get_manager("aweb")
    await aweb_db.execute(
        "DELETE FROM {{tables.task_dependencies}} WHERE task_id = $1 AND depends_on_task_id = $2",
        task_id,
        dep_id,
    )
    return {"task_id": str(task_id), "removed_depends_on_task_id": str(dep_id)}


async def add_comment(db, *, project_id: str, ref: str, agent_id: str, body: str) -> dict[str, Any]:
    task_id = await resolve_task_ref(db, project_id=project_id, ref=ref)
    aweb_db = db.get_manager("aweb")

    row = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.task_comments}} (task_id, project_id, agent_id, body)
        VALUES ($1, $2, $3, $4)
        RETURNING comment_id, created_at
        """,
        task_id,
        UUID(project_id),
        UUID(agent_id),
        body,
    )

    return {
        "comment_id": str(row["comment_id"]),
        "task_id": str(task_id),
        "agent_id": agent_id,
        "body": body,
        "created_at": row["created_at"].isoformat(),
    }


async def list_comments(db, *, project_id: str, ref: str) -> list[dict[str, Any]]:
    task_id = await resolve_task_ref(db, project_id=project_id, ref=ref)
    aweb_db = db.get_manager("aweb")

    rows = await aweb_db.fetch_all(
        """
        SELECT comment_id, task_id, agent_id, body, created_at
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
            "agent_id": str(r["agent_id"]),
            "body": r["body"],
            "created_at": r["created_at"].isoformat(),
        }
        for r in rows
    ]
