from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from awid.team_ids import team_slug
from ..claims import claim_focus_task_ref, resolve_task_claim_apex
from ..service_errors import ConflictError, NotFoundError, ValidationError

_UNSET = object()


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


async def resolve_task_ref(db, *, team_id: str, ref: str) -> UUID:
    aweb_db = db.get_manager("aweb")

    try:
        task_uuid = UUID(ref)
        row = await aweb_db.fetch_one(
            "SELECT task_id FROM {{tables.tasks}} WHERE task_id = $1 AND team_id = $2 AND deleted_at IS NULL",
            task_uuid,
            team_id,
        )
        if not row:
            raise NotFoundError("Task not found")
        return row["task_id"]
    except ValueError:
        pass

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
) -> dict[str, Any]:
    slug = _get_team_slug(team_id)
    aweb_db = db.get_manager("aweb")
    resolved_parent_task_id: UUID | None = None
    task_ref_suffix: str | None = None

    if assignee_alias:
        assignee_alias = await _resolve_assignee_alias(
            db, team_id=team_id, assignee_ref=assignee_alias,
        )

    async with aweb_db.transaction() as tx:
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

            max_sibling_index = await tx.fetch_value(
                """
                SELECT COALESCE(MAX(CAST(regexp_replace(task_ref_suffix, '^.*\\.', '') AS INTEGER)), 0)
                FROM {{tables.tasks}}
                WHERE parent_task_id = $1
                """,
                resolved_parent_task_id,
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
                 labels, parent_task_id, assignee_alias, created_by_alias)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
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
    }


async def _resolve_assignee_alias(
    db,
    *,
    team_id: str,
    assignee_ref: str,
) -> str:
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
               created_at, updated_at, closed_at
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
        "updated_at": row["updated_at"].isoformat(),
        "closed_at": row["closed_at"].isoformat() if row["closed_at"] else None,
        "blocked_by": [_dep_view(r) for r in blocked_by_rows],
        "blocks": [_dep_view(r) for r in blocks_rows],
    }


async def list_tasks(
    db,
    *,
    team_id: str,
    status: str | None = None,
    assignee_alias: str | None = None,
    task_type: str | None = None,
    priority: int | None = None,
    labels: list[str] | None = None,
    q: str | None = None,
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
            f"(title ILIKE ${idx} OR (${idx + 1} || '-' || task_ref_suffix) ILIKE ${idx})"
        )
        params.append(q_pattern)
        params.append(slug)
        idx += 2

    rows = await aweb_db.fetch_all(
        f"""
        SELECT task_id, task_number, task_ref_suffix, title, status, priority, task_type,
               assignee_alias, created_by_alias, parent_task_id, labels,
               created_at, updated_at
        FROM {{{{tables.tasks}}}}
        WHERE {' AND '.join(conditions)}
        ORDER BY task_number ASC
        """,
        *params,
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
            "updated_at": r["updated_at"].isoformat() if r["updated_at"] else None,
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
            SELECT w.workspace_id, w.alias, w.current_branch, r.canonical_origin
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
                "branch": row["current_branch"],
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
                "updated_at": row["updated_at"].isoformat(),
                "workspace_id": owner_workspace_id,
                "owner_alias": owner_alias,
                "claimed_at": claimed_at,
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
            "updated_at": r["updated_at"].isoformat(),
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
            "updated_at": r["updated_at"].isoformat(),
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
) -> dict[str, Any]:
    task_id = await resolve_task_ref(db, team_id=team_id, ref=ref)
    slug = _get_team_slug(team_id)
    aweb_db = db.get_manager("aweb")
    now = datetime.now(timezone.utc)
    resolved_assignee_alias: str | None | object = _UNSET
    claim_preacquired = False

    async with aweb_db.transaction() as tx:
        current = await tx.fetch_one(
            """
            SELECT task_id, status, assignee_alias, task_ref_suffix
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
        if assignee_alias is not _UNSET:
            resolved_assignee_alias = (
                await _resolve_assignee_alias(
                    db,
                    team_id=team_id,
                    assignee_ref=str(assignee_alias),
                )
                if assignee_alias
                else None
            )
            if status != "in_progress":
                sets.append(f"assignee_alias = ${idx}")
                params.append(resolved_assignee_alias)
                idx += 1

        auto_closed: list[dict[str, Any]] = []
        if status is not None:
            if status == "in_progress":
                task_ref = format_task_ref(slug, current["task_ref_suffix"])
                apex_task_ref = await resolve_task_claim_apex(db, team_id, task_ref)
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
