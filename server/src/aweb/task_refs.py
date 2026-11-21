"""Task reference representation shared by task services and coordination reads."""

import re
from enum import StrEnum

from awid.team_ids import team_slug


def format_task_ref(*, team_slug: str, task_ref_suffix: str) -> str:
    """Form the public team-slug reference (docs/aweb-sot.md, Task claims)."""
    return f"{team_slug}-{task_ref_suffix}"


def task_ref_suffix(*, team_id: str, ref: str) -> str:
    """Accept a full team reference or its suffix without splitting team hyphens."""
    prefix = f"{team_slug(team_id)}-"
    return (ref[len(prefix) :] if ref.startswith(prefix) else ref).strip()


class TaskTitleFields(StrEnum):
    TITLE = "title"
    TITLE_AND_TYPE = "title_and_type"


def _identifier(value: str) -> str:
    if re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*", value) is None:
        raise ValueError("Invalid task SQL identifier")
    return value


def _column(value: str) -> str:
    parts = value.split(".")
    if len(parts) != 2:
        raise ValueError("Task SQL column must name its relation")
    return ".".join(_identifier(part) for part in parts)


def task_title_join(
    *,
    alias: str,
    team_id_col: str,
    task_ref_col: str,
    fields: TaskTitleFields = TaskTitleFields.TITLE,
) -> str:
    """Join a claim/focus reference to its live task in the configured schema.

    SQL implements the same lowercase, colon-form team slug as awid.team_ids.
    Callers supply only checked identifiers, never SQL expressions or data.
    """
    alias = _identifier(alias)
    team_id_col = _column(team_id_col)
    task_ref_col = _column(task_ref_col)
    match fields:
        case TaskTitleFields.TITLE:
            selected = "t.title"
        case TaskTitleFields.TITLE_AND_TYPE:
            selected = "t.title, t.task_type AS issue_type"
        case _:
            raise ValueError("Unknown task title fields")
    return f"""
        LEFT JOIN LATERAL (
            SELECT {selected}
            FROM {{{{tables.tasks}}}} t
            WHERE t.team_id = {team_id_col}
              AND {task_ref_col} = lower(btrim(split_part({team_id_col}, ':', 1))) || '-' || t.task_ref_suffix
              AND t.deleted_at IS NULL
            LIMIT 1
        ) {alias} ON true
    """
