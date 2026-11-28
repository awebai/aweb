"""Frozen producer contexts for native coordination mutations.

These projections preserve optional key absence and explicit None separately.
They do not validate received callbacks or constrain host extension names.
"""

from dataclasses import Field, dataclass, fields
from enum import Enum
from typing import Any, ClassVar

from aweb.event_types import MutationEventType


class AbsentContextField(Enum):
    """An omitted projection field, distinct from an explicitly stored null."""

    ABSENT = "absent"


class CoordinationContext:
    """Serialize a producer's declared fields without adding omitted keys."""

    __dataclass_fields__: ClassVar[dict[str, Field[Any]]]
    event_type: ClassVar[MutationEventType]

    def to_context(self) -> dict[str, object]:
        """Return the existing callback mapping, preserving values and absence."""
        return {
            item.name: value
            for item in fields(self)
            if (value := getattr(self, item.name)) is not AbsentContextField.ABSENT
        }


@dataclass(frozen=True, kw_only=True)
class ReservationAcquiredContext(CoordinationContext):
    """Producer projection for reservation.acquired."""

    event_type: ClassVar[MutationEventType] = MutationEventType.RESERVATION_ACQUIRED
    team_id: str | None | AbsentContextField = AbsentContextField.ABSENT
    holder_agent_id: str | None | AbsentContextField = AbsentContextField.ABSENT
    alias: str | None | AbsentContextField = AbsentContextField.ABSENT
    resource_key: str | None | AbsentContextField = AbsentContextField.ABSENT
    ttl_seconds: int | AbsentContextField = AbsentContextField.ABSENT


@dataclass(frozen=True, kw_only=True)
class ReservationReleasedContext(CoordinationContext):
    """Producer projection for reservation.released."""

    event_type: ClassVar[MutationEventType] = MutationEventType.RESERVATION_RELEASED
    team_id: str | None | AbsentContextField = AbsentContextField.ABSENT
    holder_agent_id: str | None | AbsentContextField = AbsentContextField.ABSENT
    alias: str | None | AbsentContextField = AbsentContextField.ABSENT
    resource_key: str | None | AbsentContextField = AbsentContextField.ABSENT


@dataclass(frozen=True, kw_only=True)
class ReservationRenewedContext(CoordinationContext):
    """Producer projection for reservation.renewed."""

    event_type: ClassVar[MutationEventType] = MutationEventType.RESERVATION_RENEWED
    team_id: str | None | AbsentContextField = AbsentContextField.ABSENT
    holder_agent_id: str | None | AbsentContextField = AbsentContextField.ABSENT
    alias: str | None | AbsentContextField = AbsentContextField.ABSENT
    resource_key: str | None | AbsentContextField = AbsentContextField.ABSENT
    ttl_seconds: int | AbsentContextField = AbsentContextField.ABSENT


@dataclass(frozen=True, kw_only=True)
class TaskCreatedContext(CoordinationContext):
    """Producer projection for task.created."""

    event_type: ClassVar[MutationEventType] = MutationEventType.TASK_CREATED
    task_id: str | None | AbsentContextField = AbsentContextField.ABSENT
    team_id: str | None | AbsentContextField = AbsentContextField.ABSENT
    task_ref: str | None | AbsentContextField = AbsentContextField.ABSENT
    title: str | None | AbsentContextField = AbsentContextField.ABSENT
    parent_task_id: str | None | AbsentContextField = AbsentContextField.ABSENT
    assignee_alias: str | None | AbsentContextField = AbsentContextField.ABSENT
    actor_agent_id: str | None | AbsentContextField = AbsentContextField.ABSENT
    actor_alias: str | None | AbsentContextField = AbsentContextField.ABSENT
    actor_did_aw: str | None | AbsentContextField = AbsentContextField.ABSENT
    actor_did: str | None | AbsentContextField = AbsentContextField.ABSENT


@dataclass(frozen=True, kw_only=True)
class TaskUpdatedContext(CoordinationContext):
    """Producer projection for task.updated."""

    event_type: ClassVar[MutationEventType] = MutationEventType.TASK_UPDATED
    task_id: str | None | AbsentContextField = AbsentContextField.ABSENT
    task_ref: str | None | AbsentContextField = AbsentContextField.ABSENT
    actor_agent_id: str | None | AbsentContextField = AbsentContextField.ABSENT
    actor_did_aw: str | None | AbsentContextField = AbsentContextField.ABSENT


@dataclass(frozen=True, kw_only=True)
class TaskStatusChangedContext(CoordinationContext):
    """Producer projection for task.status_changed."""

    event_type: ClassVar[MutationEventType] = MutationEventType.TASK_STATUS_CHANGED
    task_id: str | None | AbsentContextField = AbsentContextField.ABSENT
    team_id: str | None | AbsentContextField = AbsentContextField.ABSENT
    task_ref: str | None | AbsentContextField = AbsentContextField.ABSENT
    title: str | None | AbsentContextField = AbsentContextField.ABSENT
    old_status: str | None | AbsentContextField = AbsentContextField.ABSENT
    new_status: str | None | AbsentContextField = AbsentContextField.ABSENT
    assignee_alias: str | None | AbsentContextField = AbsentContextField.ABSENT
    parent_task_id: str | None | AbsentContextField = AbsentContextField.ABSENT
    actor_agent_id: str | None | AbsentContextField = AbsentContextField.ABSENT
    actor_alias: str | None | AbsentContextField = AbsentContextField.ABSENT
    actor_did_aw: str | None | AbsentContextField = AbsentContextField.ABSENT
    actor_workspace_id: str | AbsentContextField = AbsentContextField.ABSENT
    claim_preacquired: bool | AbsentContextField = AbsentContextField.ABSENT
    released_claim_workspace_ids: list[str] | AbsentContextField = (
        AbsentContextField.ABSENT
    )


@dataclass(frozen=True, kw_only=True)
class TaskClaimReplacedContext(TaskStatusChangedContext):
    """Committed claim facts from an update that kept the same task status."""

    event_type: ClassVar[MutationEventType] = MutationEventType.TASK_UPDATED


@dataclass(frozen=True, kw_only=True)
class TaskAssigneeChangedContext(CoordinationContext):
    """Producer projection for task.assignee_changed."""

    event_type: ClassVar[MutationEventType] = MutationEventType.TASK_ASSIGNEE_CHANGED
    task_id: str | None | AbsentContextField = AbsentContextField.ABSENT
    team_id: str | None | AbsentContextField = AbsentContextField.ABSENT
    task_ref: str | None | AbsentContextField = AbsentContextField.ABSENT
    title: str | None | AbsentContextField = AbsentContextField.ABSENT
    actor_agent_id: str | None | AbsentContextField = AbsentContextField.ABSENT
    actor_alias: str | None | AbsentContextField = AbsentContextField.ABSENT
    actor_did_aw: str | None | AbsentContextField = AbsentContextField.ABSENT
    old_assignee_alias: str | None | AbsentContextField = AbsentContextField.ABSENT
    assignee_alias: str | None | AbsentContextField = AbsentContextField.ABSENT


@dataclass(frozen=True, kw_only=True)
class TaskDeletedContext(CoordinationContext):
    """Producer projection for task.deleted."""

    event_type: ClassVar[MutationEventType] = MutationEventType.TASK_DELETED
    task_id: str | None | AbsentContextField = AbsentContextField.ABSENT
    team_id: str | None | AbsentContextField = AbsentContextField.ABSENT
    task_ref: str | None | AbsentContextField = AbsentContextField.ABSENT
    title: str | None | AbsentContextField = AbsentContextField.ABSENT
    actor_agent_id: str | None | AbsentContextField = AbsentContextField.ABSENT
    actor_did_aw: str | None | AbsentContextField = AbsentContextField.ABSENT
    released_claim_workspace_ids: list[str] | AbsentContextField = (
        AbsentContextField.ABSENT
    )


@dataclass(frozen=True, kw_only=True)
class TaskCommentAddedContext(CoordinationContext):
    """Producer projection for task.comment_added."""

    event_type: ClassVar[MutationEventType] = MutationEventType.TASK_COMMENT_ADDED
    task_id: str | None | AbsentContextField = AbsentContextField.ABSENT
    comment_id: str | None | AbsentContextField = AbsentContextField.ABSENT
    actor_agent_id: str | None | AbsentContextField = AbsentContextField.ABSENT
    actor_did_aw: str | None | AbsentContextField = AbsentContextField.ABSENT


@dataclass(frozen=True, kw_only=True)
class TaskDependencyAddedContext(CoordinationContext):
    """Producer projection for task.dependency_added."""

    event_type: ClassVar[MutationEventType] = MutationEventType.TASK_DEPENDENCY_ADDED
    task_id: str | None | AbsentContextField = AbsentContextField.ABSENT
    depends_on_task_id: str | None | AbsentContextField = AbsentContextField.ABSENT
    actor_agent_id: str | None | AbsentContextField = AbsentContextField.ABSENT
    actor_did_aw: str | None | AbsentContextField = AbsentContextField.ABSENT


@dataclass(frozen=True, kw_only=True)
class TaskDependencyRemovedContext(CoordinationContext):
    """Producer projection for task.dependency_removed."""

    event_type: ClassVar[MutationEventType] = MutationEventType.TASK_DEPENDENCY_REMOVED
    task_id: str | None | AbsentContextField = AbsentContextField.ABSENT
    removed_depends_on_task_id: str | None | AbsentContextField = (
        AbsentContextField.ABSENT
    )
    actor_agent_id: str | None | AbsentContextField = AbsentContextField.ABSENT
    actor_did_aw: str | None | AbsentContextField = AbsentContextField.ABSENT
