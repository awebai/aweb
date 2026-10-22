"""Trusted application inputs to the shared page store; none are wire authority."""

from __future__ import annotations

import copy
from dataclasses import asdict, dataclass, field
from typing import Any


class StoreError(Exception):
    def __init__(self, code: str, status: int = 422, *, details: Any = None):
        super().__init__(code)
        self.code, self.status, self.details = code, status, details


@dataclass(frozen=True)
class Scope:
    installation_id: str
    team_id: str
    app_id: str
    page_id: str

    @property
    def key(self) -> list[str]:
        return [self.installation_id, self.team_id, self.app_id, self.page_id]


@dataclass(frozen=True)
class RetentionPolicy:
    """Explicit operator policy. No product defaults; supplied before content writes."""

    version: str
    content_purge_days: int
    audit_content_days: int
    backup_expiry_days: int
    backup_interval_hours: int
    restore_rpo_hours: int
    retry_horizon_days: int
    encrypted_backups: bool
    legal_exceptions: tuple[str, ...]

    def __post_init__(self):
        if (
            not isinstance(self.version, str)
            or not self.version
            or self.encrypted_backups is not True
            or not isinstance(self.legal_exceptions, (list, tuple))
            or any(not isinstance(item, str) or not item for item in self.legal_exceptions)
            or any(
                type(value) is not int or value <= 0
                for value in (
                    self.content_purge_days,
                    self.audit_content_days,
                    self.backup_expiry_days,
                    self.backup_interval_hours,
                    self.restore_rpo_hours,
                    self.retry_horizon_days,
                )
            )
        ):
            raise ValueError("an explicit versioned encrypted backup/retention policy is required")

    def as_dict(self) -> dict[str, Any]:
        return {**asdict(self), "legal_exceptions": list(self.legal_exceptions)}


@dataclass
class Access:
    """Persisted page ACL, set only by an owner operation.

    Principal keys come from verified member identity. Missing row/field rules
    mean the principal's page-level access applies; an explicit empty field set
    exposes no values. Read restrictions also bound writes and query fields.
    Team administration and lifecycle grants are supplied by the host's trusted
    authorization adapter, never inferred from these page-owner ACLs.
    """

    owner: str
    readers: set[str] = field(default_factory=set)
    writers: set[str] = field(default_factory=set)
    hidden_rows: dict[str, dict[str, set[str]]] = field(default_factory=dict)
    fields: dict[str, dict[str, set[str]]] = field(default_factory=dict)

    team_id: str | None = None
    team_read: bool = False
    team_write: bool = False

    def __post_init__(self):
        if type(self.team_read) is not bool or type(self.team_write) is not bool:
            raise ValueError("team ACL flags must be explicit booleans")
        if (
            self.team_id is not None and (not isinstance(self.team_id, str) or not self.team_id)
        ) or ((self.team_read or self.team_write) and self.team_id is None):
            raise ValueError("team ACL grants require an explicit team ID")

    def require_scope(self, scope: Scope) -> None:
        if self.team_id is not None and self.team_id != scope.team_id:
            raise StoreError("action_denied", 403)

    def permits(self, principal: str, operation: str, *, team_id=None) -> bool:
        if principal == self.owner:
            return True
        team = self.team_id is not None and self.team_id == team_id
        if operation == "read":
            return principal in self.readers | self.writers or (
                team and (self.team_read or self.team_write)
            )
        return operation == "write" and (principal in self.writers or (team and self.team_write))

    def visible_row(self, principal: str, collection: str, record_id: str) -> bool:
        return principal == self.owner or record_id not in self.hidden_rows.get(principal, {}).get(
            collection, set()
        )

    def visible_fields(self, principal: str, collection: dict) -> set[str]:
        declared = set(collection["schema"].get("properties", {}))
        if principal == self.owner:
            return declared
        return declared & self.fields.get(principal, {}).get(collection["id"], declared)

    def redact_schema(self, principal: str, collection: dict, *, fields=None) -> dict:
        schema = copy.deepcopy(collection["schema"])
        allowed = self.visible_fields(principal, collection)
        if fields is not None:
            allowed &= fields
        schema["properties"] = {
            k: v for k, v in schema.get("properties", {}).items() if k in allowed
        }
        if "required" in schema:
            schema["required"] = [field for field in schema["required"] if field in allowed]
        if fields is not None or not self.all_value_fields(principal, collection):
            schema.pop("default", None)
            schema.pop("examples", None)
        return schema

    def value_fields(self, principal: str, collection: dict, values) -> set[str]:
        if principal == self.owner or collection["id"] not in self.fields.get(principal, {}):
            return set(values)
        return self.visible_fields(principal, collection)

    def all_value_fields(self, principal: str, collection: dict) -> bool:
        return principal == self.owner or collection["id"] not in self.fields.get(principal, {})

    def as_dict(self) -> dict:
        def encode(value):
            if isinstance(value, set):
                return sorted(value)
            if isinstance(value, dict):
                return {key: encode(item) for key, item in value.items()}
            return value

        return encode(asdict(self))

    @classmethod
    def from_dict(cls, value: dict) -> Access:
        return cls(
            value["owner"],
            set(value["readers"]),
            set(value["writers"]),
            {p: {c: set(ids) for c, ids in cs.items()} for p, cs in value["hidden_rows"].items()},
            {p: {c: set(fs) for c, fs in cs.items()} for p, cs in value["fields"].items()},
            team_id=value.get("team_id"),
            team_read=value.get("team_read", False),
            team_write=value.get("team_write", False),
        )
