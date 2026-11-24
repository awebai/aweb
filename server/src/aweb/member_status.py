"""Canonical stored agents.status vocabulary shared by readers and lifecycle writers."""

from enum import StrEnum


class MemberStatus(StrEnum):
    """Native row states; ACTIVE still requires current-key admission to act.

    migrations/aweb/001_initial.sql:42-45 constrains these stored states.
    A lifecycle disposition maps explicitly to one of these values.
    """

    ACTIVE = "active"
    RETIRED = "retired"
    ARCHIVED = "archived"
    DELETED = "deleted"
