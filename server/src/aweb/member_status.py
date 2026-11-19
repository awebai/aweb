"""Canonical stored agents.status vocabulary shared by readers and lifecycle writers."""

from enum import StrEnum


class MemberStatus(StrEnum):
    """Native row states; ACTIVE still requires current-key admission to act.

    docs/aweb-sot.md:1227-1258 defines lifecycle dispositions separately from
    these stored states. A disposition maps explicitly to one of these values.
    """

    ACTIVE = "active"
    RETIRED = "retired"
    ARCHIVED = "archived"
    DELETED = "deleted"
