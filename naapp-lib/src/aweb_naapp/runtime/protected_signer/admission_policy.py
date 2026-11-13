"""Closed immutable public policy data. A digest is not admission authority."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from awid.signing import canonical_json_bytes
from awid.team_ids import parse_team_id

_FIELDS = {"version", "teams", "root_selector", "subject_kinds", "member_role", "bounds"}
_BOUNDS = {"max_active", "rate_window_seconds", "max_per_window"}
_DOMAIN = b"aweb.admission-policy/1\n"


class PolicyInvalid(ValueError):
    def __init__(self):
        super().__init__("admission policy is invalid")


def _positive(value: Any) -> bool:
    return type(value) is int and 0 < value < 2**53


def _ordered(value: Any) -> bool:
    return (
        type(value) is list and bool(value)
        and all(type(item) is str and bool(item) for item in value)
        and value == sorted(set(value))
    )


def _validate(fields: Any, service_id: str) -> None:
    if type(fields) is not dict or set(fields) != _FIELDS:
        raise PolicyInvalid()
    if not _positive(fields["version"]) or fields["member_role"] != "member":
        raise PolicyInvalid()
    teams, kinds = fields["teams"], fields["subject_kinds"]
    if not _ordered(teams) or not _ordered(kinds):
        raise PolicyInvalid()
    try:
        for team in teams:
            namespace, name = parse_team_id(team)
            if team != name + ":" + namespace:
                raise PolicyInvalid()
    except (ValueError, TypeError):
        raise PolicyInvalid() from None
    if not set(kinds) <= {"local_agent", "registered_agent"}:
        raise PolicyInvalid()
    selector, bounds = fields["root_selector"], fields["bounds"]
    if (type(service_id) is not str or not service_id
        or type(selector) is not dict or set(selector) != {"kind", "service_id"}
        or selector != {"kind": "service_endorsed_root", "service_id": service_id}):
        raise PolicyInvalid()
    if (type(bounds) is not dict or set(bounds) != _BOUNDS
        or not all(_positive(value) for value in bounds.values())):
        raise PolicyInvalid()


@dataclass(frozen=True, slots=True)
class AdmissionPolicy:
    """Validated canonical snapshot; callers cannot mutate nested policy data.

    Construction admits public configuration only. The host separately proves
    operator custody, current root endorsement, and transactional quota bounds.
    """

    _canonical: bytes

    @classmethod
    def from_unsigned(cls, fields: Any, *, service_id: str) -> AdmissionPolicy:
        _validate(fields, service_id)
        try:
            canonical = canonical_json_bytes(fields)
        except (ValueError, TypeError):
            raise PolicyInvalid() from None
        return cls(canonical)

    @classmethod
    def from_fields(cls, fields: Any, *, service_id: str) -> AdmissionPolicy:
        if type(fields) is not dict or set(fields) != _FIELDS | {"digest"}:
            raise PolicyInvalid()
        policy = cls.from_unsigned(
            {key: value for key, value in fields.items() if key != "digest"},
            service_id=service_id,
        )
        if fields["digest"] != policy.digest:
            raise PolicyInvalid()
        return policy

    @property
    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(_DOMAIN + self._canonical).hexdigest()

    @property
    def version(self) -> int:
        return json.loads(self._canonical)["version"]

    def fields(self) -> dict[str, Any]:
        return {**json.loads(self._canonical), "digest": self.digest}
