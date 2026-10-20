"""The grant record v1 (§4.3): who may use or run a secret, under which policy.

A subject is a principal (S5's stable principal: a did:aw, else a did:key) or
a secrets role. A ``use`` grant allows either named operations, each bound to
the digest it was granted at, or open requests; a ``run`` grant allows jobs,
each bound to its digest. Editing an operation or a job gives it a new digest,
which no existing grant covers. The record is the change/1 ``after`` v1 of a
grant.
"""

from __future__ import annotations

import re
import secrets as random
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from aweb_naapp.roles import is_role_name

from aweb_secrets.policy import DIGEST, IDENTIFIER
from aweb_secrets.secret import SECRET_ID

CAPABILITIES = ("use", "run")
FIELDS = frozenset(
    {
        "v",
        "grant_id",
        "secret_id",
        "subject",
        "capability",
        "operations",
        "open_request",
        "jobs",
        "policy_digest",
    }
)

TEMPLATE_FIELDS = FIELDS - {"grant_id", "secret_id"} | {"grant_template_id"}

GRANT_ID = re.compile(r"grt_[A-Za-z0-9_-]{4,64}")
GRANT_TEMPLATE_ID = re.compile(r"gtp_[A-Za-z0-9_-]{4,64}")
PRINCIPAL = re.compile(r"did:(aw|key):[A-Za-z0-9]{1,128}")
SECRETS_ROLE = re.compile(r"secrets\.(owner|role\.[a-z0-9][a-z0-9_-]*)")


class GrantInvalid(ValueError):
    """The record does not have the grant record v1 shape."""


def mint_grant_id() -> str:
    return "grt_" + random.token_urlsafe(16)


def is_secrets_role(role: str) -> bool:
    """Whether ``role`` is a role a secrets grant can target: the owner or an owner-defined role."""
    return SECRETS_ROLE.fullmatch(role) is not None and is_role_name(role)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise GrantInvalid(message)


def _matches(pattern: re.Pattern[str], value: Any) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _pinned(items: Any, id_field: str, what: str) -> list[tuple[str, str]]:
    _require(isinstance(items, list), f"{what} is a list")
    pairs = []
    for item in items:
        _require(
            isinstance(item, Mapping) and set(item) == {id_field, "digest"},
            f"each of {what} names its id and digest",
        )
        _require(_matches(IDENTIFIER, item[id_field]), f"{what} ids are lowercase slugs")
        _require(
            _matches(DIGEST, item["digest"]), f"{what} digests are 64 lowercase hex characters"
        )
        pairs.append((item[id_field], item["digest"]))
    _require(len(set(pairs)) == len(pairs), f"each of {what} is granted once")
    return pairs


def _check_terms(after: Mapping[str, Any]) -> None:
    """The subject, capability, allowances and policy that a grant and a grant template share."""
    _require(type(after["v"]) is int and after["v"] == 1, "this is version 1")
    subject = after["subject"]
    _require(
        isinstance(subject, Mapping)
        and len(subject) == 1
        and set(subject) <= {"principal", "role"},
        "the subject is one principal or one role",
    )
    if "principal" in subject:
        _require(_matches(PRINCIPAL, subject["principal"]), "a principal is a did:aw or a did:key")
    else:
        _require(
            isinstance(subject["role"], str) and is_secrets_role(subject["role"]),
            "the role is a secrets role",
        )
    _require(after["capability"] in CAPABILITIES, "capability is use or run")
    operations = _pinned(after["operations"], "operation_id", "operations")
    jobs = _pinned(after["jobs"], "job_id", "jobs")
    _require(isinstance(after["open_request"], bool), "open_request is a boolean")
    if after["capability"] == "use":
        _require(not jobs, "a use grant allows no jobs")
        _require(
            bool(operations) != after["open_request"],
            "a use grant allows named operations or open requests",
        )
    else:
        _require(bool(jobs), "a run grant allows at least one job")
        _require(not operations and not after["open_request"], "a run grant allows only jobs")
    _require(
        _matches(DIGEST, after["policy_digest"]), "policy_digest is 64 lowercase hex characters"
    )


def _check(after: Any) -> None:
    _require(
        isinstance(after, Mapping) and set(after) == FIELDS,
        f"a grant needs exactly {sorted(FIELDS)}",
    )
    _require(_matches(GRANT_ID, after["grant_id"]), "grant_id is a minted grant id")
    _require(_matches(SECRET_ID, after["secret_id"]), "secret_id is a minted secret id")
    _check_terms(after)


def _check_template(after: Any) -> None:
    _require(
        isinstance(after, Mapping) and set(after) == TEMPLATE_FIELDS,
        f"a grant template needs exactly {sorted(TEMPLATE_FIELDS)}",
    )
    _require(
        _matches(GRANT_TEMPLATE_ID, after["grant_template_id"]),
        "grant_template_id is a grant template id",
    )
    _check_terms(after)


@dataclass(frozen=True)
class GrantRecord:
    grant_id: str
    secret_id: str
    subject_principal: str | None
    subject_role: str | None
    capability: str
    operations: Sequence[tuple[str, str]]
    open_request: bool
    jobs: Sequence[tuple[str, str]]
    policy_digest: str

    @classmethod
    def from_after(cls, after: Mapping[str, Any]) -> GrantRecord:
        """The record for a change/1 ``after``, refused unless it is grant record v1."""
        _check(after)
        return cls(
            grant_id=after["grant_id"],
            secret_id=after["secret_id"],
            subject_principal=after["subject"].get("principal"),
            subject_role=after["subject"].get("role"),
            capability=after["capability"],
            operations=tuple((o["operation_id"], o["digest"]) for o in after["operations"]),
            open_request=after["open_request"],
            jobs=tuple((j["job_id"], j["digest"]) for j in after["jobs"]),
            policy_digest=after["policy_digest"],
        )

    def covers_operation(self, operation_id: str, digest: str) -> bool:
        return (operation_id, digest) in self.operations

    @property
    def after(self) -> dict[str, Any]:
        subject = (
            {"principal": self.subject_principal}
            if self.subject_principal is not None
            else {"role": self.subject_role}
        )
        return {
            "v": 1,
            "grant_id": self.grant_id,
            "secret_id": self.secret_id,
            "subject": subject,
            "capability": self.capability,
            "operations": [{"operation_id": o, "digest": d} for o, d in self.operations],
            "open_request": self.open_request,
            "jobs": [{"job_id": j, "digest": d} for j, d in self.jobs],
            "policy_digest": self.policy_digest,
        }


@dataclass(frozen=True)
class GrantTemplate:
    """The terms a derived secret's grant is copied from (§8.3): a grant without its secret."""

    grant_template_id: str
    terms: Mapping[str, Any]

    @classmethod
    def from_after(cls, after: Mapping[str, Any]) -> GrantTemplate:
        """The template for a change/1 ``after``, refused unless it is grant template v1."""
        _check_template(after)
        terms = {k: v for k, v in after.items() if k != "grant_template_id"}
        return cls(grant_template_id=after["grant_template_id"], terms=terms)

    def grant_for(self, secret_id: str, *, grant_id: str) -> GrantRecord:
        """The grant of these terms on ``secret_id``."""
        return GrantRecord.from_after({**self.terms, "grant_id": grant_id, "secret_id": secret_id})

    @property
    def after(self) -> dict[str, Any]:
        return {**self.terms, "grant_template_id": self.grant_template_id}
