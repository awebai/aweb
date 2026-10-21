"""aweb.secrets.change/1: a frozen set of widening changes that an owner confirms with a passkey.

A change set lists the widening items of design §6.3. Each item names its
kind, its op, the object it changes (``ref``) and that object's state after
the change (``after``). Each kind's ``after`` has its own version ``v``, so
changing a shape changes the bytes and needs a new approval, never a silently
reinterpreted one. The change set is approved through B2: the approval covers
B2's canonical bytes of ``{policy, request}``, with the change set as the
request, so the console renders and the owner confirms exactly those bytes.

A change set is drafted against one installation, generation and
configuration revision, and lives at most seven days. Confirming it for any
other installation, generation, team or revision, or after it expires, is
refused.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from aweb_naapp.egress import InternalDestinations
from aweb_naapp.runtime.approvals import RequestNotCanonical, canonical_request
from aweb_naapp.runtime.approvals.request import parse_request_json
from awid.utc_timestamps import parse_utc_seconds

from aweb_secrets import destination, grant, operation, policy, runners, secret
from aweb_secrets.principal import is_did_aw, is_did_key

TYPE = "aweb.secrets.change"
VERSION = 1
MAX_REASON_CHARS = 1000
MAX_TEXT_CHARS = 256
MAX_CONTACT_CHARS = 320
# A pending widening is confirmable for at most this long (decision 38).
MAX_LIFETIME = timedelta(days=7)

# The widening items of design §6.3, each with the ops that widen it. Destinations,
# operations, grants and policies are immutable records: broadening one creates a
# new record, and removing the old one is a narrowing act outside change sets.
KINDS: Mapping[str, frozenset[str]] = {
    "secret": frozenset({"create", "update"}),
    "secret_value": frozenset({"create"}),
    "destination": frozenset({"create"}),
    "operation": frozenset({"create"}),
    "job": frozenset({"create", "update"}),
    "runner": frozenset({"create", "update"}),
    "grant": frozenset({"create"}),
    "grant_template": frozenset({"create", "update"}),
    "role": frozenset({"create"}),
    "approver": frozenset({"create"}),
    "approver_contact": frozenset({"update"}),
    "policy": frozenset({"create"}),
    "reenable": frozenset({"enable"}),
    # Relaxing four eyes for change sets (decision 61). Requiring it narrows and
    # is applied directly, so a change set only ever carries the relaxing value.
    "change_set_policy": frozenset({"update"}),
}

DISTINCT_APPROVER = frozenset({"required", "not_required"})

# What can be disabled, and so re-enabled.
REENABLE_TARGETS = frozenset(
    {"installation", "secret", "destination", "operation", "job", "runner", "grant", "approver"}
)

# The owner role, or an owner-defined user role named in S5's segment charset.
_ROLE = re.compile(r"secrets\.(owner|role\.[a-z0-9][a-z0-9_-]*)")
MAX_ROLE_CHARS = 128


class ChangeRefused(ValueError):
    """A change set that is malformed, or cannot be confirmed now."""

    def __init__(self, message: str, code: str = "change_malformed") -> None:
        super().__init__(message)
        self.code = code


Check = Callable[[Any, str], None]


def _text(limit: int = MAX_TEXT_CHARS) -> Check:
    def check(value: Any, where: str) -> None:
        if not isinstance(value, str) or not value or len(value) > limit:
            raise ChangeRefused(f"{where} must be a non-empty string of at most {limit} characters")

    return check


def _bounded_text(limit: int) -> Check:
    def check(value: Any, where: str) -> None:
        if not isinstance(value, str) or len(value) > limit:
            raise ChangeRefused(f"{where} must be a string of at most {limit} characters")

    return check


def _optional(inner: Check) -> Check:
    def check(value: Any, where: str) -> None:
        if value is not None:
            inner(value, where)

    return check


def _positive_int(minimum: int) -> Check:
    def check(value: Any, where: str) -> None:
        if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
            raise ChangeRefused(f"{where} must be an integer of at least {minimum}")

    return check


def _one_of(values: frozenset[str]) -> Check:
    def check(value: Any, where: str) -> None:
        if value not in values:
            raise ChangeRefused(f"{where} must be one of {sorted(values)}")

    return check


def _matching(pattern: re.Pattern[str], limit: int = MAX_TEXT_CHARS) -> Check:
    def check(value: Any, where: str) -> None:
        if not isinstance(value, str) or len(value) > limit or not pattern.fullmatch(value):
            raise ChangeRefused(
                f"{where} must match {pattern.pattern} in at most {limit} characters"
            )

    return check


def _text_list(value: Any, where: str) -> None:
    if not isinstance(value, list) or not value:
        raise ChangeRefused(f"{where} must be a non-empty list")
    for index, item in enumerate(value):
        _text()(item, f"{where}[{index}]")
    if len(set(value)) != len(value):
        raise ChangeRefused(f"{where} must not repeat an entry")


def _timestamp(value: Any, where: str) -> None:
    try:
        parse_utc_seconds(value)
    except ValueError:
        raise ChangeRefused(
            f"{where} must be an RFC 3339 UTC time like 2026-10-20T12:00:00Z"
        ) from None


def _did_aw(value: Any, where: str) -> None:
    if not is_did_aw(value):
        raise ChangeRefused(f"{where} must be a did:aw")


def _did_key(value: Any, where: str) -> None:
    if not is_did_key(value):
        raise ChangeRefused(f"{where} must be an Ed25519 did:key")


def _principal(value: Any, where: str) -> None:
    """S5's stable principal key: a member's did:aw, or its did:key when it has none."""
    if isinstance(value, str) and value.startswith("did:aw:"):
        _did_aw(value, where)
    else:
        _did_key(value, where)


def _object(value: Any, where: str) -> None:
    if not isinstance(value, Mapping):
        raise ChangeRefused(f"{where} must be an object")


def _fields(value: Any, where: str, shape: Mapping[str, Check]) -> None:
    if not isinstance(value, Mapping):
        raise ChangeRefused(f"{where} must be an object")
    if set(value) != set(shape):
        raise ChangeRefused(f"{where} must have exactly the fields {sorted(shape)}")
    for field, check in shape.items():
        check(value[field], f"{where}.{field}")


@dataclass(frozen=True)
class AfterShape:
    """One frozen ``after`` shape: its fields (``v`` included), the field the
    item's ``ref`` must equal, and the fields that identify the changed object.

    ``derived`` computes fields from the whole ``after``, such as a record's
    digest, refusing an ``after`` that is not a valid record; ``ref_field`` and
    ``identity`` may name them."""

    fields: Mapping[str, Check]
    ref_field: str | None
    identity: tuple[str, ...]
    derived: Callable[[Mapping[str, Any], str], Mapping[str, Any]] | None = None
    # For a per-installation setting: the envelope field the item's ref must equal.
    envelope_ref: str | None = None


def _record_field(value: Any, where: str) -> None:
    """A field of a record whose whole ``after`` its record type checks, through ``derived``."""


def _record_fields(fields: frozenset[str]) -> Mapping[str, Check]:
    return {field: _V1 if field == "v" else _record_field for field in sorted(fields)}


def _record(
    parse: Callable[[Mapping[str, Any]], Any], digest: Callable[[Any], str] | None = None
) -> Callable[[Mapping[str, Any], str], Mapping[str, Any]]:
    def derived(after: Mapping[str, Any], where: str) -> Mapping[str, Any]:
        try:
            record = parse(after)
        except ValueError as exc:
            raise ChangeRefused(f"{where}: {exc}") from None
        return {} if digest is None else {"digest": digest(record)}

    return derived


def _destination(after: Mapping[str, Any]) -> destination.DestinationRecord:
    # The deploy's internal-destinations setting is applied when the confirmed
    # change set is stored, and again at dispatch; the shape checks the form.
    return destination.DestinationRecord.from_after(
        after, internal_destinations=InternalDestinations.ALLOWED
    )


def _policy(after: Mapping[str, Any]) -> policy.Policy:
    return policy.Policy.from_body({k: v for k, v in after.items() if k != "v"})


# A shape is found by its kind and v, so v is already the shape's own version here.
_V1: Check = _positive_int(1)

AFTER_SHAPES: dict[tuple[str, int], AfterShape] = {
    ("secret", 1): AfterShape(
        fields=_record_fields(secret.FIELDS),
        ref_field="ref",
        identity=("ref",),
        derived=_record(secret.SecretRecord.from_after),
    ),
    ("destination", 1): AfterShape(
        fields=_record_fields(destination.FIELDS),
        ref_field="destination_id",
        identity=("destination_id",),
        derived=_record(_destination),
    ),
    ("operation", 1): AfterShape(
        fields=_record_fields(operation.FIELDS),
        ref_field="operation_id",
        identity=("operation_id", "digest"),
        derived=_record(operation.OperationTemplate.from_after, lambda record: record.digest),
    ),
    ("runner", 1): AfterShape(
        fields=_record_fields(runners.FIELDS),
        ref_field="runner_id",
        identity=("runner_id",),
        derived=_record(runners.RunnerRecord.from_after),
    ),
    ("grant", 1): AfterShape(
        fields=_record_fields(grant.FIELDS),
        ref_field="grant_id",
        identity=("grant_id",),
        derived=_record(grant.GrantRecord.from_after),
    ),
    ("grant_template", 1): AfterShape(
        fields=_record_fields(grant.TEMPLATE_FIELDS),
        ref_field="grant_template_id",
        identity=("grant_template_id",),
        derived=_record(grant.GrantTemplate.from_after),
    ),
    ("policy", 1): AfterShape(
        fields=_record_fields(policy.FIELDS | {"v"}),
        ref_field="digest",
        identity=("digest",),
        derived=_record(_policy, lambda record: record.digest),
    ),
    ("secret_value", 1): AfterShape(
        fields={"v": _V1, "secret_ref": _text(), "version": _positive_int(1)},
        ref_field="secret_ref",
        identity=("secret_ref",),
    ),
    ("approver", 1): AfterShape(
        fields={
            "v": _V1,
            "approver_ref": _text(),
            "contact": _text(MAX_CONTACT_CHARS),
            "covers": _text_list,
            "principal": _optional(_principal),
        },
        ref_field="approver_ref",
        identity=("approver_ref",),
    ),
    ("approver_contact", 1): AfterShape(
        fields={"v": _V1, "approver_ref": _text(), "contact": _text(MAX_CONTACT_CHARS)},
        ref_field="approver_ref",
        identity=("approver_ref",),
    ),
    ("role", 1): AfterShape(
        fields={
            "v": _V1,
            "role": _matching(_ROLE, MAX_ROLE_CHARS),
            "principal": _principal,
        },
        ref_field="role",
        identity=("role", "principal"),
    ),
    ("change_set_policy", 1): AfterShape(
        fields={"v": _V1, "distinct_approver": _one_of(frozenset({"not_required"}))},
        ref_field=None,
        identity=(),
        envelope_ref="installation_id",
    ),
    ("reenable", 1): AfterShape(
        fields={"v": _V1, "target_kind": _one_of(REENABLE_TARGETS), "target_ref": _text()},
        ref_field="target_ref",
        identity=("target_kind", "target_ref"),
    ),
}

_CONSOLE_DRAFTER: Mapping[str, Check] = {
    "via": _one_of(frozenset({"console"})),
    "scope": _text(),
    "subject": _text(),
}
_MEMBER_DRAFTER: Mapping[str, Check] = {
    "via": _one_of(frozenset({"team_auth"})),
    "principal": _principal,
    "member_did_key": _did_key,
    "certificate_id": _text(),
    "alias": _text(),
}


def _drafter(value: Any, where: str) -> None:
    if not isinstance(value, Mapping):
        raise ChangeRefused(f"{where} must be an object")
    if value.get("via") == "console":
        _fields(value, where, _CONSOLE_DRAFTER)
    elif value.get("via") == "team_auth":
        shape = dict(_MEMBER_DRAFTER)
        if "did_aw" in value:
            shape["did_aw"] = _did_aw
        _fields(value, where, shape)
        if value["principal"] != value.get("did_aw", value["member_did_key"]):
            raise ChangeRefused(f"{where}.principal must be did_aw if present, else member_did_key")
    else:
        raise ChangeRefused(f"{where}.via must be console or team_auth")


def _item(value: Any, where: str) -> tuple[str, tuple[Any, ...]]:
    _fields(
        value,
        where,
        {
            "kind": _one_of(frozenset(KINDS)),
            "op": _text(),
            "ref": _text(),
            "after": _object,
        },
    )
    kind, op, ref, after = value["kind"], value["op"], value["ref"], value["after"]
    if op not in KINDS[kind]:
        raise ChangeRefused(f"{where}.op {op!r} is not a widening op for {kind}")
    version = after.get("v")
    shape = AFTER_SHAPES.get((kind, version)) if isinstance(version, int) else None
    if shape is None or isinstance(version, bool):
        raise ChangeRefused(f"{where}.after.v names no frozen shape for {kind}")
    _fields(after, f"{where}.after", shape.fields)
    found = dict(after)
    if shape.derived is not None:
        derived = shape.derived(after, f"{where}.after")
        if set(derived) & set(after):
            raise ChangeRefused(f"{where}.after: a derived field shadows an after field")
        found.update(derived)
    if shape.ref_field is not None and found[shape.ref_field] != ref:
        raise ChangeRefused(f"{where}.ref must equal after.{shape.ref_field}")
    return kind, tuple(found[field] for field in shape.identity)


def _changes(value: Any, where: str) -> None:
    if not isinstance(value, list) or not value:
        raise ChangeRefused(f"{where} must be a non-empty list")
    seen: set[tuple[str, tuple[Any, ...]]] = set()
    for index, item in enumerate(value):
        identity = _item(item, f"{where}[{index}]")
        if identity in seen:
            raise ChangeRefused(f"{where}[{index}] changes an object already in this change set")
        seen.add(identity)


_ENVELOPE: Mapping[str, Check] = {
    "v": _positive_int(1),
    "type": _one_of(frozenset({TYPE})),
    "change_id": _text(),
    "installation_id": _text(),
    "install_generation": _positive_int(1),
    "team_id": _text(),
    "drafter": _drafter,
    "base_revision": _positive_int(0),
    "changes": _changes,
    "reason": _bounded_text(MAX_REASON_CHARS),
    "issued_at": _timestamp,
    "expires_at": _timestamp,
}


def validate_change(change: Mapping[str, Any]) -> None:
    """Refuse, with :class:`ChangeRefused`, any change set outside the frozen shape."""
    _fields(change, "change", _ENVELOPE)
    if change["v"] != VERSION:
        raise ChangeRefused(f"change.v must be {VERSION}")
    for index, item in enumerate(change["changes"]):
        shape = AFTER_SHAPES[(item["kind"], item["after"]["v"])]
        if shape.envelope_ref is not None and item["ref"] != change[shape.envelope_ref]:
            raise ChangeRefused(
                f"change.changes[{index}].ref must equal change.{shape.envelope_ref}"
            )
    lifetime = parse_utc_seconds(change["expires_at"]) - parse_utc_seconds(change["issued_at"])
    if not timedelta(0) < lifetime <= MAX_LIFETIME:
        raise ChangeRefused("change.expires_at must be after change.issued_at, within 7 days")
    try:
        canonical_request(change)
    except RequestNotCanonical as exc:
        raise ChangeRefused(str(exc)) from None


def parse_change(raw: bytes) -> dict[str, Any]:
    """A change set received as JSON. Refuses what canonical JSON cannot carry
    (duplicate keys, floats) and anything outside the frozen shape."""
    try:
        change = parse_request_json(raw)
    except RequestNotCanonical as exc:
        raise ChangeRefused(str(exc)) from None
    validate_change(change)
    return change


def covered_bytes(change: Mapping[str, Any], policy: Mapping[str, Any]) -> bytes:
    """The bytes a B2 approval of ``change`` under ``policy`` covers."""
    validate_change(change)
    return canonical_request({"policy": dict(policy), "request": dict(change)})


def check_confirmable(
    change: Mapping[str, Any],
    *,
    installation_id: str,
    install_generation: int,
    team_id: str,
    current_revision: int,
    now: datetime,
) -> None:
    """Refuse confirming ``change`` unless it was drafted for this installation,
    generation and team, against ``current_revision``, and has not expired at ``now``."""
    validate_change(change)
    drafted_for = (change["installation_id"], change["install_generation"], change["team_id"])
    if drafted_for != (installation_id, install_generation, team_id):
        raise ChangeRefused(
            "the change set was drafted for another installation, generation or team",
            code="change_wrong_installation",
        )
    if change["base_revision"] != current_revision:
        raise ChangeRefused(
            "the configuration changed after this change set was drafted",
            code="base_revision_stale",
        )
    if now >= parse_utc_seconds(change["expires_at"]):
        raise ChangeRefused("the change set has expired", code="change_expired")


def check_confirmer(
    change: Mapping[str, Any],
    *,
    distinct_approver: str,
    confirmer: str,
    drafter_principal: str | None = None,
) -> None:
    """Refuse a confirmation that four eyes forbids (decision 61).

    ``distinct_approver`` is the installation's setting in force now, at
    confirmation, whatever it was when the change set was drafted. While it is
    ``required``, the confirming principal must differ from the drafter's: a
    member's principal from the change set, or, for a console draft, the
    principal behind its scope, which the caller passes as
    ``drafter_principal``. A drafter whose principal is unknown is refused."""
    if distinct_approver not in DISTINCT_APPROVER:
        raise ValueError(f"distinct_approver must be one of {sorted(DISTINCT_APPROVER)}")
    if distinct_approver == "not_required":
        return
    drafter = change["drafter"]
    drafted_by = drafter["principal"] if drafter["via"] == "team_auth" else drafter_principal
    if drafted_by is None or drafted_by == confirmer:
        raise ChangeRefused(
            "four eyes is required: the drafter cannot confirm", code="distinct_approver_required"
        )
