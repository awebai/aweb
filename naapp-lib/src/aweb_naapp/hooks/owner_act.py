"""The ``aweb.owner-act/1`` verifier: the team owner's signed governance act.

This is the Python reading of ``docs/owner-act.md``; the Go authority in
``cli/go/awid/owneract.go`` pins the bytes, and both pass the same public
vector with the same refusal codes and order. A verifier proves that the act
was signed by the team's current controller key, for this verifier, within its
lifetime, naming the expected subject. It cannot tell who held the key: that
only the organization owner signs, after a fresh step-up, is the signing
deployment's obligation.

The public way to verify an act is ``aweb_naapp.hooks.owner_act_nonces``:
``OwnerActVerifier.prepare`` outside any transaction, then ``consume_in`` in
the transaction that applies the act's effect, which alone returns a
``VerifiedOwnerAct``. This module holds the checks those two call; they are
private so that no caller can act on an owner act without its single-use
nonce and its exact subject.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from awid.did import public_key_from_did
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from aweb_naapp.hooks.strictjson import (
    MAX_SAFE_INTEGER,
    Refused,
    canonical,
    decode_signature,
    parse_canonical_object,
)

__all__ = ["APP_ACTS", "CORE_ACTS", "LOGS_ACTS", "PREFIX", "Refused", "VerifiedOwnerAct"]

PREFIX = b"aweb.owner-act/1\n"
MAX_LIFETIME = timedelta(minutes=10)
CLOCK_SKEW = timedelta(seconds=60)

# Each verifier accepts only its own closed vocabulary.
CORE_ACTS = ("hook-binding.activate", "hook-binding.revoke")
APP_ACTS = ("app-role.designate", "app-role.revoke", "app-credential.recover")
LOGS_ACTS = ("logs.retention.set", "logs.erase", "logs.legal-hold.set", "logs.legal-hold.release")

_TIME = "%Y-%m-%dT%H:%M:%SZ"
_MAX_ITEMS = 64
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_TEAM_ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}:[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?")
_ORIGIN = re.compile(r"https://[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?(:[0-9]{1,5})?")
_DID_KEY = re.compile(r"did:key:z[1-9A-HJ-NP-Za-km-z]{40,60}")
_NONCE = re.compile(r"[0-9a-f]{32}")
_TIME_SHAPE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_APP_ID = re.compile(r"[a-z][a-z0-9-]{0,62}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_TOKEN = re.compile(r"[a-z][a-z0-9_.-]{0,63}")
_APP_SCOPE = re.compile(r"[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}")
_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}")
_PATH = re.compile(r"/[A-Za-z0-9._~!$&'()*+,;=:@/%-]{0,511}")
_METHOD = re.compile(r"GET|HEAD|POST|PUT|PATCH|DELETE")
_HOOKS = (
    "post-secret-use-hook",
    "post-governance-hook",
    "post-manifest-command-hook",
    "post-mutation-hook",
    "post-command-hook",
)
_HOOK = re.compile("|".join(_HOOKS))
_EVENT_CLASS = re.compile("|".join(("all", *_HOOKS)))
_CATALOG_ID = re.compile(r"[a-z][a-z0-9_.-]{0,63}")


@dataclass(frozen=True)
class _Field:
    pattern: re.Pattern[str] | None = None
    integer: tuple[int, int] | None = None
    is_list: bool = False
    enum: tuple[str, ...] | None = None

    def accepts(self, value: Any) -> bool:
        if self.integer is not None:
            low, high = self.integer
            return isinstance(value, int) and not isinstance(value, bool) and low <= value <= high
        if self.is_list:
            if not isinstance(value, list) or len(value) > _MAX_ITEMS:
                return False
            if len(set(map(str, value))) != len(value):
                return False
            return all(isinstance(item, str) and self._matches(item) for item in value)
        if self.enum is not None:
            return isinstance(value, str) and value in self.enum
        return isinstance(value, str) and self._matches(value)

    def _matches(self, value: str) -> bool:
        assert self.pattern is not None
        return self.pattern.fullmatch(value) is not None


def _string(pattern: re.Pattern[str]) -> _Field:
    return _Field(pattern=pattern)


def _list(pattern: re.Pattern[str]) -> _Field:
    return _Field(pattern=pattern, is_list=True)


def _enum(*values: str) -> _Field:
    return _Field(enum=values)


def _integer(low: int, high: int) -> _Field:
    return _Field(integer=(low, high))


@dataclass(frozen=True)
class _Subject:
    """One act's subject: its fields, those it always requires, and those
    required (and otherwise refused) when another field takes a value."""

    fields: Mapping[str, _Field]
    required: tuple[str, ...]
    when: tuple[tuple[str, str, tuple[str, ...]], ...] = ()


def _app_fields(**extra: _Field) -> dict[str, _Field]:
    return {"app_id": _string(_APP_ID), "installation_id": _string(_UUID), **extra}


_BINDING = _Subject(
    fields={
        "binding_id": _string(_UUID),
        "installation_id": _string(_UUID),
        "generation": _integer(1, MAX_SAFE_INTEGER),
        "app_id": _string(_APP_ID),
        "origin": _string(_ORIGIN),
        "digest": _string(_DIGEST),
        "kind": _enum("registration", "production"),
        "catalog_id": _string(_CATALOG_ID),
        "catalog_version": _integer(1, MAX_SAFE_INTEGER),
        "hook": _string(_HOOK),
        "tool": _string(_TOKEN),
        "method": _string(_METHOD),
        "path": _string(_PATH),
        "scopes": _list(_APP_SCOPE),
        "reads": _list(_TOKEN),
    },
    required=(
        "binding_id",
        "installation_id",
        "generation",
        "app_id",
        "origin",
        "digest",
        "kind",
        "catalog_id",
        "catalog_version",
        "hook",
    ),  # fmt: skip
    when=(
        ("kind", "registration", ("tool", "method", "path", "scopes")),
        ("kind", "production", ("reads",)),
    ),
)
# A holder who does not exist yet: the app mints the subject, and the act
# commits to the enrolment contact by its SHA-256, without carrying it.
_ENROLMENT = _Subject(
    fields=_app_fields(role=_string(_TOKEN), contact_sha256=_string(_SHA256)),
    required=("app_id", "installation_id", "role", "contact_sha256"),
)
# An existing holder.
_REVOCATION = _Subject(
    fields=_app_fields(role=_string(_TOKEN), subject_ref=_string(_REF)),
    required=("app_id", "installation_id", "role", "subject_ref"),
)
_SUBJECTS: dict[str, _Subject] = {
    "hook-binding.activate": _BINDING,
    "hook-binding.revoke": _BINDING,
    "app-role.designate": _ENROLMENT,
    "app-role.revoke": _REVOCATION,
    "app-credential.recover": _ENROLMENT,
    "logs.retention.set": _Subject(
        fields=_app_fields(
            event_class=_string(_EVENT_CLASS),
            retention=_enum("keep", "days"),
            retention_days=_integer(1, 36500),
        ),
        required=("app_id", "installation_id", "event_class", "retention"),
        when=(("retention", "days", ("retention_days",)),),
    ),
    "logs.erase": _Subject(
        fields=_app_fields(
            erase_scope=_enum("actor", "range"),
            actor_ref=_string(_REF),
            chain_epoch=_integer(1, MAX_SAFE_INTEGER),
            team_seq_first=_integer(1, MAX_SAFE_INTEGER),
            team_seq_last=_integer(1, MAX_SAFE_INTEGER),
            reason_code=_string(_TOKEN),
        ),
        required=("app_id", "installation_id", "erase_scope", "reason_code"),
        when=(
            ("erase_scope", "actor", ("actor_ref",)),
            ("erase_scope", "range", ("chain_epoch", "team_seq_first", "team_seq_last")),
        ),
    ),
    "logs.legal-hold.set": _Subject(
        fields=_app_fields(
            hold_id=_string(_REF),
            hold_scope=_enum("all", "actor"),
            actor_ref=_string(_REF),
            reason_code=_string(_TOKEN),
        ),
        required=("app_id", "installation_id", "hold_id", "hold_scope", "reason_code"),
        when=(("hold_scope", "actor", ("actor_ref",)),),
    ),
    "logs.legal-hold.release": _Subject(
        fields=_app_fields(hold_id=_string(_REF)),
        required=("app_id", "installation_id", "hold_id"),
    ),
}
_FIELDS = (
    "v", "type", "act", "team_id", "aud", "team_key_did", "subject", "issued_at",
    "expires_at", "nonce",
)  # fmt: skip


@dataclass(frozen=True)
class _CheckedAct:
    """An act that passed every check up to its signature. It is not
    authority: its nonce and subject are not checked yet."""

    fields: dict[str, Any]
    act: str
    team_id: str
    audience: str
    subject: dict[str, Any]
    nonce: str
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class VerifiedOwnerAct:
    """A fully verified owner act: signed by the team's current controller key
    for this verifier, within its lifetime, naming exactly the expected
    subject, and with its nonce consumed in the effect's transaction. Only
    ``OwnerActVerifier.consume_in`` returns one. ``transaction_id`` is the
    ``txid_current()`` of that transaction: the act is authority only there.
    The conformance reading of the vector consumes nothing and sets it to None."""

    fields: dict[str, Any]
    act: str
    team_id: str
    audience: str
    subject: dict[str, Any]
    nonce: str
    issued_at: datetime
    expires_at: datetime
    transaction_id: int | None


def _check_owner_act(
    signing: bytes,
    signature: str,
    *,
    team_id: str,
    current_team_key_did: str,
    audience: str,
    acts: Sequence[str],
    now: datetime,
) -> _CheckedAct:
    """Every check up to and including the signature (steps 1 to 9 of the
    contract). The caller then checks the nonce and the expected subject."""
    if not team_id or not current_team_key_did or not audience or not acts or now is None:
        raise Refused("verifier_misconfigured", "every verifier option is required")
    if not signing.startswith(PREFIX):
        raise Refused("wrong_prefix", "signing bytes do not start with the owner-act prefix")
    act = _check_fields(parse_canonical_object(signing[len(PREFIX) :]))
    if act.team_id != team_id:
        raise Refused("team_mismatch", f"act for {act.team_id}, expected {team_id}")
    if act.audience != audience:
        raise Refused("audience_mismatch", f"act for {act.audience}")
    if act.act not in acts:
        raise Refused("act_not_allowed", f"{act.act} is not in this verifier's vocabulary")
    if act.expires_at - act.issued_at > MAX_LIFETIME:
        raise Refused("lifetime_too_long", "an owner act lives at most ten minutes")
    moment = _utc(now)
    if act.issued_at > moment + CLOCK_SKEW:
        raise Refused("not_yet_valid", f"issued at {act.fields['issued_at']}")
    if moment >= act.expires_at:
        raise Refused("expired", f"expired at {act.fields['expires_at']}")
    if act.fields["team_key_did"] != current_team_key_did:
        raise Refused("owner_required", "not signed for the team's current controller key")
    try:
        team_key = public_key_from_did(current_team_key_did)
    except ValueError:
        raise Refused("bad_signature", "the current team key does not decode") from None
    raw = decode_signature(signature)
    try:
        VerifyKey(team_key).verify(signing, raw)
    except BadSignatureError:
        raise Refused("bad_signature", "signature does not verify under the team key") from None
    return act


def _verify_owner_act(
    signing: bytes,
    signature: str,
    *,
    team_id: str,
    current_team_key_did: str,
    audience: str,
    acts: Sequence[str],
    now: datetime,
    expected_subject: Mapping[str, Any],
    nonce_used: Callable[[str], bool],
) -> VerifiedOwnerAct:
    """Every check in the contract's order, with the nonce read through
    ``nonce_used``: the conformance reading of the vector. It does not make an
    act single-use under concurrency; ``OwnerActVerifier`` does."""
    if expected_subject is None or nonce_used is None:
        raise Refused("verifier_misconfigured", "every verifier option is required")
    act = _check_owner_act(
        signing,
        signature,
        team_id=team_id,
        current_team_key_did=current_team_key_did,
        audience=audience,
        acts=acts,
        now=now,
    )
    if nonce_used(act.nonce):
        raise Refused("nonce_reused", act.nonce)
    _require_subject(act, expected_subject)
    return _verified(act, None)


def _require_subject(act: _CheckedAct, expected_subject: Mapping[str, Any]) -> None:
    """The act's subject must be exactly the stored row, compared as canonical bytes."""
    if canonical(dict(expected_subject)) != canonical(act.subject):
        raise Refused("subject_mismatch", "the act names a different subject")


def _verified(act: _CheckedAct, transaction_id: int | None) -> VerifiedOwnerAct:
    return VerifiedOwnerAct(
        fields=act.fields,
        act=act.act,
        team_id=act.team_id,
        audience=act.audience,
        subject=act.subject,
        nonce=act.nonce,
        issued_at=act.issued_at,
        expires_at=act.expires_at,
        transaction_id=transaction_id,
    )


def _check_fields(f: dict[str, Any]) -> _CheckedAct:
    for name in sorted(f):
        if name not in _FIELDS:
            raise Refused("unknown_field", name)
    for name in sorted(_FIELDS):
        if name not in f:
            raise Refused("missing_field", name)
    if f["v"] != 1 or isinstance(f["v"], bool):
        raise Refused("invalid_value", "v")
    if f["type"] != "aweb.owner-act":
        raise Refused("invalid_value", "type")
    spec = _SUBJECTS.get(f["act"]) if isinstance(f["act"], str) else None
    if spec is None:
        raise Refused("unknown_act", str(f["act"]))
    for name, pattern in (
        ("aud", _ORIGIN),
        ("expires_at", _TIME_SHAPE),
        ("issued_at", _TIME_SHAPE),
        ("nonce", _NONCE),
        ("team_id", _TEAM_ID),
        ("team_key_did", _DID_KEY),
    ):
        if not isinstance(f[name], str) or not pattern.fullmatch(f[name]):
            raise Refused("invalid_value", name)
    issued = _time(f["issued_at"], "issued_at")
    expires = _time(f["expires_at"], "expires_at")
    if expires <= issued:
        raise Refused("invalid_value", "expires_at must follow issued_at")
    try:
        public_key_from_did(f["team_key_did"])
    except ValueError:
        raise Refused("invalid_value", "team_key_did is not an Ed25519 did:key") from None
    subject = f["subject"]
    if not isinstance(subject, dict):
        raise Refused("invalid_value", "subject is not an object")
    _check_subject(spec, subject)
    first = subject.get("team_seq_first")
    if isinstance(first, int) and first > subject["team_seq_last"]:
        raise Refused("invalid_value", "subject.team_seq_last precedes team_seq_first")
    return _CheckedAct(
        fields=f,
        act=f["act"],
        team_id=f["team_id"],
        audience=f["aud"],
        subject=subject,
        nonce=f["nonce"],
        issued_at=issued,
        expires_at=expires,
    )


def _check_subject(spec: _Subject, subject: dict[str, Any]) -> None:
    conditional = {name for _, _, names in spec.when for name in names}
    required = list(spec.required)
    for field, value, names in spec.when:
        if subject.get(field) == value:
            required.extend(names)
    for name in sorted(subject):
        if name in conditional and name not in required:
            raise Refused("unknown_field", f"subject.{name}")
    optional = {
        name for name in spec.fields if name not in conditional and name not in spec.required
    }
    for name in sorted(subject):
        if name not in required and name not in optional:
            raise Refused("unknown_field", f"subject.{name}")
    for name in sorted(required):
        if name not in subject:
            raise Refused("missing_field", f"subject.{name}")
    for name in sorted(subject):
        if not spec.fields[name].accepts(subject[name]):
            raise Refused("invalid_value", f"subject.{name}")


def _time(value: str, name: str) -> datetime:
    try:
        parsed = datetime.strptime(value, _TIME)
    except ValueError:
        raise Refused("invalid_value", name) from None
    if parsed.strftime(_TIME) != value:
        raise Refused("invalid_value", name)
    return parsed


def _utc(moment: datetime) -> datetime:
    """A timezone-aware moment as naive UTC. A naive moment is refused: its
    offset is unknown, so it cannot be compared with a signed UTC time."""
    if moment.tzinfo is None:
        raise Refused("verifier_misconfigured", "now must be timezone-aware")
    return moment.astimezone(UTC).replace(tzinfo=None)
