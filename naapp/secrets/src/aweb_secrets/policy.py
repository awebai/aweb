"""secrets policies: immutable records addressed by the digest of their canonical form.

A grant references a policy by digest, and every audit event carries it. The
digest is the SHA-256 of ``aweb.secrets.policy/1\\n`` followed by the canonical
JSON of the policy body (sorted keys, no whitespace, UTF-8), so a policy can
never be edited in place: a changed field is a different policy.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, time
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError, available_timezones

from awid.signing import canonical_json_bytes

DIGEST_PREFIX = b"aweb.secrets.policy/1\n"

APPROVALS = ("none", "per_use")
DISTINCT_APPROVER = ("required", "not_required")
RATE_SCOPES = ("principal_secret", "secret")
CHANNELS = ("mcp_l2", "dashboard", "api")
DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
MAX_APPROVAL_TTL_S = 86_400
MAX_RESULT_BYTES = 16 * 1024 * 1024

FIELDS = frozenset(
    {
        "approval",
        "approvers",
        "approval_ttl_s",
        "rate",
        "windows",
        "operations",
        "open_request",
        "result",
        "requires_attestation",
        "distinct_approver",
    }
)

IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
DIGEST = re.compile(r"[0-9a-f]{64}")
_CLOCK = re.compile(r"([01][0-9]|2[0-3]):[0-5][0-9]")


class PolicyInvalid(ValueError):
    """The policy body does not have the policy shape."""


@dataclass(frozen=True)
class AttestationFacts:
    """What a verified ``aweb.principal-attestation/1`` asserts about a request."""

    custodian_id: str
    channel: str
    human_principal: str | None


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise PolicyInvalid(message)


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _exact_keys(value: Any, keys: frozenset[str], what: str) -> Mapping[str, Any]:
    _require(
        isinstance(value, Mapping) and set(value) == keys, f"{what} needs exactly {sorted(keys)}"
    )
    return value


def _check_rate(rate: Any) -> None:
    _require(isinstance(rate, list), "rate is a list of buckets")
    scopes = [
        _exact_keys(bucket, frozenset({"per", "capacity", "window_s"}), "a rate bucket")["per"]
        for bucket in rate
    ]
    _require(
        all(scope in RATE_SCOPES for scope in scopes),
        "a rate bucket counts per principal_secret or per secret",
    )
    _require(len(set(scopes)) == len(scopes), "each rate scope has one bucket")
    for bucket in rate:
        _require(
            _is_int(bucket["capacity"]) and bucket["capacity"] >= 1,
            "a bucket's capacity is a positive integer",
        )
        _require(
            _is_int(bucket["window_s"]) and bucket["window_s"] >= 1,
            "a bucket's window is a positive integer",
        )


def _zone(name: Any) -> ZoneInfo:
    _require(
        isinstance(name, str) and name in available_timezones(), "windows need an IANA time zone"
    )
    try:
        return ZoneInfo(name)
    except ZoneInfoNotFoundError:
        raise PolicyInvalid("windows need an IANA time zone") from None


def _clock(value: Any) -> time:
    _require(
        isinstance(value, str) and _CLOCK.fullmatch(value) is not None, "a window bound is HH:MM"
    )
    return time.fromisoformat(value)


def _check_windows(windows: Any) -> None:
    if windows is None:
        return
    windows = _exact_keys(windows, frozenset({"time_zone", "ranges"}), "windows")
    _zone(windows["time_zone"])
    _require(
        isinstance(windows["ranges"], list) and len(windows["ranges"]) > 0,
        "windows need at least one range",
    )
    for window in windows["ranges"]:
        window = _exact_keys(window, frozenset({"days", "from", "to"}), "a window range")
        days = window["days"]
        _require(
            isinstance(days, list)
            and len(days) > 0
            and len(set(days)) == len(days)
            and all(d in DAYS for d in days),
            "a window range names its weekdays",
        )
        _require(
            _clock(window["from"]) < _clock(window["to"]), "a window range starts before it ends"
        )


def _check_operations(operations: Any) -> None:
    _require(isinstance(operations, list), "operations is a list")
    for operation in operations:
        operation = _exact_keys(
            operation, frozenset({"operation_id", "digest"}), "an allowed operation"
        )
        _require(
            isinstance(operation["operation_id"], str)
            and IDENTIFIER.fullmatch(operation["operation_id"]) is not None,
            "an operation id is a lowercase slug",
        )
        _require(
            isinstance(operation["digest"], str)
            and DIGEST.fullmatch(operation["digest"]) is not None,
            "an operation digest is 64 lowercase hex characters",
        )
    pairs = [(o["operation_id"], o["digest"]) for o in operations]
    _require(len(set(pairs)) == len(pairs), "an operation is allowed once")


def _check_attestation(predicates: Any) -> None:
    if predicates is None:
        return
    _require(
        isinstance(predicates, Mapping)
        and len(predicates) > 0
        and set(predicates) <= {"custodial_via", "channels", "human_principal"},
        "requires_attestation is null or a non-empty set of predicates",
    )
    if "custodial_via" in predicates:
        _require(
            isinstance(predicates["custodial_via"], str) and predicates["custodial_via"] != "",
            "custodial_via names a custodian",
        )
    if "channels" in predicates:
        channels = predicates["channels"]
        _require(
            isinstance(channels, list)
            and len(channels) > 0
            and len(set(channels)) == len(channels)
            and all(channel in CHANNELS for channel in channels),
            "channels lists attested channels",
        )
    if "human_principal" in predicates:
        _require(predicates["human_principal"] is True, "human_principal can only be required")


def _check(body: Any) -> None:
    _exact_keys(body, FIELDS, "a policy")
    _require(body["approval"] in APPROVALS, "approval is none or per_use")
    approvers = body["approvers"]
    _require(
        isinstance(approvers, list)
        and all(isinstance(a, str) and a for a in approvers)
        and len(set(approvers)) == len(approvers),
        "approvers is a list of approver ids",
    )
    _require(body["approval"] == "none" or bool(approvers), "per_use approval needs an approver")
    ttl = body["approval_ttl_s"]
    _require(_is_int(ttl) and 1 <= ttl <= MAX_APPROVAL_TTL_S, "approval_ttl_s is 1 s to one day")
    _check_rate(body["rate"])
    _check_windows(body["windows"])
    _check_operations(body["operations"])
    _require(isinstance(body["open_request"], bool), "open_request is a boolean")
    result = _exact_keys(body["result"], frozenset({"max_bytes"}), "result")
    _require(
        _is_int(result["max_bytes"]) and 1 <= result["max_bytes"] <= MAX_RESULT_BYTES,
        "result.max_bytes is 1 byte to 16 MiB",
    )
    _check_attestation(body["requires_attestation"])
    _require(
        body["distinct_approver"] in DISTINCT_APPROVER,
        "distinct_approver is required or not_required",
    )


def policy_digest(body: Mapping[str, Any]) -> str:
    return hashlib.sha256(DIGEST_PREFIX + canonical_json_bytes(dict(body))).hexdigest()


@dataclass(frozen=True)
class Policy:
    body: Mapping[str, Any]
    digest: str

    @classmethod
    def from_body(cls, body: Mapping[str, Any]) -> Policy:
        """The policy for ``body``, refused with :class:`PolicyInvalid` unless it has the policy shape."""
        _check(body)
        return cls(body=body, digest=policy_digest(body))

    @property
    def requires_attestation(self) -> bool:
        return self.body["requires_attestation"] is not None

    def window_open(self, instant: datetime) -> bool:
        """Whether ``instant`` falls inside one of the policy's windows, in its time zone."""
        if instant.tzinfo is None:
            raise ValueError("a window is evaluated at an aware instant")
        windows = self.body["windows"]
        if windows is None:
            return True
        local = instant.astimezone(ZoneInfo(windows["time_zone"]))
        day = DAYS[local.weekday()]
        clock = local.time().replace(tzinfo=None)
        return any(
            day in window["days"]
            and time.fromisoformat(window["from"]) <= clock < time.fromisoformat(window["to"])
            for window in windows["ranges"]
        )

    def attestation_satisfied(self, facts: AttestationFacts | None) -> bool:
        """Whether a verified attestation meets the policy's predicates; none is needed without them."""
        predicates = self.body["requires_attestation"]
        if predicates is None:
            return True
        if facts is None:
            return False
        if "custodial_via" in predicates and facts.custodian_id != predicates["custodial_via"]:
            return False
        if "channels" in predicates and facts.channel not in predicates["channels"]:
            return False
        return not ("human_principal" in predicates and facts.human_principal is None)

    @property
    def allowed_operations(self) -> Sequence[tuple[str, str]]:
        return [(o["operation_id"], o["digest"]) for o in self.body["operations"]]
