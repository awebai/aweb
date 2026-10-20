"""App usage reporting, aweb.usage/1 (docs/app-usage.md).

The app is the authority for its own usage and reports it in batches signed
with its app-usage credential. This module validates a batch, computes its
report digest, checks the lifecycle grant's batch rules for a retired
installation, and builds the app-usage credential, as the contract's
conformance vectors freeze them. Deduplication, gaps and the grant's key,
installation and deadline are the collector's stateful checks.
"""

from __future__ import annotations

import base64
import hashlib
import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from awid.did import did_from_public_key
from awid.signing import canonical_json_bytes, sign_message
from awid.team_ids import parse_team_id
from nacl.signing import SigningKey

USAGE_FORMAT = "aweb.usage/1"
METRIC_VERSION = 1
REPORT_PREFIX = b"aweb.usage-report/1\n"
MAX_ENTRIES = 1000
# The collector's limit on a raw request body, checked before parsing.
MAX_BODY_BYTES = 1 << 20
SAFE_INTEGER = 2**53 - 1

COUNTERS = frozenset(
    {
        "calls",
        "pages_created",
        "pages_updated",
        "pages_deleted",
        "page_reads",
        "records_created",
        "records_updated",
        "records_deleted",
        "record_reads",
        "intents_created",
        "intents_transitioned",
        "decisions_requested",
        "decisions_answered",
        "mails_sent",
    }
)
GAUGES = frozenset(
    {
        "pages_live",
        "records_live",
        "bytes_live",
        "bytes_versions",
        "bytes_audit",
        "bytes_assets",
        "bytes_deleted_retained",
    }
)
OUTCOMES = frozenset(
    {
        "committed",
        "idempotent_noop",
        "read",
        "refused_validation",
        "refused_auth",
        "refused_policy",
        "safety_limited",
        "failed",
    }
)
SOURCES = frozenset({"cli", "mcp", "surface", "link", "sync", "background", "hook", "lifecycle"})
LIFECYCLE_COUNTERS = frozenset({"calls", "pages_deleted", "records_deleted"})

_BATCH_FIELDS = frozenset(
    {
        "format",
        "team_id",
        "app_id",
        "installation_id",
        "installation_generation",
        "reporter",
        "epoch",
        "report_id",
        "first_seq",
        "last_seq",
        "metric_version",
        "entries",
        "inventory",
    }
)
_REQUIRED_BATCH_FIELDS = _BATCH_FIELDS - {"inventory"}
_ENTRY_FIELDS = frozenset(
    {"seq", "occurred_at", "operation_id", "attempt_id", "source", "outcome", "deltas"}
)
_ID = re.compile(r"[A-Za-z0-9._-]{1,128}")
_OPAQUE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_REPORTER = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")


class UsageReportRefused(ValueError):
    """A usage report failed; ``code`` is the contract's error code."""

    def __init__(self, code: str, reason: str) -> None:
        super().__init__(f"{code}: {reason}")
        self.code = code


def _bad(reason: str) -> UsageReportRefused:
    return UsageReportRefused("schema_invalid", reason)


def _matches(pattern: re.Pattern[str], value: object) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _quantity(value: object, minimum: int = 0) -> bool:
    return (
        isinstance(value, int) and not isinstance(value, bool) and minimum <= value <= SAFE_INTEGER
    )


def _check_entry(entry: object, seq: int) -> None:
    if not isinstance(entry, Mapping) or set(entry) != _ENTRY_FIELDS:
        raise _bad("entry fields")
    if entry["seq"] != seq or not _quantity(entry["seq"], 1):
        raise _bad("entry sequence")
    stamp = entry["occurred_at"]
    if not _matches(_TIMESTAMP, stamp):
        raise _bad("occurred_at")
    try:
        datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise _bad("occurred_at") from exc
    if not (_matches(_ID, entry["operation_id"]) and _matches(_ID, entry["attempt_id"])):
        raise _bad("operation or attempt id")
    if not isinstance(entry["source"], str) or entry["source"] not in SOURCES:
        raise _bad("source")
    if not isinstance(entry["outcome"], str) or entry["outcome"] not in OUTCOMES:
        raise _bad("outcome")
    deltas = entry["deltas"]
    if not isinstance(deltas, Mapping):
        raise _bad("deltas")
    for metric, value in deltas.items():
        if not isinstance(metric, str) or metric not in COUNTERS or not _quantity(value):
            raise _bad("deltas")


def _check_inventory(inventory: object, first: int, last: int) -> None:
    if not isinstance(inventory, Mapping) or set(inventory) != GAUGES | {"at_seq"}:
        raise _bad("inventory fields")
    at_seq = inventory["at_seq"]
    if not _quantity(at_seq, 1) or not first <= at_seq <= last:
        raise _bad("inventory at_seq")
    if not all(_quantity(inventory[gauge]) for gauge in GAUGES):
        raise _bad("inventory gauges")


def validate_report(batch: object) -> None:
    """Check a report batch against docs/app-usage.md §3."""
    if not isinstance(batch, Mapping):
        raise _bad("batch is not an object")
    keys = set(batch)
    if not (_REQUIRED_BATCH_FIELDS <= keys <= _BATCH_FIELDS):
        raise _bad("batch fields")
    if batch["format"] != USAGE_FORMAT or batch["metric_version"] != METRIC_VERSION:
        raise _bad("format or metric_version")
    if not _quantity(batch["metric_version"], 1):
        raise _bad("metric_version")
    if not (_matches(_OPAQUE, batch["app_id"]) and _matches(_OPAQUE, batch["installation_id"])):
        raise _bad("app or installation")
    try:
        parse_team_id(batch["team_id"])
    except (TypeError, ValueError, AttributeError) as exc:
        raise _bad("team_id") from exc
    if not _quantity(batch["installation_generation"], 1):
        raise _bad("installation_generation")
    if not _matches(_REPORTER, batch["reporter"]) or not _matches(_ID, batch["report_id"]):
        raise _bad("reporter or report_id")
    if not _quantity(batch["epoch"], 1):
        raise _bad("epoch")
    first, last = batch["first_seq"], batch["last_seq"]
    if not (_quantity(first, 1) and _quantity(last, 1)) or first > last:
        raise _bad("sequence range")
    if last - first >= MAX_ENTRIES:
        raise _bad("too many entries")
    entries = batch["entries"]
    if not isinstance(entries, list) or len(entries) != last - first + 1:
        raise _bad("entries")
    for offset, entry in enumerate(entries):
        _check_entry(entry, first + offset)
    if "inventory" in batch:
        _check_inventory(batch["inventory"], first, last)
    try:
        canonical_json_bytes(dict(batch))
    except (UnicodeEncodeError, ValueError, TypeError) as exc:
        raise _bad("batch has no canonical form") from exc


def report_sha256(batch: Mapping[str, Any]) -> str:
    """Bare hex SHA-256 of the domain-prefixed canonical batch."""
    return hashlib.sha256(REPORT_PREFIX + canonical_json_bytes(dict(batch))).hexdigest()


def check_lifecycle_report(batch: Mapping[str, Any]) -> None:
    """The lifecycle grant's batch rules for a retired installation (§4).

    Every entry must be lifecycle work, committed, counting only calls and
    deletions. The grant's key, installation and deadline are the
    collector's checks.
    """
    for entry in batch["entries"]:
        if entry["source"] != "lifecycle" or entry["outcome"] != "committed":
            raise UsageReportRefused("scope_denied", "not a committed lifecycle entry")
        if not set(entry["deltas"]) <= LIFECYCLE_COUNTERS:
            raise UsageReportRefused("scope_denied", "a counter the lifecycle grant does not cover")


def app_usage_credential(
    *,
    signing_key: SigningKey,
    aud: str,
    method: str,
    path: str,
    team_id: str,
    app_id: str,
    kid: str,
    installation_id: str,
    installation_generation: int,
    body: bytes,
    timestamp: str,
) -> dict[str, str]:
    """Headers for one report under the app credential family's app-usage purpose."""
    did_key = did_from_public_key(bytes(signing_key.verify_key))
    payload = {
        "v": 1,
        "auth": "app-usage",
        "aud": aud,
        "method": method.upper(),
        "path": path,
        "team_id": team_id,
        "app_id": app_id,
        "kid": kid,
        "did_key": did_key,
        "installation_id": installation_id,
        "installation_generation": installation_generation,
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "timestamp": timestamp,
    }
    canonical = canonical_json_bytes(payload)
    signature = sign_message(bytes(signing_key), canonical)
    return {
        "Authorization": f"AWEB-App-Usage DIDKey {did_key} {signature}",
        "X-AWEB-App-ID": app_id,
        "X-AWEB-App-Key-ID": kid,
        "X-AWEB-Team-ID": team_id,
        "X-AWEB-Timestamp": timestamp,
        "X-AWEB-Signed-Payload": base64.urlsafe_b64encode(canonical).rstrip(b"=").decode("ascii"),
    }
