"""The broker's value-free durable receipt, distinct from its live response."""

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from aweb_naapp.dispatch import State
from aweb_secrets_values import ValueInvalid, ValueInvalidReason
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager

from aweb_secrets.member_types import ToolReply

NOT_SENT_MESSAGE = (
    "The request was not sent. Check the secret and destination configuration, then resubmit."
)
_NOT_SENT_MESSAGES = frozenset(
    {NOT_SENT_MESSAGE, *(str(ValueInvalid(reason)) for reason in ValueInvalidReason)}
)

_IDENTITY = (
    "request_id",
    "request_ref",
    "reconcile_ref",
    "control_approval_id",
    "control_approval_ref",
)
_COUNTS = ("status", "upstream_bytes", "redaction_count")
_FLAGS = ("truncated", "undeclared_credential", "upstream_truncated")
_MACS = ("upstream_response_hmac", "returned_hmac")


def not_sent_message(body: Mapping[str, Any]) -> str | None:
    """Project only a fixed, value-free pre-send remedy (§7.6)."""
    message = body.get("message")
    if (
        body.get("state") == State.NOT_SENT
        and isinstance(message, str)
        and message in _NOT_SENT_MESSAGES
    ):
        return message
    return None


def durable_broker_receipt(
    reply: ToolReply,
    audit: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Copy a closed metadata projection, never an entity or upstream header.

    Only the initiating request receives broker_result_reply's live bytes.
    This same boundary serves winning outcomes and late observations.
    """
    body: dict[str, Any] = {"state": reply.body["state"]}
    for name in _IDENTITY:
        if name in reply.body:
            body[name] = reply.body[name]
    if "code" in reply.body:
        body["code"] = reply.body["code"]
    if "next" in reply.body:
        body["next"] = reply.body["next"]
    message = not_sent_message(reply.body)
    if message is not None:
        body["message"] = message
    live = reply.body.get("result")
    if isinstance(live, Mapping):
        metadata: dict[str, Any] = {"body": None, "headers": None}
        for name in (*_COUNTS, *_FLAGS):
            if name in live:
                metadata[name] = live[name]
        if audit is not None:
            for name in (*_MACS, "disposition", "undeclared_credential", "upstream_truncated"):
                if name in audit:
                    metadata[name] = audit[name]
        body["result"] = metadata
    return body


async def prepare_legacy_broker_outcomes(db: AsyncDatabaseManager) -> None:
    """Recorded app purge BEFORE shared S3 imports immutable legacy snapshots.

    Fresh schemas have no old rows. The migration records that fact too.
    Shared migrations neither know these tables nor guess broker/run identity.
    """
    await AsyncMigrationManager(
        db,
        migrations_path=str(Path(__file__).parent / "broker_outcome_migrations"),
        module_name="aweb_secrets_broker_outcomes",
    ).apply_pending_migrations()
