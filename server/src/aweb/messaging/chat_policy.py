"""Chat is for agents; authoritative human recipients are reached by mail."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from aweb.identity_binding import verified_key_sql

from aweb.human_kind import human_predicate_sql, is_verified_human

from uuid import uuid4

from aweb.service_errors import ValidationError


class HumanChatRefused(ValidationError):
    reason = "recipient_human_mail_only"

    def __init__(self, recipient: str | list[str]):
        values = [recipient] if isinstance(recipient, str) else recipient
        self.recipients = sorted({value.strip() for value in values if value.strip()})
        if len(self.recipients) == 1:
            description = f"{self.recipients[0]} is a person"
        elif self.recipients:
            description = f"{', '.join(self.recipients)} are people"
        else:
            description = "This chat includes a person"
        target = self.recipients[0] if self.recipients else "<their alias>"
        super().__init__(f"{description}; aweb reaches people by mail: aw mail send --to {target}")

    def body(self, *, correlation_id: str | None = None) -> dict:
        return dict(
            detail=self.detail,
            reason=self.reason,
            retryable=False,
            correlation_id=correlation_id or str(uuid4()),
            recipients=self.recipients,
        )


def recipient_label(row: Mapping[str, Any]) -> str:
    """Choose an actionable recipient label without treating it as identity authority."""
    return str(
        row.get("address")
        or row.get("alias")
        or row.get("did_aw")
        or row.get("did")
        or row.get("did_key")
        or ""
    )


async def require_agent_chat(
    db,
    recipients: Sequence[Mapping[str, Any]],
    *,
    locked_policy_rows: Mapping[str, Sequence[Mapping[str, Any]]] | None = None,
) -> None:
    """Refuse verified-human projections; unknown kind remains allowed.

    docs/mail-and-chat.md:12-15 keeps recipient kind independent of membership.
    This policy preflight deliberately performs no registry I/O. Strict federation
    resolution remains the sole outbound authority path; receivers apply their
    own verified-human refusal. Local projections come from verified connect
    and the required cutover revalidation, never a fresh per-send ancestry claim.
    """
    manager = db.get_manager("aweb")
    humans = []
    for row in recipients:
        did = str(row.get("did_aw") or row.get("did") or row.get("did_key") or "").strip()
        if not did:
            continue
        if locked_policy_rows is not None and did in locked_policy_rows:
            # These rows include raw DID claims. Only the verified projection
            # of a stable DID or the literal key can establish human kind.
            human = any(
                is_verified_human(policy) and did in (policy.get("did_aw"), policy.get("did_key"))
                for policy in locked_policy_rows[did]
            )
        else:
            human = await manager.fetch_one(
                f"""SELECT 1 FROM {{{{tables.agents}}}} WHERE deleted_at IS NULL
                     AND {human_predicate_sql()}
                     AND ((did_aw=$1 AND {verified_key_sql()})
                          OR did_key=$1)
                   LIMIT 1""",
                did,
            )
        if human:
            humans.append(recipient_label(row))
            continue
    if humans:
        raise HumanChatRefused(humans)
