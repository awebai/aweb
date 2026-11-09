"""Chat is for agents; authoritative human recipients are reached by mail."""
from __future__ import annotations

from aweb.human_kind import human_predicate_sql

from uuid import uuid4

from aweb.service_errors import ValidationError


class HumanChatRefused(ValidationError):
    reason = 'recipient_human_mail_only'

    def __init__(self, recipient: str | list[str]):
        values = [recipient] if isinstance(recipient, str) else recipient
        self.recipients = sorted({value.strip() for value in values if value.strip()})
        if len(self.recipients) == 1:
            description = f'{self.recipients[0]} is a person'
        elif self.recipients:
            description = f'{", ".join(self.recipients)} are people'
        else:
            description = 'This chat includes a person'
        target = self.recipients[0] if self.recipients else '<their alias>'
        super().__init__(f'{description}; aweb reaches people by mail: aw mail send --to {target}')

    def body(self, *, correlation_id: str | None = None) -> dict:
        return dict(detail=self.detail, reason=self.reason, retryable=False,
                    correlation_id=correlation_id or str(uuid4()), recipients=self.recipients)


def recipient_label(row: dict) -> str:
    return str(row.get('address') or row.get('alias') or row.get('did_aw')
               or row.get('did') or row.get('did_key') or '')


async def require_agent_chat(db, recipients: list[dict], *, registry_client=None) -> None:
    """Refuse verified-human projections; unknown kind remains allowed.

    This policy preflight deliberately performs no registry I/O. The retained
    registry_client keyword is source compatibility only. Strict federation
    resolution remains the sole outbound authority path; receivers apply their
    own verified-human refusal. Local projections come from verified connect
    and the required cutover revalidation, never a fresh per-send ancestry claim.
    """
    manager = db.get_manager('aweb')
    humans = []
    for row in recipients:
        did = str(row.get('did_aw') or row.get('did') or row.get('did_key') or '').strip()
        if not did:
            continue
        human = await manager.fetch_one(
            f"""SELECT 1 FROM {{{{tables.agents}}}} WHERE deleted_at IS NULL
                 AND {human_predicate_sql()}
                 AND ((did_aw=$1 AND did_aw_verified_key=did_key)
                      OR did_key=$1)
               LIMIT 1""", did,
        )
        if human:
            humans.append(recipient_label(row))
            continue
    if humans:
        raise HumanChatRefused(humans)
