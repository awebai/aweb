"""Chat is for agents; authoritative human recipients are reached by mail."""
from __future__ import annotations

import asyncio
import logging
from uuid import uuid4

from awid.id_certificates import verify_id_chain
from aweb.service_errors import ValidationError

logger = logging.getLogger(__name__)


class HumanChatRefused(ValidationError):
    reason = 'recipient_human_mail_only'

    def __init__(self, recipient: str):
        super().__init__(
            f'{recipient} is a person; aweb reaches people by mail: aw mail send --to {recipient}'
        )

    def body(self, *, correlation_id: str | None = None) -> dict:
        return dict(detail=self.detail, reason=self.reason, retryable=False,
                    correlation_id=correlation_id or str(uuid4()))


def recipient_label(row: dict) -> str:
    return str(row.get('address') or row.get('alias') or row.get('did_aw')
               or row.get('did') or row.get('did_key') or 'recipient')


async def require_agent_chat(db, recipients: list[dict], *, registry_client=None) -> None:
    """Unknown kind is allowed. Names and missing evidence never imply human.

    Team projections can establish a human type, but do not select a thread's
    identity. Remote/global evidence uses the public current chain verifier;
    nearest_human on an AGENT certificate does not make the agent a human.
    """
    manager = db.get_manager('aweb')
    for row in recipients:
        did = str(row.get('did_aw') or row.get('did') or row.get('did_key') or '').strip()
        if not did:
            continue
        human = await manager.fetch_one(
            """SELECT 1 FROM {{tables.agents}} WHERE deleted_at IS NULL
                 AND agent_type='human'
                 AND ((did_aw=$1 AND did_aw_verified_key=did_key)
                      OR did_key=$1)
               LIMIT 1""", did,
        )
        if human:
            raise HumanChatRefused(recipient_label(row))
        resolve = getattr(registry_client, 'resolve_key_fresh', None)
        evidence_for = getattr(registry_client, 'id_chain_evidence', None)
        if not did.startswith('did:aw:') or not callable(resolve) or not callable(evidence_for):
            continue
        try:
            async with asyncio.timeout(5):
                resolution = await resolve(did)
                key = str(row.get('did_key') or row.get('current_did_key') or '')
                if resolution.did_aw != did or resolution.current_did_key != key:
                    continue
                enrollment = resolution.id_tree
                if enrollment is None or not enrollment.enrolled:
                    continue
                subject = dict(id=did, did_key=key)
                evidence = await evidence_for(None, subject, domain=enrollment.domain)
                result = verify_id_chain(None, subject=subject, evidence=evidence, domain=enrollment.domain)
        except Exception:
            # This optional kind lookup neither grants delivery nor changes its
            # existing authority checks. Unavailable kind evidence is unknown.
            logger.warning('Chat recipient kind unavailable for %s', did, exc_info=True)
            continue
        if result['identity_valid'] is True and result['kind'] == 'human':
            raise HumanChatRefused(recipient_label(row))
