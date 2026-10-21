"""Attributable audit events for approvals and approver credentials.

The app supplies the sink: today a log or an outbox table, later the audit-log
naapp through aw-hooks. Each event is emitted inside the transaction that makes
the change it records, so the two commit or roll back together. Events carry
references and outcomes only, never a link token, challenge, credential or
request secret.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Protocol

from pgdbm.core import TransactionManager


class AuditKind(StrEnum):
    APPROVER_DESIGNATED = "approver_designated"
    APPROVER_REDESIGNATED = "approver_redesignated"
    APPROVER_ENROLLED = "approver_enrolled"
    APPROVER_ENROLMENT_REISSUED = "approver_enrolment_reissued"
    APPROVER_RETIRED = "approver_retired"
    APPROVER_CONTACT_CHANGE_SCHEDULED = "approver_contact_change_scheduled"
    APPROVER_LOGGED_IN = "approver_logged_in"
    APPROVAL_REQUESTED = "approval_requested"
    APPROVAL_DECIDED = "approval_decided"
    APPROVAL_REVOKED = "approval_revoked"
    DISPATCH_ADMITTED = "dispatch_admitted"
    DISPATCH_OUTCOME = "dispatch_outcome"


@dataclass(frozen=True)
class AuditEvent:
    kind: AuditKind
    actor: str
    subject: str
    occurred_at: datetime
    approval_id: str | None = None
    details: Mapping[str, str] = field(default_factory=dict)


class AuditSink(Protocol):
    async def emit(self, event: AuditEvent, transaction: TransactionManager) -> None:
        """Record the event in `transaction`, the pgdbm transaction of the change."""
        ...
