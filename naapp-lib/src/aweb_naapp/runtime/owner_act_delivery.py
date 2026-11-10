"""The shared delivery/effect interface; this module mounts no HTTP route.

The router authenticates before prepare, and owns the single effect transaction.
The human-role adapter is shared across apps and uses the canonical B3 writers.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal, Protocol

from fastapi import HTTPException
from pgdbm import TransactionManager

from aweb_naapp.hooks.owner_act import HumanCredential, VerifiedOwnerAct
from aweb_naapp.runtime.human_member import HumanMemberProof
from aweb_naapp.runtime.installation import AdmittedInstallation

__all__ = [
    "CheckedHumanRoleMember",
    "OwnerActDelivery",
    "OwnerActDeliveryCode",
    "OwnerActDeliveryRefused",
    "OwnerActEffect",
    "OwnerActEffectResult",
    "PreparedOwnerActEffect",
]

OwnerActDeliveryCode = Literal[
    "owner_required",
    "principal_not_member",
    "principal_not_human",
    "principal_status_unavailable",
]


class OwnerActDeliveryRefused(Exception):
    """A typed effect refusal, mapped to HTTP only by the delivery router.

    principal_status_unavailable maps to 503; the other codes map to 403.
    No request input or underlying verifier detail is reflected to the caller.
    """

    def __init__(self, code: OwnerActDeliveryCode) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class CheckedHumanRoleMember:
    """The exact supplied signed JSON bytes and their original H2 proof.

    Identity fields come from the proof, not from values beside it. This is
    trusted process-local evidence, never a request DTO or role authority.
    """

    certificate: bytes
    proof: HumanMemberProof

    @property
    def team_id(self) -> str:
        return self.proof.team_id

    @property
    def principal(self) -> str:
        return self.proof.principal

    def require_fresh(self) -> None:
        """Check the original deadline without renewing or acquiring evidence."""
        try:
            self.proof.require_fresh()
        except HTTPException:
            raise OwnerActDeliveryRefused("principal_status_unavailable") from None


@dataclass(frozen=True)
class OwnerActDelivery:
    """Parsed input, NOT authority; only consume_in produces VerifiedOwnerAct.

    certificate is the decoded signed JSON artifact, not its base64 transport.
    It is required for designate/replace and absent for revoke. The HTTP parser
    owns presence/encoding checks and uses the existing HumanCredential parser.
    """

    act: str
    team_id: str
    subject: Mapping[str, Any]
    credential: HumanCredential | None
    notice_contact: str | None
    certificate: bytes | None


@dataclass(frozen=True)
class OwnerActEffectResult:
    act: str
    role: str
    principal: str
    effective_at: datetime


class OwnerActEffect(Protocol):
    async def prepare(
        self, *, installation: AdmittedInstallation, delivery: OwnerActDelivery
    ) -> PreparedOwnerActEffect:
        """After signature authentication, before every effect lock.

        Close any local preflight transaction before H2/network work. Retain
        the exact checked artifact and original proof for designate/replace;
        revoke performs no holder membership/kind lookup. Return a NEW prepared
        object per delivery; it is never shared across requests or retries.
        """
        ...


class PreparedOwnerActEffect(Protocol):
    """One delivery's preparation, writes and post-commit notices.

    The object retains the writer's Designation/notices between apply and
    after_commit. The router uses it once and never reuses it for another act.
    """

    @property
    def expected_subject(self) -> Mapping[str, Any]:
        """Independently built input to OwnerActVerifier.consume_in.

        Build from admitted app/installation, the declared role, target
        principal and actual canonical credential/contact inputs. Returning
        delivery.subject unchanged does not independently bind these inputs.
        """
        ...

    async def apply(
        self,
        tx: TransactionManager,
        *,
        installation: AdmittedInstallation,
        act: VerifiedOwnerAct,
    ) -> OwnerActEffectResult:
        """Use the router's original F6-fenced transaction and consumed act.

        Bind the complete prepared subject, act/team/principal and exact
        certificate to the original evidence. Take prepare_retirement at entry
        for replace/revoke BEFORE any role/holding/B3/S4 hold. designate_holder
        refuses an existing holding/approver and retires nothing, so needs no
        retirement gate. No role/B3/S4 locks may precede this call.

        Canonical writer, app SQL hook and governance enqueue all use tx. No
        remote work or second checkout occurs under these effect locks.
        """
        ...

    def require_fresh(self) -> None:
        """Last synchronous check before commit, with original deadlines.

        After all apply/app/governance awaits, the router first checks its
        already-held F6 fence again (no refresh/upgrade), then calls this.
        Check the original H2 deadline AND consumed act's validity window;
        installation freshness is enforced by that final existing fence check.
        Never obtain fresh proof here. A refusal rolls back nonce and effects.
        """
        ...

    async def after_commit(self, result: OwnerActEffectResult) -> None:
        """Send retained notices only AFTER a successful commit.

        Governance is enqueued inside apply, not here. Failure to send a notice
        cannot report that the committed effect rolled back. Process death may
        lose these notices; security-critical delivery needs a durable outbox.
        """
        ...
