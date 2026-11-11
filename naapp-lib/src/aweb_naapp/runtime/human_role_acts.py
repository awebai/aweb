"""The one human-role effect every app mounts behind the owner-act delivery
route (owner-act-delivery.md, Effects): ``human-role.designate``,
``human-credential.replace`` and ``human-role.revoke`` for the roles the app
declares with the human-role acts, and the retirement of those holdings with
the app's installation.

The route authenticates the act and owns the one effect transaction. This
effect checks the member before every lock, applies the canonical holder
writer in the route's transaction under the recorder's prepared act, and sends
the writer's notices only after the commit.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from pgdbm.core import TransactionManager

from aweb_naapp import roles
from aweb_naapp.hooks.owner_act import HumanCredential, VerifiedOwnerAct
from aweb_naapp.runtime.credential_audit import CredentialAudit
from aweb_naapp.runtime.installation import AdmittedInstallation
from aweb_naapp.runtime.owner_act_delivery import (
    CheckedHumanRoleMember,
    OwnerActDelivery,
    OwnerActDeliveryRefused,
    OwnerActEffectResult,
)
from aweb_naapp.runtime.passkeys import (
    Designation,
    DesignationRefused,
    Passkeys,
    RetiredSubjects,
    RetiringInstallation,
    contact_sha256,
    prepare_retirement,
    retire_subjects,
)
from aweb_naapp.runtime.passkeys.service import (
    HOLDER_DESIGNATE_ACT,
    HOLDER_REPLACE_ACT,
    HOLDER_REVOKE_ACT,
)

__all__ = ["CheckMember", "HumanRoleActs"]

type CheckMember = Callable[..., Awaitable[CheckedHumanRoleMember]]
type AppliedHook = Callable[[TransactionManager, OwnerActEffectResult], Awaitable[None]]

# The acts that hold a role with a credential, and so carry a certificate.
_HOLDING_ACTS = frozenset({HOLDER_DESIGNATE_ACT, HOLDER_REPLACE_ACT})


def _utcnow() -> datetime:
    return datetime.now(UTC)


class HumanRoleActs:
    """The app's effect for the human-role acts of the roles it declares.

    ``check_member`` is the runtime's ``check_human_role_member``. A role in
    ``notice_roles`` takes no act that names no notice contact. ``on_applied``
    is the app's own write, run in the effect's transaction after the holder
    writer, such as bumping a configuration revision.
    """

    def __init__(
        self,
        *,
        roles: frozenset[str],
        passkeys: Passkeys,
        recorder: CredentialAudit,
        check_member: CheckMember,
        notice_roles: frozenset[str] = frozenset(),
        on_applied: AppliedHook | None = None,
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        if not notice_roles <= roles:
            raise ValueError("a notice role must be a declared human role")
        self._roles = roles
        self._notice_roles = notice_roles
        self._passkeys = passkeys
        self._recorder = recorder
        self._check_member = check_member
        self._on_applied = on_applied
        self._clock = clock

    async def prepare(
        self, *, installation: AdmittedInstallation, delivery: OwnerActDelivery
    ) -> PreparedHumanRoleAct:
        """Check the delivery against the app's declaration and, for an act
        that holds a role, the member and their certificate, before any lock.
        A revoke reads no membership: a holder who left the team is revoked
        too."""
        act = delivery.act
        role = delivery.subject.get("role")
        principal = delivery.subject.get("principal")
        if (
            act not in _HOLDING_ACTS | {HOLDER_REVOKE_ACT}
            or delivery.team_id != installation.team_id
            or not isinstance(role, str)
            or role not in self._roles
            or not isinstance(principal, str)
        ):
            raise OwnerActDeliveryRefused("owner_required")
        member = None
        if act in _HOLDING_ACTS:
            if (
                delivery.credential is None
                or delivery.certificate is None
                or (role in self._notice_roles and delivery.notice_contact is None)
            ):
                raise OwnerActDeliveryRefused("owner_required")
            member = await self._check_member(
                installation.team_id, principal=principal, certificate=delivery.certificate
            )
        elif (
            delivery.credential is not None
            or delivery.certificate is not None
            or delivery.notice_contact is not None
        ):
            raise OwnerActDeliveryRefused("owner_required")
        context = await self._recorder.prepare_owner_act(
            installation, signing=delivery.signing, signature=delivery.signature
        )
        return PreparedHumanRoleAct(
            self,
            installation=installation,
            act=act,
            role=role,
            principal=principal,
            credential=delivery.credential,
            notice_contact=delivery.notice_contact,
            member=member,
            context=context,
        )

    async def retire(
        self, tx: TransactionManager, *, app_id: str, team_id: str
    ) -> list[RetiredSubjects]:
        """End every holding of the team and destroy its holders' credentials,
        in the installation fence's retirement transaction: the holdings'
        scopes are read first, then the team's roles and holdings are purged,
        then the scopes' subjects are retired, by installation."""
        scopes = await roles.holding_scopes_of_team(tx, team_id)
        await roles.purge_team(tx, team_id)
        return [
            await retire_subjects(
                tx,
                installation=RetiringInstallation(
                    app_id=app_id, team_id=team_id, installation_id=installation_id
                ),
                scopes=installation_scopes,
            )
            for installation_id, installation_scopes in sorted(scopes.items())
        ]


@dataclass(eq=False)
class PreparedHumanRoleAct:
    """One delivery's preparation: never shared across deliveries."""

    _acts: HumanRoleActs
    installation: AdmittedInstallation
    act: str
    role: str
    principal: str
    credential: HumanCredential | None
    notice_contact: str | None
    member: CheckedHumanRoleMember | None
    context: Any
    _consumed: VerifiedOwnerAct | None = field(default=None, init=False)
    _designation: Designation | None = field(default=None, init=False)

    @property
    def expected_subject(self) -> Mapping[str, Any]:
        subject: dict[str, Any] = {
            "app_id": self.installation.app_id,
            "installation_id": self.installation.installation_id,
            "role": self.role,
            "principal": self.principal,
        }
        if self.credential is not None:
            subject["credential_sha256"] = self.credential.sha256
        if self.notice_contact is not None:
            subject["notice_contact_sha256"] = contact_sha256(self.notice_contact)
        return subject

    async def apply(
        self,
        tx: TransactionManager,
        *,
        installation: AdmittedInstallation,
        act: VerifiedOwnerAct,
    ) -> OwnerActEffectResult:
        if (
            self._consumed is not None
            or installation != self.installation
            or act.act != self.act
            or act.team_id != installation.team_id
            or act.subject != self.expected_subject
        ):
            raise OwnerActDeliveryRefused("owner_required")
        self._consumed = act
        if self.act != HOLDER_DESIGNATE_ACT:
            await prepare_retirement(tx, installation=installation)
        passkeys = self._acts._passkeys
        with self._acts._recorder.prepared(self.context):
            try:
                if self.act == HOLDER_REVOKE_ACT:
                    await passkeys.revoke_holder(tx, act=act)
                    effective_at = self._acts._clock()
                else:
                    assert self.member is not None and self.credential is not None
                    writer = (
                        passkeys.designate_holder
                        if self.act == HOLDER_DESIGNATE_ACT
                        else passkeys.replace_holder_credential
                    )
                    designation = await writer(
                        tx,
                        act=act,
                        credential=self.credential,
                        certificate=self.member.certificate,
                        notice_contact=self.notice_contact,
                    )
                    self._designation = designation
                    effective_at = designation.effective_at
            except DesignationRefused:
                raise OwnerActDeliveryRefused("owner_required") from None
        result = OwnerActEffectResult(self.act, self.role, self.principal, effective_at)
        if self._acts._on_applied is not None:
            await self._acts._on_applied(tx, result)
        return result

    def require_fresh(self) -> None:
        if self._consumed is None:
            raise OwnerActDeliveryRefused("owner_required")
        if self.member is not None:
            self.member.require_fresh()
        now = self._acts._clock().astimezone(UTC).replace(tzinfo=None)
        if now >= self._consumed.expires_at:
            raise OwnerActDeliveryRefused("owner_required")

    async def after_commit(self, result: OwnerActEffectResult) -> None:
        if self._designation is not None:
            await self._acts._passkeys.deliver(self._designation)
