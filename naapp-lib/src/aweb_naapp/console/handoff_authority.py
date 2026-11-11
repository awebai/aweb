"""App-owned holding projections and caller-transaction handoff dependencies.

These types provide no authority. A factory receives the actual app callbacks;
neither a request nor a process-global registry selects their implementation.
App-issued targets and held handles pass through unchanged. Only the app's
versioned, value-free holding identity may be persisted as their binding.
"""

from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Protocol, TypeVar

from pgdbm.core import TransactionManager

from aweb_naapp.runtime.installation import AdmittedInstallation
from aweb_naapp.runtime.passkeys import PreparedCurrentApprovers


@dataclass(frozen=True)
class PublicScope:
    """A parsed public selector, not evidence of a holding or human identity."""

    installation_id: str
    role: str
    principal: str


class ScopeFields(Protocol):
    @property
    def installation_id(self) -> str: ...

    @property
    def role(self) -> str: ...

    @property
    def principal(self) -> str: ...


class CredentialTarget(Protocol):
    @property
    def public_scope(self) -> ScopeFields: ...

    @property
    def admitted(self) -> AdmittedInstallation: ...

    @property
    def team_id(self) -> str: ...

    @property
    def b3_scope(self) -> str: ...


class SessionTarget(CredentialTarget, Protocol):
    @property
    def subject(self) -> str: ...

    @property
    def holding_ref(self) -> object: ...


class PreparedSessionTarget(Protocol):
    @property
    def target(self) -> SessionTarget: ...

    @property
    def approvers(self) -> PreparedCurrentApprovers: ...

    @property
    def approver_pairs(self) -> Sequence[tuple[str, str]]: ...


_Held = TypeVar("_Held", bound=PreparedSessionTarget)
_TargetOut = TypeVar("_TargetOut", bound=SessionTarget, covariant=True)
_TargetIn = TypeVar("_TargetIn", bound=SessionTarget, contravariant=True)


class HoldSessionTarget(Protocol[_TargetIn, _Held]):
    async def __call__(
        self,
        tx: TransactionManager,
        target: _TargetIn | _Held,
        *,
        approver_pairs: Sequence[tuple[str, str]],
    ) -> _Held: ...


class CredentialTargetResolver(Protocol):
    async def __call__(self, scope: PublicScope, /, *, team_id: str) -> CredentialTarget: ...


class SessionTargetResolver(Protocol[_TargetOut]):
    async def __call__(self, scope: PublicScope, /, *, team_id: str) -> _TargetOut: ...


@dataclass(frozen=True)
class HandoffAuthority[Target: SessionTarget, Held: PreparedSessionTarget]:
    """Factory-owned dependencies with the app's exact target/handle types.

    Every projection receives the authenticated start's or retained session's
    team explicitly. Credential projection requires no holding. Browser admission
    supplies the team from the app's existing owner or holding record.
    No callback may discover a team by an installation-wide authority scan.
    Projection and remote evidence acquisition precede effect transactions.
    Hold takes F6 and all app/role locks before preparing one complete B3 pair
    union. Check uses the issued handle in that same transaction, without any
    network, row lock or rearm; callers retain their phase/transaction control.

    Holding identity is a stable app-owned public digest, not a serialization
    of holding_ref, a certificate, or permission to issue a session.
    """

    credential_target: CredentialTargetResolver
    session_target: SessionTargetResolver[Target]
    hold_session_target: HoldSessionTarget[Target, Held]
    check_session_target: Callable[[TransactionManager, Held], Awaitable[bool]]
    holding_identity: Callable[[Target], str]
