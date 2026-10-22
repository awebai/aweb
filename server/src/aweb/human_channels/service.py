"""Public embedding ports frozen by P0; supplied by P2b/P3–P9, not implemented here.

Record schemas and semantics are in docs/human-channels-contract-v1.md. None of
these Protocols is an authorization adapter or an implementation stub service.
"""
from __future__ import annotations

from typing import AsyncContextManager, Protocol, TYPE_CHECKING
from .contract import ContractRecord

if TYPE_CHECKING:
    from aweb.identity_auth_deps import MessagingAuth
    from asyncpg import Connection


class HumanChannelsUnitOfWork(Protocol):
    """One owned PostgreSQL transaction; rollback on failure or unfinished ingress.

    The service owns commit. Embedders may write only their own data using this
    exact connection. They must not begin/commit independently or access OSS SQL.
    Network calls, signer/key lookup and event publication are outside the lock.
    """
    @property
    def transaction(self) -> Connection:
        """The supported asyncpg connection for caller-owned persistence only."""
        ...

    async def claim_ingress(self, key: ContractRecord) -> ContractRecord | None:
        """IngressKey -> original result or new transaction-local claim.

        key.issuer must equal this UoW's authenticated principal, never a caller
        chosen namespace. Refuse mismatch before effects or result disclosure.
        """
        ...

    async def accept(self, prepared: ContractRecord) -> ContractRecord:
        """PreparedSend -> provisional AcceptedSend; rechecks under session lock."""
        ...

    async def finish_ingress(self, result: ContractRecord) -> None:
        """IngressResult: once per new claim, same key/input/message; no private IDs on wire."""
        ...


class HumanChannelsService(Protocol):
    """All calls take verified existing messaging auth, never a claimed owner ID."""
    async def capabilities(self, auth: MessagingAuth) -> ContractRecord:
        """Capabilities: implemented/enabled/refused, not just package version."""
        ...

    async def resolve(self, auth: MessagingAuth, request: ContractRecord) -> ContractRecord:
        """ResolveRequest -> AuthorityFacts, selected team/participant only."""
        ...

    async def prepare(self, auth: MessagingAuth, request: ContractRecord) -> ContractRecord:
        """PrepareRequest -> PreparedSend; crypto/I/O now, current-authority recheck at accept."""
        ...

    def unit_of_work(self, auth: MessagingAuth) -> AsyncContextManager[HumanChannelsUnitOfWork]:
        ...

    async def ingress_result(self, auth: MessagingAuth, key: ContractRecord) -> ContractRecord:
        """IngressKey -> IngressResult; issuer must equal authenticated principal.

        Current authority is required; another issuer's result is not disclosed.
        """
        ...

    async def list(self, auth: MessagingAuth, request: ContractRecord) -> ContractRecord:
        """PageRequest -> PageResult: ALL authorized mail/session/message handles, not just pair UI."""
        ...

    async def session(self, auth: MessagingAuth, session_id: str) -> ContractRecord:
        """SessionView; current member/key/bridge/history-control context."""
        ...

    async def create_session(self, auth: MessagingAuth, request: ContractRecord) -> ContractRecord:
        """SessionCreate -> SessionView after owner/recipient/disclosure consent."""
        ...

    async def change_membership(self, auth: MessagingAuth, intent: ContractRecord) -> ContractRecord:
        """SignedArtifact of MembershipIntent -> SessionView; add/remove/leave/delegate/transfer/history."""
        ...

    async def checkpoint(self, auth: MessagingAuth, intent: ContractRecord) -> ContractRecord:
        """SignedArtifact of CheckpointIntent -> signed CheckpointReceipt or NarrowStopAck."""
        ...

    async def checkpoint_receipt(self, auth: MessagingAuth, session_id: str, transition_id: str) -> ContractRecord:
        """Original signed CheckpointReceipt; public control-history grant required."""
        ...

    async def message_acceptance(self, auth: MessagingAuth, session_id: str, message_id: str) -> ContractRecord:
        """Original signed MessageAcceptance; message interval authorization required."""
        ...

    async def verify_presence(self, auth: MessagingAuth, intent: ContractRecord) -> ContractRecord:
        """SignedArtifact of PresenceIntent -> VerifiedPresence; Cloud persists settings/generation."""
        ...

    async def verify_presence_binding(self, auth: MessagingAuth, intent: ContractRecord) -> ContractRecord:
        """SignedArtifact of PresenceBindingIntent -> VerifiedPresenceBinding; shared/dedicated only.

        This verifier never treats native suppression approval as binding consent.
        Cloud separately proves the exact private platform resource and applies CAS.
        """
        ...

    async def native_operation(self, auth: MessagingAuth, request: ContractRecord) -> ContractRecord:
        """SignedArtifact of NativeOperationRequest -> signed NativeOperation; durable owner/fence, no automatic restart."""
        ...

    async def commit_native_reply(self, auth: MessagingAuth, request: ContractRecord) -> ContractRecord:
        """SignedArtifact of NativeReply -> original AcceptedSend; fenced reply-slot + outbox commit."""
        ...
