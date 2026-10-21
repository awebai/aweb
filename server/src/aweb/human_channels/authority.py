"""Trusted embedding facts for native messaging; never inferred from wire data.

Providers own their identity/custody/access authority. They must not look up OSS
private tables. Resolve/prepare can do network I/O; acceptance hooks use only the
supplied transaction to lock/recheck host-owned state, with no network I/O.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from .contract import ContractRecord

if TYPE_CHECKING:
    from asyncpg import Connection

    from aweb.identity_auth_deps import MessagingAuth


@dataclass(frozen=True)
class NativeMessagingSubject:
    """Exact candidate selected by OSS, not an external platform account.

    A provider must independently establish the binding and current key; the
    candidate is lookup input, not proof of identity/custody/access.
    """

    principal: str
    signing_key_id: str
    actor_id: str | None
    team_id: str | None


class NativeMessagingAuthority(Protocol):
    async def current(
        self,
        auth: MessagingAuth,
        subject: NativeMessagingSubject,
    ) -> ContractRecord:
        """Return bound AuthorityFacts or ContractError(authority_unavailable).

        Bind exact actor/principal/current signing key/team/service audience;
        require active identity, access and current inbound policy. Signing-key
        custody is independent of encryption-key assertions/custody. Missing
        authority never defaults to self_custodial. No external IDs or secrets.
        """
        ...

    async def lock_authority(
        self,
        auth: MessagingAuth,
        prepared: ContractRecord,
        ingress_key: ContractRecord,
        transaction: Connection,
    ) -> None:
        """Before accept: lock/recheck current host authority on THIS connection.

        Check current identity/signing custody, actor binding, account/session,
        link, organization policy/consent and private binding revision as
        applicable. Refuse stale/revoked/unavailable facts with ContractError.
        Locks last through accept, own correlation/delivery-intent writes and
        finish_ingress. No independent transaction or network I/O. This method
        is invoked by accept; a TTL/revision snapshot alone is insufficient.
        """
        ...

    async def authorize_recovery(
        self,
        auth: MessagingAuth,
        ingress_key: ContractRecord,
        transaction: Connection,
    ) -> None:
        """Current requester authority before original-result disclosure.

        Check only host-owned current recovery authority on this connection.
        Returning an original result never sends or revives an old route.
        """
        ...
