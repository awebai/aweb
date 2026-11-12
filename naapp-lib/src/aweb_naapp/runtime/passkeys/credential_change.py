"""An in-effect approver's own credential maintenance (human-credential.add
and human-credential.replace, variant current_passkey).

The new credential registers with user verification first; a current
credential's assertion then approves that exact credential, the holding and
the operation. The caller's credential-change fence takes, in its original
transaction: its own lifecycle lock (F6), the retirement gate of its authority
context, its actor and target role holds, then `prepare_credential_change`,
then its session holds (S4). B3's preparation holds the scope's approver row
and its active credentials for update from the outset, so nothing is upgraded
from a shared hold later. The fence returns that handle and the change
validates it.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol

from awid.signing import canonical_json_bytes
from pgdbm.core import TransactionManager
from webauthn.helpers import bytes_to_base64url

from aweb_naapp.hooks.owner_act import HumanCredential
from aweb_naapp.runtime.approvals import DeliveryStatus
from aweb_naapp.runtime.passkeys.current_approver import _guard_live, _live

if TYPE_CHECKING:
    from aweb_naapp.runtime.passkeys.service import Passkeys

ADD = "add"
REPLACE = "replace"
REGISTRATION_PREFIX = b"aweb.passkey-credential-registration/1\n"
CHANGE_PREFIX = b"aweb.passkey-credential-change/1\n"
CHANGE_REQUEST_PREFIX = b"aweb.passkey-credential-change-request/1\n"
# The live-approval limit of a credential change, whatever the app's challenge
# lifetime: the registration and the assertion approving it both expire by then.
CHANGE_DEADLINE = timedelta(minutes=5)


class CredentialChangeRefused(Exception):
    """A credential change is not allowed now. `reason` is one of
    `not_in_effect`, `no_notice_contact`, `no_active_credential`,
    `registration_unavailable`, `registration_did_not_verify`,
    `credential_registered`, `not_active_credential`, `cap_reached`, `cap_unavailable`,
    `stale_binding` or `expired`; a caller's fence may raise it with its own."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class CredentialPolicy:
    """How many active credentials one holding may have. The default is five;
    a stricter bound may be lower, never below one."""

    max_active: int = 5

    def __post_init__(self) -> None:
        if isinstance(self.max_active, bool) or not isinstance(self.max_active, int):
            raise ValueError("a credential cap is an integer")
        if self.max_active < 1:
            raise ValueError("a credential cap is at least one")


@dataclass(frozen=True)
class CredentialChange:
    """A committed credential change. `challenge` is the base64url challenge
    the approving assertion answered, which the client already holds.
    `delivery` is how the notice went, once it was sent."""

    operation: str
    scope: str
    subject: str
    credential_id: bytes
    retired_credential_id: bytes | None
    evidence_ref: str
    challenge: str
    delivery: DeliveryStatus | None = None


class CredentialChangeState(StrEnum):
    COMMITTED = "committed"
    PENDING = "pending"
    SPENT_UNCOMMITTED = "spent_uncommitted"
    NOT_FOUND = "not_found"


@dataclass(frozen=True)
class CredentialChangeStatus:
    """What became of the change a challenge approves: committed, still able
    to commit (pending), or past its deadline with nothing committed. It grants
    nothing."""

    state: CredentialChangeState
    change: CredentialChange | None = None


@dataclass(frozen=True)
class PreparedCredentialChange:
    """B3's write holds for one scope's credential change, in one original
    caller transaction. It grants no authority."""

    _service: Passkeys = field(repr=False)
    _tx: TransactionManager = field(repr=False)
    _transaction_id: int = field(repr=False)
    _guard_key: int = field(repr=False)
    _scope: str = field(repr=False)
    _subject: str | None = field(repr=False)


class CredentialChangeFence(Protocol):
    """The caller's authority over one credential change, in the change's
    effect transaction. `prepare` takes the caller's locks in their contracted
    order, with `Passkeys.prepare_credential_change` among them, and returns
    its handle; `check` is the final read-only check, after the effect and its
    audit and receipt, before the commit. Expected refusal raises
    CredentialChangeRefused; any other exception propagates unchanged."""

    async def prepare(self, tx: TransactionManager) -> PreparedCredentialChange: ...

    async def check(self, tx: TransactionManager) -> None: ...


class CredentialReceipt(Protocol):
    """The caller's record of the change, written through the effect
    transaction (SQL only, no network), after audit and before the fence's
    final check."""

    async def __call__(self, tx: TransactionManager, change: CredentialChange) -> None: ...


async def prepare_credential_change(
    service: Passkeys, tx: TransactionManager, scope: str
) -> PreparedCredentialChange:
    if not _live(tx) or await tx.fetch_value("SHOW transaction_isolation") != "read committed":
        raise ValueError("credential change preparation needs a live READ COMMITTED transaction")
    subject = await tx.fetch_value(
        "SELECT subject FROM {{tables.passkey_approvers}} "
        "WHERE scope = $1 AND superseded_at IS NULL FOR UPDATE",
        scope,
    )
    if subject is not None:
        await tx.fetch_all(
            "SELECT credential_id FROM {{tables.passkey_credentials}} "
            "WHERE subject = $1 AND revoked_at IS NULL ORDER BY credential_id FOR UPDATE",
            subject,
        )
    guard = uuid.uuid4().int & ((1 << 63) - 1)
    await tx.execute("SELECT pg_advisory_xact_lock($1::bigint)", guard)
    xid = int(await tx.fetch_value("SELECT txid_current()"))
    if not await _guard_live(tx, xid, guard):
        raise ValueError("credential change preparation lost its transaction")
    return PreparedCredentialChange(service, tx, xid, guard, scope, subject)


async def require_prepared(
    service: Passkeys, tx: TransactionManager, prepared: object, scope: str
) -> PreparedCredentialChange:
    """The handle B3 prepared for this scope in this very transaction, still
    holding its locks; a caller error otherwise."""
    if (
        not isinstance(prepared, PreparedCredentialChange)
        or prepared._service is not service
        or prepared._tx is not tx
        or prepared._scope != scope
        or not _live(tx)
        or not await _guard_live(tx, prepared._transaction_id, prepared._guard_key)
    ):
        raise ValueError("the fence did not return this transaction's credential change handle")
    return prepared


def registration_preimage(scope: str, subject: str, nonce: bytes) -> bytes:
    fields = {"nonce": nonce.hex(), "scope": scope, "subject": subject}
    return REGISTRATION_PREFIX + canonical_json_bytes(fields)


def credential_sha256(credential_id: bytes, public_key: bytes, rp_id: str) -> str:
    """The digest an owner act names a credential by, at its effective relying party."""
    return HumanCredential(credential_id, public_key, rp_id).sha256


def change_preimage(
    *,
    scope: str,
    subject: str,
    operation: str,
    new_sha256: str,
    retire_sha256: str | None,
    nonce: bytes,
) -> bytes:
    fields = {
        "credential_sha256": new_sha256,
        "nonce": nonce.hex(),
        "operation": operation,
        "scope": scope,
        "subject": subject,
    }
    if retire_sha256 is not None:
        fields["retire_credential_sha256"] = retire_sha256
    return CHANGE_PREFIX + canonical_json_bytes(fields)


def _credential(credential_id: bytes, public_key: bytes, rp_id: str) -> dict[str, str]:
    return {
        "credential_id": bytes_to_base64url(credential_id),
        "public_key": bytes_to_base64url(public_key),
        "rp_id": rp_id,
    }


def change_request(
    new: tuple[bytes, bytes], retire: tuple[bytes, bytes] | None, rp_id: str
) -> bytes:
    """The sidecar naming the credentials a change binds, bound to the
    challenge transitively through their digests."""
    body = {"credential": _credential(*new, rp_id)}
    if retire is not None:
        body["retire_credential"] = _credential(*retire, rp_id)
    return CHANGE_REQUEST_PREFIX + canonical_json_bytes(body)


def challenge_of(preimage: bytes) -> bytes:
    return hashlib.sha256(preimage).digest()
