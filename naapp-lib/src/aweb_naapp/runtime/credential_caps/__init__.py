"""The shared credential cap (human-credential.cap-set).

One cap per policy key bounds how many active credentials each holding under
that key may hold; every holding counts its own. An app role's key is
(app_id, installation_id, role), set by the team owner's act. A protected
authority's key is (service_id, authority, human), set through the shared
signer's protected effect, which does not exist yet: such evidence refuses.
A key with no stored cap uses the deployment's configured one.

A cap change and a credential change serialize on the policy key, whether
or not a cap is stored for it yet: `set_cap` holds the key's transaction lock
exclusively before its row, `resolve` holds it shared. An effect that mounts
cap-set takes its installation fence and any role holds before `set_cap`,
and never a fence or passkey lock after the cap row. B3 reads the cap under its
own write preparation, through the app's resolver, which maps a scope to its
key and calls `resolve`.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from awid.signing import canonical_json_bytes
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager
from pgdbm.core import TransactionManager

from aweb_naapp.hooks.owner_act import (
    CREDENTIAL_CAP_ACT,
    VerifiedOwnerAct,
    owner_act_signing_bytes,
)
from aweb_naapp.runtime.passkeys.credential_change import CredentialPolicy

if TYPE_CHECKING:
    from aweb_naapp.runtime.credential_audit import CredentialAudit

__all__ = ["CapKey", "CredentialCapRefused", "CredentialCaps"]

MIGRATIONS = Path(__file__).parent / "migrations"
MIGRATION_MODULE = "aweb_naapp_credential_caps"
_KEY_PREFIX = b"aweb.naapp.credential-caps/1\n"


class CredentialCapRefused(Exception):
    """A cap change is not allowed. `reason` is `protected_evidence_unavailable`,
    `not_a_cap_act`, `act_not_in_this_transaction` or `cap_out_of_range`."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class CapKey:
    """The policy key of an app role: every holding of the role reads its cap."""

    app_id: str
    installation_id: str
    role: str

    @property
    def policy_key(self) -> str:
        return canonical_json_bytes(["app", self.app_id, self.installation_id, self.role]).decode()

    @property
    def lock_id(self) -> int:
        """The key's transaction-lock ID, held even when no cap is stored."""
        digest = hashlib.sha256(_KEY_PREFIX + self.policy_key.encode()).digest()
        return int.from_bytes(digest[:8], "big", signed=True)


def _utcnow() -> datetime:
    return datetime.now(UTC)


class CredentialCaps:
    def __init__(
        self,
        db: AsyncDatabaseManager,
        *,
        recorder: CredentialAudit,
        ceiling: CredentialPolicy,
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        """`ceiling` is the deployment's finite maximum, the same one B3 is
        configured with; `recorder` records each app cap change."""
        self.db = db
        self._recorder = recorder
        self._ceiling = ceiling
        self._clock = clock

    async def migrate(self) -> None:
        await AsyncMigrationManager(
            self.db, migrations_path=str(MIGRATIONS), module_name=MIGRATION_MODULE
        ).apply_pending_migrations()

    async def resolve(self, tx: TransactionManager, key: CapKey) -> int | None:
        """The key's stored cap, held for share in `tx`; None when it has
        none, which means the configured cap. Holding the key shared, it waits
        for a cap change in flight, a first one included."""
        await tx.execute("SELECT pg_advisory_xact_lock_shared($1::bigint)", key.lock_id)
        return await tx.fetch_value(
            "SELECT cap FROM {{tables.credential_caps}} WHERE policy_key = $1 FOR SHARE",
            key.policy_key,
        )

    async def set_cap(self, tx: TransactionManager, *, evidence: object) -> int:
        """Set a key's cap in the transaction that consumed `evidence`, and
        record it there; return the cap. An app role's evidence is the team
        owner's VerifiedOwnerAct, naming exactly app_id, installation_id, role
        and cap. Lowering evicts nothing: a holding above it only refuses
        further adds."""
        if not isinstance(evidence, VerifiedOwnerAct):
            raise CredentialCapRefused("protected_evidence_unavailable")
        if evidence.act != CREDENTIAL_CAP_ACT:
            raise CredentialCapRefused("not_a_cap_act")
        if evidence.transaction_id != await tx.fetch_value("SELECT txid_current()"):
            raise CredentialCapRefused("act_not_in_this_transaction")
        cap = evidence.subject["cap"]
        if not 1 <= cap <= self._ceiling.max_active:
            raise CredentialCapRefused("cap_out_of_range")
        key = CapKey(
            evidence.subject["app_id"],
            evidence.subject["installation_id"],
            evidence.subject["role"],
        )
        await tx.execute("SELECT pg_advisory_xact_lock($1::bigint)", key.lock_id)
        await tx.fetch_value(
            "SELECT 1 FROM {{tables.credential_caps}} WHERE policy_key = $1 FOR UPDATE",
            key.policy_key,
        )
        now = self._clock()
        await tx.execute(
            "INSERT INTO {{tables.credential_caps}} "
            "(policy_key, cap, policy_version, act_ref, set_in, set_at) "
            "VALUES ($1, $2, 1, $3, txid_current(), $4) "
            "ON CONFLICT (policy_key) DO UPDATE SET cap = EXCLUDED.cap, "
            "policy_version = {{tables.credential_caps}}.policy_version + 1, "
            "act_ref = EXCLUDED.act_ref, set_in = txid_current(), set_at = EXCLUDED.set_at",
            key.policy_key,
            cap,
            hashlib.sha256(owner_act_signing_bytes(evidence.fields)).hexdigest(),
            now,
        )
        await self._recorder.record_credential_cap(tx, evidence, key, occurred_at=now)
        return cap
