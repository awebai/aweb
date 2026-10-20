"""Verifying owner acts, single use under concurrency.

An owner act is verified in two steps, so that a slow registry never holds the
locks of the transaction that applies the act's effect:

1. ``OwnerActVerifier.prepare``, outside any transaction, reads the team's
   current controller key and checks the act up to its signature. It returns a
   ``PreparedOwnerAct``, which is not authority.
2. ``OwnerActVerifier.consume_in``, inside the effect's transaction, requires
   the exact subject and inserts the act's nonce under a unique key. It returns
   the only verified type, ``VerifiedOwnerAct``.

Two concurrent uses of one act cannot both commit: the second insert waits on
the first and then conflicts, and the second effect rolls back with
``nonce_reused``. A failed effect rolls its nonce row back with it, so the
owner may retry the same act.
"""

from __future__ import annotations

import hashlib
from collections.abc import Awaitable, Callable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from pgdbm import AsyncDatabaseManager, AsyncMigrationManager, TransactionManager

from aweb_naapp.hooks.owner_act import (
    CLOCK_SKEW,
    Refused,
    VerifiedOwnerAct,
    _check_owner_act,
    _CheckedAct,
    _require_subject,
    _verified,
)

__all__ = [
    "OwnerActVerifier",
    "PreparedOwnerAct",
    "apply_owner_act_migrations",
    "prune_owner_act_nonces",
]

MIGRATIONS_PATH = Path(__file__).resolve().parent / "migrations"
# How long a team key read in prepare stays current: the registry cache bound.
KEY_FRESHNESS = timedelta(seconds=60)
MIGRATIONS_MODULE = "aweb_naapp_hooks"


async def apply_owner_act_migrations(db: AsyncDatabaseManager) -> None:
    await AsyncMigrationManager(
        db, migrations_path=str(MIGRATIONS_PATH), module_name=MIGRATIONS_MODULE
    ).apply_pending_migrations()


class PreparedOwnerAct:
    """An owner act checked up to its signature, waiting for ``consume_in``.

    It is NOT authority: its nonce is unconsumed and its subject unchecked, so
    nothing may be applied on the strength of it. It exposes only the act's
    name, for logging.
    """

    __slots__ = ("_checked", "_prepared_at", "_signing", "_verifier")

    def __init__(
        self,
        checked: _CheckedAct,
        signing: bytes,
        verifier: OwnerActVerifier,
        prepared_at: datetime,
    ) -> None:
        self._checked = checked
        self._signing = signing
        self._verifier = verifier
        self._prepared_at = prepared_at

    @property
    def act_name(self) -> str:
        return self._checked.act

    def __repr__(self) -> str:
        return f"PreparedOwnerAct({self._checked.act!r})"


class OwnerActVerifier:
    """One verifier's owner-act check: its scope, audience and vocabulary, and
    how it reads a team's current controller key.

    ``team_key_for`` returns the team's current key read from its registry,
    cached at most 60 seconds, so a rotated-out key stops verifying within
    that bound. ``clock`` returns a timezone-aware now.
    """

    def __init__(
        self,
        *,
        scope: str,
        audience: str,
        acts: Sequence[str],
        team_key_for: Callable[[str], Awaitable[str]],
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if not scope or not audience or not acts:
            raise Refused(
                "verifier_misconfigured", "a scope, an audience and a vocabulary are required"
            )
        self.scope = scope
        self.audience = audience
        self.acts = tuple(acts)
        self._team_key_for = team_key_for
        self._clock = clock

    async def prepare(self, signing: bytes, signature: str, *, team_id: str) -> PreparedOwnerAct:
        """Read the team's current key and check the act up to its signature.

        Call this outside any transaction: it may read the registry over the
        network. The result is not authority; pass it to ``consume_in``.
        """
        team_key = await self._team_key_for(team_id)
        now = self._clock()
        checked = _check_owner_act(
            signing,
            signature,
            team_id=team_id,
            current_team_key_did=team_key,
            audience=self.audience,
            acts=self.acts,
            now=now,
        )
        return PreparedOwnerAct(checked, signing, self, _utc_now(lambda: now))

    async def consume_in(
        self,
        tx: TransactionManager,
        prepared: PreparedOwnerAct,
        *,
        expected_subject: Mapping[str, Any],
    ) -> VerifiedOwnerAct:
        """Finish verifying a prepared act inside ``tx``, the transaction that
        applies its effect: refuse a used nonce, require the exact subject, and
        consume the nonce. Returns the verified act.

        Nothing here awaits the network, only the transaction's own database
        work, so a slow registry never holds the effect's locks.
        """
        if not isinstance(prepared, PreparedOwnerAct) or prepared._verifier is not self:
            raise Refused("verifier_misconfigured", "the act was prepared by another verifier")
        if expected_subject is None:
            raise Refused("verifier_misconfigured", "every verifier option is required")
        act = prepared._checked
        now = _utc_now(self._clock)
        # The team key read in prepare is trusted for the same bound as the
        # registry cache: a prepared act older than that may predate a key
        # rotation, so it no longer proves the current controller key.
        if now - prepared._prepared_at > KEY_FRESHNESS:
            raise Refused("owner_required", "prepared too long ago for its team key to be current")
        # Expiry again: a prepared act held past its expiry could otherwise be
        # consumed after its earlier nonce row was pruned.
        if now >= act.expires_at:
            raise Refused("expired", f"expired at {act.fields['expires_at']}")
        used = await tx.fetch_value(
            "SELECT 1 FROM {{tables.owner_act_nonces}} WHERE scope = $1 AND team_id = $2 AND nonce = $3",
            self.scope,
            act.team_id,
            act.nonce,
        )
        if used is not None:
            raise Refused("nonce_reused", act.nonce)
        _require_subject(act, expected_subject)
        inserted = await tx.fetch_value(
            "INSERT INTO {{tables.owner_act_nonces}} (scope, team_id, nonce, act_sha256, expires_at) "
            "VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING RETURNING nonce",
            self.scope,
            act.team_id,
            act.nonce,
            hashlib.sha256(prepared._signing).hexdigest(),
            act.expires_at.replace(tzinfo=UTC),
        )
        if inserted is None:
            raise Refused("nonce_reused", act.nonce)
        return _verified(act)


def _utc_now(clock: Callable[[], datetime]) -> datetime:
    now = clock()
    if now.tzinfo is None:
        raise Refused("verifier_misconfigured", "now must be timezone-aware")
    return now.astimezone(UTC).replace(tzinfo=None)


async def prune_owner_act_nonces(db: AsyncDatabaseManager, *, now: datetime) -> int:
    """Delete nonce rows whose act could no longer verify: past its expiry by
    more than the clock allowance. Returns how many were deleted."""
    if now.tzinfo is None:
        raise Refused("verifier_misconfigured", "now must be timezone-aware")
    deleted = await db.fetch_all(
        "DELETE FROM {{tables.owner_act_nonces}} WHERE expires_at < $1 RETURNING nonce",
        now - CLOCK_SKEW,
    )
    return len(deleted)
