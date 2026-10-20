"""Single use for owner acts: a nonce row inserted in the act's effect transaction.

``OwnerActVerifier.verify_in`` reads the team's current key, runs every check
of ``aweb_naapp.hooks.owner_act`` and inserts the act's nonce under a unique
key in the caller's transaction. Two concurrent uses of one act cannot both
commit: the second insert waits on the first and then conflicts, and the
second effect rolls back with ``nonce_reused``. A failed effect rolls its
nonce row back with it, so the owner may retry the same act.
"""

from __future__ import annotations

import hashlib
from collections.abc import Awaitable, Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pgdbm import AsyncDatabaseManager, AsyncMigrationManager, TransactionManager

from aweb_naapp.hooks.owner_act import (
    CLOCK_SKEW,
    OwnerAct,
    Refused,
    check_owner_act,
    require_subject,
)

MIGRATIONS_PATH = Path(__file__).resolve().parent / "migrations"
MIGRATIONS_MODULE = "aweb_naapp_hooks"


async def apply_owner_act_migrations(db: AsyncDatabaseManager) -> None:
    await AsyncMigrationManager(
        db, migrations_path=str(MIGRATIONS_PATH), module_name=MIGRATIONS_MODULE
    ).apply_pending_migrations()


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

    async def verify_in(
        self,
        tx: TransactionManager,
        signing: bytes,
        signature: str,
        *,
        team_id: str,
        expected_subject: Mapping[str, Any],
    ) -> OwnerAct:
        """Verify an owner act and consume its nonce in ``tx``, the transaction
        that applies its effect. Raise the first refusal."""
        if expected_subject is None:
            raise Refused("verifier_misconfigured", "every verifier option is required")
        act = check_owner_act(
            signing,
            signature,
            team_id=team_id,
            current_team_key_did=await self._team_key_for(team_id),
            audience=self.audience,
            acts=self.acts,
            now=self._clock(),
        )
        used = await tx.fetch_value(
            "SELECT 1 FROM {{tables.owner_act_nonces}} WHERE scope = $1 AND team_id = $2 AND nonce = $3",
            self.scope,
            act.team_id,
            act.nonce,
        )
        if used is not None:
            raise Refused("nonce_reused", act.nonce)
        require_subject(act, expected_subject)
        inserted = await tx.fetch_value(
            "INSERT INTO {{tables.owner_act_nonces}} (scope, team_id, nonce, act_sha256, expires_at) "
            "VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING RETURNING nonce",
            self.scope,
            act.team_id,
            act.nonce,
            hashlib.sha256(signing).hexdigest(),
            act.expires_at.replace(tzinfo=UTC),
        )
        if inserted is None:
            raise Refused("nonce_reused", act.nonce)
        return act


async def prune_owner_act_nonces(db: AsyncDatabaseManager, *, now: datetime) -> int:
    """Delete nonce rows whose act could no longer verify: past its expiry by
    more than the clock allowance. Returns how many were deleted."""
    if now.tzinfo is None:
        raise Refused("verifier_misconfigured", "now must be timezone-aware")
    cutoff = now - CLOCK_SKEW
    deleted = await db.fetch_all(
        "DELETE FROM {{tables.owner_act_nonces}} WHERE expires_at < $1 RETURNING nonce",
        cutoff,
    )
    return len(deleted)
