"""X9 installation admission and dispatch fencing.

Refresh before taking a dispatch row lock. ``check`` does SQL only inside the
dispatch transaction; its shared lock serializes the commit with local grant
observations. Remote changes become visible within the grant source's cache
window plus one refresh (at most 60 + 5 seconds with TeamGrantSource defaults).
There is no cross-server lease and no rollback of already committed work.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from pgdbm import AsyncDatabaseManager, AsyncMigrationManager
from pgdbm.core import TransactionManager

from aweb_naapp.runtime.authorization import Grant, GrantSource, GrantUnavailable

MIGRATIONS_PATH = Path(__file__).parent / "installation_migrations"
MIGRATIONS_MODULE = "aweb_naapp_installation"
MAX_FRESHNESS_SECONDS = 60.0


class InstallationRefused(Exception):
    """Stable installation refusal for the app's HTTP/audit boundary."""

    def __init__(self, code: str, status: int, message: str) -> None:
        self.code = code
        self.status = status
        super().__init__(message)


@dataclass(frozen=True, kw_only=True)
class AdmittedInstallation:
    team_id: str
    app_id: str
    installation_id: str
    generation: int


class InstallationDispatchFence:
    """S3's prepare/check protocol, bound to one installation and transaction.

    Create a fresh object for each dispatch/admission call. S3 must invoke
    prepare before its pair and intent locks, then check under those locks.
    """

    def __init__(
        self, store: InstallationFence, admitted: AdmittedInstallation, grant: Grant | None = None,
    ) -> None:
        self.store = store
        self.admitted = admitted
        self.grant = grant
        self._prepared_tx: TransactionManager | None = None

    async def prepare(self, tx: TransactionManager) -> None:
        if self.grant is not None:
            self.admitted = await self.store.admit(tx, self.grant)
        else:
            await self.store._lock(tx, self.admitted)
        self._prepared_tx = tx

    async def check(self, tx: TransactionManager, dispatch: object) -> None:
        if self._prepared_tx is not tx:
            raise _unavailable("Prepare the installation fence before taking dispatch locks")
        await self.store._check_locked(tx, self.admitted)


async def apply_installation_migrations(db: AsyncDatabaseManager) -> None:
    """Install the shared fence store, separately from the app's own tables."""
    await AsyncMigrationManager(
        db, migrations_path=str(MIGRATIONS_PATH), module_name=MIGRATIONS_MODULE
    ).apply_pending_migrations()


def _unavailable(message: str = "The installation authority is not fresh") -> InstallationRefused:
    return InstallationRefused("authority_unavailable", 503, message)


class InstallationFence:
    def __init__(
        self,
        db: AsyncDatabaseManager,
        *,
        app_id: str,
        grants: GrantSource,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if not app_id:
            raise ValueError("an installation fence needs its app ID")
        self.db = db
        self.app_id = app_id
        self.grants = grants
        self.monotonic = monotonic

    def for_installation(self, admitted: AdmittedInstallation) -> InstallationDispatchFence:
        """Bind a previously admitted intent to S3's required fence protocol."""
        return InstallationDispatchFence(self, admitted)

    def for_admission(self, grant: Grant) -> InstallationDispatchFence:
        """Record B1's grant in S3's pre-lock phase and expose ``.admitted``.

        Pass this object to S3.admit(fence=...), rather than observing the
        installation after S3 has acquired its pair or intent locks.
        """
        return InstallationDispatchFence(self, self._identity(grant), grant)

    def _identity(self, grant: Grant) -> AdmittedInstallation:
        if (
            not isinstance(grant.installation_id, str)
            or not grant.installation_id
            or type(grant.generation) is not int
            or grant.generation <= 0
            or grant.generation > 9223372036854775807
        ):
            raise InstallationRefused(
                "installation_identity_required", 403,
                "The installation authority must supply an identity and positive generation",
            )
        return AdmittedInstallation(
            team_id=grant.team_id, app_id=self.app_id,
            installation_id=grant.installation_id, generation=grant.generation,
        )

    def _remaining(self, grant: Grant) -> float:
        self._identity(grant)
        remaining = grant.fresh_until - self.monotonic()
        if not 0 < remaining <= MAX_FRESHNESS_SECONDS:
            raise _unavailable()
        return remaining

    async def _slot(self, tx: TransactionManager, team_id: str):
        await tx.execute(
            """INSERT INTO {{tables.installation_fences}} (app_id, team_id)
               VALUES ($1, $2) ON CONFLICT (app_id, team_id) DO NOTHING""",
            self.app_id, team_id,
        )
        return await tx.fetch_one(
            """SELECT installation_id, generation, state, clock_timestamp() AS observed_at
               FROM {{tables.installation_fences}}
               WHERE app_id = $1 AND team_id = $2 FOR UPDATE""",
            self.app_id, team_id,
        )

    async def _retire(self, tx: TransactionManager, team_id: str, installation_id: str | None) -> None:
        if installation_id is not None:
            await tx.execute(
                """INSERT INTO {{tables.retired_installation_fences}} (app_id, team_id, installation_id)
                   VALUES ($1, $2, $3) ON CONFLICT DO NOTHING""",
                self.app_id, team_id, installation_id,
            )

    async def admit(self, tx: TransactionManager, grant: Grant) -> AdmittedInstallation:
        """Bind admission to B1's fresh grant in the caller's transaction.

        Call before locking app resources. The observation rolls back with the
        caller's transaction. Committed higher generations and retired IDs are
        never replaced by an older grant, even if another process cached it.
        """
        self._remaining(grant)
        row = await self._slot(tx, grant.team_id)
        retired = await tx.fetch_value(
            """SELECT EXISTS (SELECT 1 FROM {{tables.retired_installation_fences}}
               WHERE app_id = $1 AND team_id = $2 AND installation_id = $3)""",
            self.app_id, grant.team_id, grant.installation_id,
        )
        if retired or (
            row["installation_id"] == grant.installation_id
            and row["state"] == "inactive"
            and grant.generation <= row["generation"]
        ):
            raise InstallationRefused("installation_inactive", 403, "The installation is inactive")
        if row["installation_id"] == grant.installation_id:
            if row["generation"] > grant.generation:
                raise InstallationRefused("generation_superseded", 409, "A newer generation was observed")
        else:
            await self._retire(tx, grant.team_id, row["installation_id"])
        # Re-evaluate after waiting for the row lock: lock waits never extend
        # the source's freshness. The DB deadline survives process restarts.
        remaining = self._remaining(grant)
        await tx.execute(
            """UPDATE {{tables.installation_fences}}
               SET installation_id = $3, generation = $4, state = 'active',
                   fresh_until = $5::timestamptz + $6 * interval '1 second'
               WHERE app_id = $1 AND team_id = $2""",
            self.app_id, grant.team_id, grant.installation_id, grant.generation,
            row["observed_at"], remaining,
        )
        return self._identity(grant)

    async def _invalidate(self, team_id: str) -> None:
        async with self.db.transaction() as tx:
            await tx.execute(
                """UPDATE {{tables.installation_fences}} SET fresh_until = NULL
                   WHERE app_id = $1 AND team_id = $2""",
                self.app_id, team_id,
            )

    async def refresh(self, team_id: str) -> None:
        """Observe authority BEFORE the dispatch transaction/intent row lock.

        Uses ordinary ``grant_for`` cache semantics, never a forced refresh.
        An outage invalidates local freshness and raises; callers must stop.
        A definitive negative disables the observed generation. ``None`` also
        covers a key denial, so a fresh higher generation may recover the same
        ID after a key update. Only an observed replacement ID retires an ID.
        """
        try:
            grant = await self.grants.grant_for(team_id)
            if grant is not None:
                if grant.team_id != team_id:
                    raise _unavailable("The authority returned another team's installation")
                self._remaining(grant)
        except (GrantUnavailable, InstallationRefused) as exc:
            await self._invalidate(team_id)
            if isinstance(exc, InstallationRefused):
                raise
            raise _unavailable("The installation authority cannot be reached") from exc
        async with self.db.transaction() as tx:
            if grant is not None:
                await self.admit(tx, grant)
            else:
                await self._slot(tx, team_id)
                await tx.execute(
                    """UPDATE {{tables.installation_fences}}
                       SET state = 'inactive', fresh_until = NULL
                       WHERE app_id = $1 AND team_id = $2""",
                    self.app_id, team_id,
                )

    async def check(self, tx: TransactionManager, admitted: AdmittedInstallation) -> None:
        """SQL-only standalone check; acquire this before app resource locks.

        S3 callers pass ``for_installation`` or ``for_admission`` instead: its
        prepare phase enforces fence -> pair -> intent lock order. The bound
        check phase takes no new lock and evaluates freshness AFTER lock waits.
        """
        await self._lock(tx, admitted)
        await self._check_locked(tx, admitted)

    async def _lock(self, tx: TransactionManager, admitted: AdmittedInstallation) -> None:
        if admitted.app_id != self.app_id:
            raise InstallationRefused("generation_superseded", 409, "The admission belongs to another app")
        # Do not evaluate the SQL clock in this query: PostgreSQL can project
        # it before the row-lock wait and return that stale result afterward.
        row = await tx.fetch_one(
            """SELECT installation_id FROM {{tables.installation_fences}}
               WHERE app_id = $1 AND team_id = $2 FOR SHARE""",
            self.app_id, admitted.team_id,
        )
        if row is None:
            raise _unavailable("Refresh the installation before dispatch")

    async def _check_locked(self, tx: TransactionManager, admitted: AdmittedInstallation) -> None:
        row = await tx.fetch_one(
            """SELECT installation_id, generation, state,
                      fresh_until > clock_timestamp() AS fresh
               FROM {{tables.installation_fences}}
               WHERE app_id = $1 AND team_id = $2""",
            self.app_id, admitted.team_id,
        )
        if row is None:
            raise _unavailable("Refresh the installation before dispatch")
        if row["state"] == "inactive":
            raise InstallationRefused("installation_inactive", 403, "The installation is inactive")
        if not row["fresh"]:
            raise _unavailable()
        if row["installation_id"] != admitted.installation_id or row["generation"] != admitted.generation:
            raise InstallationRefused("generation_superseded", 409, "The admitted generation is no longer current")
