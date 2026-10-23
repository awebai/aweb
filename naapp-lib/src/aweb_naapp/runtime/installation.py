"""X9 installation admission and dispatch fencing.

Refresh before taking a dispatch row lock. ``check`` does SQL only inside the
dispatch transaction; its shared lock serializes the commit with local grant
observations. Remote changes become visible within the grant source's cache
window plus one refresh (at most 60 + 5 seconds with TeamGrantSource defaults).
There is no cross-server lease and no rollback of already committed work.
"""

from __future__ import annotations

import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Protocol

from pgdbm import AsyncDatabaseManager, AsyncMigrationManager
from pgdbm.core import TransactionManager

from aweb_naapp.runtime.authorization import Grant, GrantSource, GrantUnavailable

MIGRATIONS_PATH = Path(__file__).parent / "installation_migrations"
MIGRATIONS_MODULE = "aweb_naapp_installation"
MAX_FRESHNESS_SECONDS = 60.0


class InstallationStatus(Protocol):
    """Structural view of G1's GrantStatus; the source owns its concrete type."""

    @property
    def team_id(self) -> str: ...
    @property
    def app_id(self) -> str: ...
    @property
    def state(self) -> str: ...
    @property
    def installation_id(self) -> str | None: ...
    @property
    def generation(self) -> int | None: ...
    @property
    def fresh_until(self) -> float: ...
    @property
    def granted_scopes(self) -> frozenset[str]: ...
    @property
    def installed_at(self) -> datetime: ...


class InstallationGrantSource(GrantSource, Protocol):
    async def status_for(self, team_id: str) -> InstallationStatus | None:
        """Fresh typed status; None denies this caller's key, never an uninstall.

        Shares grant_for's cache and timeout, and raises GrantUnavailable on an
        outage. Only state == 'uninstalled' confirms terminal retirement.
        """
        ...


RetirementHook = Callable[[TransactionManager, str], Awaitable[object]]


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


@dataclass(frozen=True)
class InstallationPermit:
    """A fresh observation; check its SQL fence before locking app resources."""
    store: InstallationFence
    status: InstallationStatus
    admitted: AdmittedInstallation

    async def check(self, tx: TransactionManager) -> None:
        await self.store.check(tx, self.admitted)

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[TransactionManager]:
        """Fence before resources and recheck freshness before their commit."""
        async with self.store.db.transaction() as tx:
            await self.check(tx)
            yield tx
            await self.check(tx)

    def database(self) -> InstallationDatabase:
        """A SQL facade for member handlers using this exact admission."""
        return InstallationDatabase(self)

    def bind(self, *, installation_id: str | None, created_at: datetime, refused: bool = False) -> str:
        """Bind a legacy capability only to an installation older than that row.

        The caller persists this ID or a permanent refusal under the resource
        lock. No future installation may retry adoption of a refused row.
        Database clock skew is outside this creation-order rule.
        """
        if refused:
            raise InstallationRefused("installation_binding_refused", 403, "The capability's installation binding was refused")
        if installation_id is not None:
            if installation_id != self.admitted.installation_id:
                raise InstallationRefused("installation_replaced", 403, "The capability belongs to a retired installation")
            return installation_id
        installed_at = self.status.installed_at
        if not isinstance(installed_at, datetime) or installed_at.tzinfo is None or created_at.tzinfo is None:
            raise _unavailable("A typed installation creation time is required")
        if installed_at >= created_at:
            raise InstallationRefused("installation_binding_refused", 403, "The current installation was created after this capability")
        return self.admitted.installation_id


class InstallationDatabase:
    """Route SQL through a permit; nested app transactions stay on its lock.

    This contains no authority logic or cache. A handler's explicit transaction
    gets the shared fence before app locks and rechecks it before committing.
    Single statements use the same transaction path.
    """

    def __init__(self, permit: InstallationPermit) -> None:
        self.permit = permit

    def transaction(self):
        return self.permit.transaction()

    async def execute(self, query, *args, **kwargs):
        async with self.transaction() as tx:
            return await tx.execute(query, *args, **kwargs)

    async def fetch_one(self, query, *args, **kwargs):
        async with self.transaction() as tx:
            return await tx.fetch_one(query, *args, **kwargs)

    async def fetch_all(self, query, *args, **kwargs):
        async with self.transaction() as tx:
            return await tx.fetch_all(query, *args, **kwargs)


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
        grants: InstallationGrantSource,
        on_retire: RetirementHook | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if not app_id:
            raise ValueError("an installation fence needs its app ID")
        self.db = db
        self.app_id = app_id
        self.grants = grants
        self.on_retire = on_retire
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
            """SELECT installation_id, generation, active_installation_id, state
               FROM {{tables.installation_fences}}
               WHERE app_id = $1 AND team_id = $2 FOR UPDATE""",
            self.app_id, team_id,
        )

    def _order(self, row, grant: Grant) -> None:
        # Generation orders ALL IDs for this (app, team), including an ID that
        # this app never saw before. Freshness cannot order cached observations.
        if row["generation"] is not None:
            if row["generation"] > grant.generation:
                raise InstallationRefused("generation_superseded", 409, "A newer generation was observed")
            if row["generation"] == grant.generation and row["installation_id"] != grant.installation_id:
                raise _unavailable("The authority assigned one generation to different installations")

    async def _retire(self, tx: TransactionManager, team_id: str, installation_id: str | None) -> None:
        if installation_id is not None:
            retired = await tx.fetch_value(
                """INSERT INTO {{tables.retired_installation_fences}} (app_id, team_id, installation_id)
                   VALUES ($1, $2, $3) ON CONFLICT DO NOTHING RETURNING installation_id""",
                self.app_id, team_id, installation_id,
            )
            if retired is not None and self.on_retire is not None:
                await self.on_retire(tx, team_id)

    async def admit(self, tx: TransactionManager, grant: Grant) -> AdmittedInstallation:
        """Bind admission to B1's fresh grant in the caller's transaction.

        Call before locking app resources. The observation rolls back with the
        caller's transaction. Committed higher generations and retired IDs are
        never replaced by an older grant, even if another process cached it.
        """
        self._remaining(grant)
        row = await self._slot(tx, grant.team_id)
        self._order(row, grant)
        retired = await tx.fetch_value(
            """SELECT EXISTS (SELECT 1 FROM {{tables.retired_installation_fences}}
               WHERE app_id = $1 AND team_id = $2 AND installation_id = $3)""",
            self.app_id, grant.team_id, grant.installation_id,
        )
        if retired:
            raise InstallationRefused("installation_inactive", 403, "The installation is inactive")
        if row["active_installation_id"] != grant.installation_id:
            await self._retire(tx, grant.team_id, row["active_installation_id"])
        # Re-evaluate after waiting for the row lock: lock waits never extend
        # the source's freshness. Read the DB clock after all lock waits too:
        # a pre-wait SQL projection would deduct the wait a second time.
        observed_at = await tx.fetch_value("SELECT clock_timestamp()")
        remaining = self._remaining(grant)
        await tx.execute(
            """UPDATE {{tables.installation_fences}}
               SET installation_id = $3, generation = $4, state = 'active',
                   active_installation_id = $3,
                   fresh_until = $5::timestamptz + $6 * interval '1 second'
               WHERE app_id = $1 AND team_id = $2""",
            self.app_id, grant.team_id, grant.installation_id, grant.generation,
            observed_at, remaining,
        )
        return self._identity(grant)

    async def _invalidate(self, team_id: str) -> None:
        async with self.db.transaction() as tx:
            await tx.execute(
                """UPDATE {{tables.installation_fences}} SET fresh_until = NULL
                   WHERE app_id = $1 AND team_id = $2""",
                self.app_id, team_id,
            )

    async def refresh(self, team_id: str) -> InstallationStatus:
        """Observe authority BEFORE the dispatch transaction/intent row lock.

        Uses ordinary ``status_for`` cache semantics, never a forced refresh.
        An outage invalidates local freshness and raises; callers must stop.
        None is a caller-specific key denial: refuse it without shared writes.
        Pending/unknown states disable shared use but may recover at the same
        generation. Only confirmed uninstall or replacement retires an ID and
        invokes on_retire inside the observation transaction.
        """
        try:
            status = await self.grants.status_for(team_id)
            if status is not None:
                if status.team_id != team_id or status.app_id != self.app_id:
                    raise _unavailable("The authority returned another team's installation")
                grant = Grant(
                    team_id=status.team_id, scopes=status.granted_scopes,
                    installation_id=status.installation_id, generation=status.generation,
                    fresh_until=status.fresh_until,
                )
                self._remaining(grant)
        except (GrantUnavailable, InstallationRefused) as exc:
            await self._invalidate(team_id)
            if isinstance(exc, InstallationRefused):
                raise
            raise _unavailable("The installation authority cannot be reached") from exc
        if status is None:
            # A stale replica's denied key says nothing about the healthy
            # replica's installed generation in the shared database.
            raise InstallationRefused("installation_inactive", 403, "This caller's app key is not registered")
        async with self.db.transaction() as tx:
            if status.state == "active":
                await self.admit(tx, grant)
            else:
                row = await self._slot(tx, team_id)
                self._remaining(grant)
                self._order(row, grant)
                if status.state == "uninstalled":
                    await self._retire(tx, team_id, row["active_installation_id"])
                    await self._retire(tx, team_id, status.installation_id)
                await tx.execute(
                    """UPDATE {{tables.installation_fences}}
                       SET installation_id = $3, generation = $4,
                           state = 'inactive', fresh_until = NULL,
                           active_installation_id = CASE WHEN $5 THEN NULL ELSE active_installation_id END
                       WHERE app_id = $1 AND team_id = $2""",
                    self.app_id, team_id, status.installation_id, status.generation,
                    status.state == "uninstalled",
                )

        return status

    async def permit(self, team_id: str) -> InstallationPermit:
        """Refresh outside app locks, then require an active typed installation."""
        status = await self.refresh(team_id)
        if status.state != "active":
            raise InstallationRefused("installation_inactive", 403, "The app installation is inactive")
        assert status.installation_id is not None and status.generation is not None
        return InstallationPermit(self, status, AdmittedInstallation(
            team_id=team_id, app_id=self.app_id,
            installation_id=status.installation_id, generation=status.generation,
        ))

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
