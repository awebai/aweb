"""logs' readers composed on the shared runtime (audit-substrate.md §B4, §B5).

:func:`reader_service` builds, on the runtime's one installation fence, hook
registrations and producer, everything a designated reader needs: the reader
directory, the owner's designation and revocation acts, B3 passkeys whose
changes the shared credential recorder appends to logs' own chain, and the
console sessions that admit only a current reader. It returns the routes of
each origin; the app mounts them.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import timedelta

from aweb_naapp import ratelimit
from aweb_naapp.console import (
    ClientIdentity,
    ConsoleSessions,
    LoginLimiter,
    apply_console_migrations,
    console_login_router,
    credential_router,
)
from aweb_naapp.hooks.owner_act import APP_ACTS
from aweb_naapp.hooks.owner_act_nonces import OwnerActVerifier, apply_owner_act_migrations
from aweb_naapp.hooks.producer import RegistrationView
from aweb_naapp.runtime.app import NaappRuntime
from aweb_naapp.runtime.authorization import Authorization
from aweb_naapp.runtime.credential_audit import CredentialAudit
from aweb_naapp.runtime.installation import InstallationFence, apply_installation_migrations
from aweb_naapp.runtime.passkeys import PasskeyDelivery, Passkeys, RelyingParty
from fastapi import APIRouter
from pgdbm import AsyncDatabaseManager

from aweb_logs.ledger import LogsSigner
from aweb_logs.read_routes import (
    ReaderReads,
    reader_governance_router,
    reader_read_router,
    reader_slot_router,
)
from aweb_logs.readers import ReaderDesignations, ReaderDirectory

GOVERNANCE_HOOK = "post-governance-hook"
CREDENTIAL_AUDIT_MODULE = "aweb_logs_credential_audit"


class ReaderService:
    """The reader routes of each origin, over one composed set of services."""

    def __init__(
        self,
        *,
        db: AsyncDatabaseManager,
        directory: ReaderDirectory,
        fence: InstallationFence,
        designations: ReaderDesignations,
        passkeys: Passkeys,
        recorder: CredentialAudit,
        sessions: ConsoleSessions,
        limiter: LoginLimiter,
        chain_keys: frozenset[str],
    ) -> None:
        self.directory = directory
        self.fence = fence
        router = APIRouter()
        router.include_router(console_login_router(sessions=sessions, limiter=limiter))
        router.include_router(credential_router(passkeys=passkeys, recorder=recorder))
        router.include_router(reader_governance_router(designations))
        router.include_router(
            reader_read_router(
                ReaderReads(db, sessions=sessions, directory=directory, chain_keys=chain_keys)
            )
        )
        self.console_router = router

    def agent_router(self, authorized: Callable[..., Awaitable[Authorization]]) -> APIRouter:
        """The reader tools of the agent origin, admitted by ``authorized``."""
        return reader_slot_router(self.directory, authorized=authorized, fence=self.fence)


async def reader_service(
    runtime: NaappRuntime,
    *,
    signer: LogsSigner,
    console_origin: str,
    delivery: PasskeyDelivery,
    backlog_age: timedelta,
) -> ReaderService:
    """Apply the stores the readers need and compose their services. Call
    once the runtime's database is open, inside its lifespan."""
    db = runtime.db()
    for migrate in (
        apply_installation_migrations,
        ratelimit.apply_ratelimit_migrations,
        apply_owner_act_migrations,
        apply_console_migrations,
    ):
        await migrate(db)
    app_id = runtime.manifest.app_id
    fence = runtime.installation_fence()
    registrations = runtime.hook_registrations()
    directory = ReaderDirectory(db)

    async def governance_view(team_id: str) -> RegistrationView | None:
        return await registrations.view(team_id, GOVERNANCE_HOOK)

    async def team_key(team_id: str) -> str:
        return (await runtime.team_cache().get(team_id)).team_did_key

    passkeys: Passkeys | None = None

    def current_passkeys() -> Passkeys:
        assert passkeys is not None
        return passkeys

    recorder = CredentialAudit(
        db=db,
        app_id=app_id,
        fence=fence,
        contexts=directory.proof_context(app_id=app_id),
        owner_act_scope=app_id,
        producer=runtime.hook_producer,
        passkeys=current_passkeys,
        role_of=directory.role_of,
        registration_view=governance_view,
        max_backlog_age=backlog_age,
        migration_module=CREDENTIAL_AUDIT_MODULE,
        after_enqueue=directory.appender(signer),
    )
    passkeys = Passkeys(
        db,
        rp=RelyingParty(origin=console_origin, name="Logs"),
        delivery=delivery,
        audit=recorder,
        retirement=directory,
        enrolment_ttl=timedelta(hours=1),
        challenge_ttl=timedelta(minutes=5),
        proof_context=directory.proof_context(app_id=app_id),
    )
    await recorder.migrate()
    await passkeys.migrate()
    designations = ReaderDesignations(
        directory,
        fence=fence,
        verifier=OwnerActVerifier(
            scope=app_id,
            audience=runtime.settings.public_origin,
            acts=APP_ACTS,
            team_key_for=team_key,
        ),
        passkeys=passkeys,
        recorder=recorder,
    )
    sessions = ConsoleSessions(db, passkeys=passkeys, scopes=directory.is_current_reader)
    limiter = LoginLimiter(
        db, client_identity=ClientIdentity(), limit=12, window=timedelta(minutes=1)
    )
    return ReaderService(
        db=db,
        directory=directory,
        fence=fence,
        designations=designations,
        passkeys=passkeys,
        recorder=recorder,
        sessions=sessions,
        limiter=limiter,
        chain_keys=frozenset({signer.did_key}),
    )
