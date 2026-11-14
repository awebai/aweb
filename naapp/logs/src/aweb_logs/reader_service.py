"""logs' readers composed on the shared runtime (audit-substrate.md §B4, §B5).

:func:`reader_service` builds, on the runtime's one installation fence, hook
registrations and producer, everything a reader needs: the reader directory
over the ``logs.reader`` holdings, B3 passkeys whose changes the shared
credential recorder appends to logs' own chain, and the console sessions that
admit only a current reader: a passkey login's cookie session, or the
key-bound session aw collects through the shared handoff. It returns the
routes of each origin; the app mounts them.
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
from aweb_naapp.console.handoff_authority import HandoffAuthority
from aweb_naapp.console.handoff_sessions import ConsoleHandoffs
from aweb_naapp.console.human_role_authority import HumanRoleHandoffAuthority
from aweb_naapp.hooks.owner_act import APP_ACTS, HUMAN_ROLE_ACTS, LOGS_ACTS
from aweb_naapp.hooks.owner_act_nonces import OwnerActVerifier, apply_owner_act_migrations
from aweb_naapp.hooks.producer import RegistrationView
from aweb_naapp.roles import apply_roles_migrations, is_holding_scope
from aweb_naapp.runtime.app import NaappRuntime
from aweb_naapp.runtime.authorization import Authorization
from aweb_naapp.runtime.credential_audit import CredentialAudit
from aweb_naapp.runtime.human_member import HumanMemberProof
from aweb_naapp.runtime.human_roles import HumanRoleHoldings
from aweb_naapp.runtime.installation import InstallationFence, apply_installation_migrations
from aweb_naapp.runtime.owner_act_router import OwnerActLimiter, mount_owner_act_routes
from aweb_naapp.runtime.passkeys import PasskeyDelivery, Passkeys, RelyingParty
from aweb_naapp.runtime.team_auth import Principal
from fastapi import APIRouter, Request
from pgdbm import AsyncDatabaseManager
from pgdbm.core import TransactionManager

from aweb_logs.console_ui import console_pages_router
from aweb_logs.governance import SELF_RECORDED_ACTS, LogsGovernance
from aweb_logs.ledger import LogsSigner
from aweb_logs.purge_ledger import PurgeLedger
from aweb_logs.read_routes import ReaderReads, reader_read_router, reader_removal_router
from aweb_logs.reader_acts import reader_acts
from aweb_logs.readers import READER_ROLE, ReaderDirectory, ReaderRemovals

GOVERNANCE_HOOK = "post-governance-hook"
CREDENTIAL_AUDIT_MODULE = "aweb_logs_credential_audit"


def reader_sessions(
    *,
    db: AsyncDatabaseManager,
    directory: ReaderDirectory,
    fence: InstallationFence,
    passkeys: Passkeys,
    principal: Callable[[Request], Awaitable[Principal]],
    human_member: Callable[..., Awaitable[HumanMemberProof]],
    limiter: LoginLimiter,
) -> tuple[ConsoleSessions, ConsoleHandoffs]:
    """The console origin's sessions and the shared handoff that issues aw's.

    A cookie session is a current reader's passkey login. A key-bound session
    is one aw collected through the handoff: ``principal`` authenticates the
    member who starts it on the public origin, its team is the one the session
    keeps, and ``human_member`` checks that member is the holding's human. Both
    kinds are admitted only for a current ``logs.reader`` holding.
    """
    holdings = HumanRoleHandoffAuthority(
        role=READER_ROLE,
        holdings=HumanRoleHoldings(roles=frozenset({READER_ROLE}), passkeys=passkeys),
        fence=fence,
        passkeys=passkeys,
    )
    handoffs = ConsoleHandoffs(
        db=db,
        passkeys=passkeys,
        authority=HandoffAuthority(
            holdings.credential_target,
            holdings.session_target,
            holdings.hold_session_target,
            holdings.check_session_target,
            holdings.holding_identity,
        ),
        principal=principal,
        human_member=human_member,
        limiter=limiter,
    )
    sessions = ConsoleSessions(
        db, passkeys=passkeys, scopes=directory.is_current_reader, key_bound=handoffs.current
    )
    return sessions, handoffs


class ReaderService:
    """The reader routes of each origin, over one composed set of services.
    ``sessions`` is the console origin's one session service: every console
    route admits only a current reader through it. ``handoffs`` issues aw's
    key-bound sessions: its start is ``handoff_router``, for the public origin,
    and its approval pages are on the console origin."""

    def __init__(
        self,
        *,
        db: AsyncDatabaseManager,
        directory: ReaderDirectory,
        fence: InstallationFence,
        passkeys: Passkeys,
        recorder: CredentialAudit,
        sessions: ConsoleSessions,
        handoffs: ConsoleHandoffs,
        limiter: LoginLimiter,
        chain_keys: frozenset[str],
        governance: LogsGovernance,
        owner_acts: APIRouter,
    ) -> None:
        self.directory = directory
        # The owner's retention, erasure and hold acts. No route delivers them
        # yet: owner-act delivery covers only the app-role and credential acts.
        self.governance = governance
        self.fence = fence
        self.sessions = sessions
        self.removals = ReaderRemovals(directory, fence=fence, passkeys=passkeys, recorder=recorder)
        reads = ReaderReads(db, sessions=sessions, directory=directory, chain_keys=chain_keys)
        self.handoff_router = handoffs.api_router()
        router = APIRouter()
        router.include_router(console_login_router(sessions=sessions, limiter=limiter))
        router.include_router(handoffs.human_router())
        router.include_router(credential_router(passkeys=passkeys, recorder=recorder))
        router.include_router(console_pages_router(reads))
        router.include_router(reader_read_router(reads))
        router.include_router(owner_acts)
        self.console_router = router

    def agent_router(self, authorized: Callable[..., Awaitable[Authorization]]) -> APIRouter:
        """The reader tools of the agent origin, admitted by ``authorized``."""
        router = APIRouter()
        router.include_router(reader_removal_router(self.removals, authorized=authorized))
        return router


async def reader_service(
    runtime: NaappRuntime,
    *,
    signer: LogsSigner,
    console_origin: str,
    client_address_header: str | None,
    delivery: PasskeyDelivery,
    backlog_age: timedelta,
    purges: PurgeLedger,
) -> ReaderService:
    """Apply the stores the readers need and compose their services. Call
    once the runtime's database is open, inside its lifespan."""
    db = runtime.db()
    for migrate in (
        apply_installation_migrations,
        ratelimit.apply_ratelimit_migrations,
        apply_owner_act_migrations,
        apply_console_migrations,
        apply_roles_migrations,
    ):
        await migrate(db)
    app_id = runtime.manifest.app_id
    fence = runtime.installation_fence()
    registrations = runtime.hook_registrations()
    passkeys: Passkeys | None = None

    def current_passkeys() -> Passkeys:
        assert passkeys is not None
        return passkeys

    directory = ReaderDirectory(db, app_id=app_id, passkeys=current_passkeys)

    async def governance_view(team_id: str) -> RegistrationView | None:
        return await registrations.view(team_id, GOVERNANCE_HOOK)

    async def team_authority(team_id):
        from awid.protected_membership import observe_team_protection
        return await observe_team_protection(runtime.registry_client(), team_id)

    async def team_key(team_id: str) -> str:
        return (await runtime.team_cache().get(team_id)).team_did_key

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
        ungated_acts=SELF_RECORDED_ACTS,
        human_roles=frozenset({READER_ROLE}),
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
        holding_scopes=is_holding_scope,
    )
    await recorder.migrate()
    await passkeys.migrate()
    verifier = OwnerActVerifier(
        scope=app_id,
        audience=runtime.settings.public_origin,
        acts=APP_ACTS + LOGS_ACTS,
        team_key_for=team_key, team_authority_for=team_authority,
    )
    client_identity = ClientIdentity(trusted_header=client_address_header)
    limiter = LoginLimiter(
        db, client_identity=client_identity, limit=12, window=timedelta(minutes=1)
    )
    acts = reader_acts(
        passkeys=passkeys, recorder=recorder, check_member=runtime.check_human_role_member
    )

    async def retire_readers(tx: TransactionManager, team_id: str) -> None:
        # A retired installation's readers end, and their credentials and
        # sessions go, in the fence's retirement transaction.
        await acts.retire(tx, app_id=app_id, team_id=team_id)

    fence.on_retire = retire_readers
    owner_acts = APIRouter()
    mount_owner_act_routes(
        owner_acts,
        runtime=runtime,
        effect=acts,
        verifier=OwnerActVerifier(
            scope=app_id, audience=console_origin, acts=HUMAN_ROLE_ACTS, team_key_for=team_key, team_authority_for=team_authority
        ),
        limiter=OwnerActLimiter(
            client_identity=client_identity, limit=12, window=timedelta(minutes=1)
        ),
    )
    sessions, handoffs = reader_sessions(
        db=db,
        directory=directory,
        fence=fence,
        passkeys=passkeys,
        principal=runtime.principal,
        human_member=runtime.check_human_member,
        limiter=limiter,
    )
    return ReaderService(
        db=db,
        directory=directory,
        fence=fence,
        passkeys=passkeys,
        recorder=recorder,
        sessions=sessions,
        handoffs=handoffs,
        limiter=limiter,
        chain_keys=frozenset({signer.did_key}),
        governance=LogsGovernance(
            db,
            purges=purges,
            fence=fence,
            verifier=verifier,
            recorder=recorder,
            logs_origin=runtime.settings.public_origin,
        ),
        owner_acts=owner_acts,
    )
