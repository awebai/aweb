"""Production composition: one runtime and one shared set of business services."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

import httpx
from aweb_naapp.console import apply_console_migrations
from aweb_naapp.dispatch import apply_dispatch_migrations
from aweb_naapp.egress import AddressPolicy, DnsResolver, Egress
from aweb_naapp.email import EmailSettings, Mailer
from aweb_naapp.hooks.owner_act import APP_ACTS
from aweb_naapp.hooks.owner_act_nonces import OwnerActVerifier, apply_owner_act_migrations
from aweb_naapp.key_file import read_key_file
from aweb_naapp.nonces import apply_nonce_migrations
from aweb_naapp.roles import purge_team
from aweb_naapp.runtime.app import NaappRuntime
from aweb_naapp.runtime.approvals import (
    ActionPolicy,
    Approval,
    ApprovalRevocation,
    Approvals,
    Approver,
    PgApprovalStore,
)
from aweb_naapp.runtime.health import CheckResult
from aweb_naapp.runtime.passkeys import Passkeys, RelyingParty
from aweb_naapp.signing_key import read_signing_key_file
from fastapi import APIRouter
from nacl.signing import SigningKey
from pgdbm.core import TransactionManager

from aweb_secrets.activity_service import ActivityReads
from aweb_secrets.app import Authorized, ConsoleRouter, SecretsService, create_app
from aweb_secrets.approval_email import ApprovalEmailDelivery
from aweb_secrets.audit_sink import SecretsAudit
from aweb_secrets.broker_service import BrokerRequests
from aweb_secrets.catalog import Catalog
from aweb_secrets.change import TYPE as CHANGE_TYPE
from aweb_secrets.change_policy import apply_change_policy_migrations
from aweb_secrets.change_sets import (
    ChangeSetPolicies,
    ChangeSets,
    DraftLimit,
    apply_change_set_migrations,
)
from aweb_secrets.config import ServiceSettings
from aweb_secrets.console import OwnerConsole, owner_console_router
from aweb_secrets.console_activity import ConsoleActivity, console_activity_router
from aweb_secrets.console_bootstrap import console_bootstrap_router
from aweb_secrets.console_changes import ConsoleChanges, console_changes_router
from aweb_secrets.console_forms import console_forms_router
from aweb_secrets.console_jobs import console_jobs_router
from aweb_secrets.console_ui import console_ui_router
from aweb_secrets.console_use_approvals import (
    ConsoleUseApprovals,
    console_run_approvals_router,
    console_use_approvals_router,
)
from aweb_secrets.console_values import ConsoleValues, console_values_router
from aweb_secrets.containment import Containment
from aweb_secrets.containment_routes import containment_api_router, containment_console_router
from aweb_secrets.credential_audit import CredentialAudit, GovernanceUnavailable
from aweb_secrets.custody import (
    AwsKmsProvider,
    BackendCredentialOpener,
    Custody,
    CustodyUnavailable,
    KeyProvider,
    LocalKeyFileProvider,
    SecretOpener,
    apply_custody_migrations,
    seal_canary,
)
from aweb_secrets.custody.opening import UseSecretOpener
from aweb_secrets.installation_lookup import InstallationLookup
from aweb_secrets.jobs import apply_job_migrations
from aweb_secrets.metadata_routes import MetadataServices, metadata_router
from aweb_secrets.owners import OwnerDirectory, apply_owner_migrations, is_owner_scope
from aweb_secrets.passkey_context import PasskeyContexts
from aweb_secrets.passkey_email import PasskeyEmailDelivery
from aweb_secrets.response_audit import ResponseKey
from aweb_secrets.run_context import apply_run_dispatch_migrations
from aweb_secrets.run_service import RunDispatch
from aweb_secrets.runner_routes import runner_dispatch_router, runner_registration_router
from aweb_secrets.runners import apply_runner_migrations, deregister_runner
from aweb_secrets.status_service import UseStatus
from aweb_secrets.tokens import ProcessTokenCache
from aweb_secrets.use_approvals import UseApprovers, UsePolicies, apply_use_approval_migrations
from aweb_secrets.use_audit import UseApprovalAudit
from aweb_secrets.use_context import UseCommitter, apply_use_context_migrations
from aweb_secrets.use_dispatch_authority import UseDispatchAuthority
from aweb_secrets.use_routes import UseServices, use_router

_LOG = logging.getLogger(__name__)


class _Policies:
    def __init__(self, changes: ChangeSetPolicies, uses: UsePolicies) -> None:
        self._changes, self._uses = changes, uses

    async def current(self, ref: str) -> ActionPolicy | None:
        change = await self._changes.current(ref)
        return change if change is not None else await self._uses.current(ref)


class _Approvers:
    def __init__(self, owners: OwnerDirectory, uses: UseApprovers) -> None:
        self._owners, self._uses = owners, uses

    async def candidates(self, policy: ActionPolicy, request: Mapping[str, Any]) -> list[Approver]:
        provider = self._owners if request.get("type") == CHANGE_TYPE else self._uses
        return await provider.candidates(policy, request)

    async def is_current(self, scope: str, subject: str) -> bool:
        return await self._uses.is_current(scope, subject)


@dataclass
class _Services:
    console: OwnerConsole
    changes: ConsoleChanges
    containment: Containment
    values: ConsoleValues
    use_pages: ConsoleUseApprovals
    activity: ConsoleActivity
    catalog: Catalog
    broker: BrokerRequests
    runs: RunDispatch
    status: UseStatus


async def _compose(
    runtime: NaappRuntime,
    settings: ServiceSettings,
    provider: KeyProvider,
    mailer: Mailer,
    committer: UseCommitter,
    response_key: ResponseKey,
    runner_key: SigningKey,
) -> _Services:
    db = runtime.db()
    fence = runtime.installation_fence()
    # Configure the shared fence; never create another G1 source or fence.
    fence.on_retire = purge_team
    registrations = runtime.hook_registrations()
    store = PgApprovalStore(db)
    await store.migrate()
    for migrate in (
        apply_owner_act_migrations,
        apply_owner_migrations,
        apply_console_migrations,
        apply_change_policy_migrations,
        apply_custody_migrations,
        apply_change_set_migrations,
        apply_dispatch_migrations,
        apply_nonce_migrations,
        apply_job_migrations,
        apply_runner_migrations,
        apply_use_approval_migrations,
        apply_use_context_migrations,
        apply_run_dispatch_migrations,
    ):
        await migrate(db)

    async def approval(tx: TransactionManager, approval_id: str) -> Approval | None:
        return await store.get_in(approval_id, tx)

    async def governance_view(team_id):
        return await registrations.view(team_id, "post-governance-hook")

    async def use_view(team_id):
        return await registrations.view(team_id, "post-secret-use-hook")

    def shared_passkeys() -> Passkeys:
        return passkeys

    contexts = PasskeyContexts(app_id=settings.app_id)
    credentials = CredentialAudit(
        db=db,
        app_id=settings.app_id,
        fence=fence,
        contexts=contexts,
        owner_act_scope=settings.app_id,
        producer=runtime.hook_producer,
        passkeys=shared_passkeys,
        approval=approval,
        registration_view=governance_view,
        max_backlog_age=timedelta(seconds=settings.hook_events_stalled_after_seconds),
    )
    # Run stores are ready before opting this same branch into run recording.
    use_audit = UseApprovalAudit(
        producer=runtime.hook_producer,
        passkeys=shared_passkeys,
        approval=approval,
        max_backlog_age=timedelta(seconds=settings.hook_events_stalled_after_seconds),
        enable_runs=True,
    )
    audit = SecretsAudit(credentials=credentials, use=use_audit)
    passkeys = Passkeys(
        db,
        rp=RelyingParty(origin=settings.console_origin, name="Secrets"),
        delivery=PasskeyEmailDelivery(mailer=mailer, console_origin=settings.console_origin),
        audit=audit,
        retirement=ApprovalRevocation(store, audit),
        enrolment_ttl=timedelta(hours=1),
        challenge_ttl=timedelta(minutes=5),
        owner_scopes=is_owner_scope,
        proof_context=contexts,
    )
    await passkeys.migrate()
    await credentials.migrate()
    owners = OwnerDirectory(passkeys, db)
    approvals = Approvals(
        store=store,
        policies=_Policies(ChangeSetPolicies(db, owners), UsePolicies(db)),
        approvers=_Approvers(owners, UseApprovers(db, passkeys, owners)),
        delivery=ApprovalEmailDelivery(
            mailer=mailer, approval_url=settings.console_origin + "/approvals"
        ),
        authenticators=[passkeys.authenticator()],
        audit=audit,
    )

    async def team_key(team_id):
        return (await runtime.team_cache().get(team_id)).team_did_key

    console = OwnerConsole(
        db=db,
        passkeys=passkeys,
        directory=owners,
        fence=fence,
        verifier=OwnerActVerifier(
            scope=settings.app_id,
            audience=settings.public_origin,
            acts=APP_ACTS,
            team_key_for=team_key,
        ),
        installation=InstallationLookup(fence),
        credential_audit=credentials,
    )
    custody = Custody(provider, db)
    tokens = ProcessTokenCache()

    async def governance(tx: TransactionManager, *, team_id, **event):
        rows = await tx.fetch_all(
            "SELECT installation_id,generation FROM {{tables.installation_fences}}"
            " WHERE app_id=$1 AND team_id=$2 AND state='active'",
            settings.app_id,
            team_id,
        )
        if len(rows) != 1:
            raise GovernanceUnavailable()
        producer = runtime.hook_producer(
            installation_id=rows[0]["installation_id"], generation=rows[0]["generation"]
        )
        if event["payload"].get("direction") == "widening":
            await producer.require_admission(
                tx,
                team_id=team_id,
                hook="post-governance-hook",
                occurred_at=event["occurred_at"],
                view=event.get("view"),
                max_backlog_age=timedelta(seconds=settings.hook_events_stalled_after_seconds),
            )
        return await producer.enqueue(tx, hook="post-governance-hook", team_id=team_id, **event)

    containment = Containment(
        db=db,
        fence=fence,
        approvals=approvals,
        custody=custody,
        passkeys=passkeys,
        directory=owners,
        tokens=tokens,
        governance=governance,
        credential_audit=credentials,
        deregister_runner=deregister_runner,
    )
    writer = ChangeSets(
        db,
        approvals=approvals,
        passkeys=passkeys,
        directory=owners,
        custody=custody,
        containment=containment,
        credential_audit=credentials,
        draft_limit=DraftLimit(count=20, window=timedelta(hours=1)),
        internal_destinations=settings.internal_destinations,
    )
    changes = ConsoleChanges(
        console=console,
        changes=writer,
        approvals=approvals,
        registrations=registrations,
        after_commit=containment.evict,
    )
    opener = UseSecretOpener(
        db,
        native=SecretOpener(provider, db),
        credential_opener=BackendCredentialOpener(provider, db),
    )
    common: dict[str, Any] = dict(
        fence=fence,
        opener=opener,
        committer=committer,
        response_key=response_key,
        producer=runtime.hook_producer,
        registration_view=use_view,
        approvals=approvals,
        use_audit=use_audit,
        max_backlog_age=timedelta(seconds=settings.hook_events_stalled_after_seconds),
        sweep_margin=timedelta(seconds=settings.sweep_margin_seconds),
        derived_max_ttl_s=settings.derived_max_ttl_s,
        internal_destinations=settings.internal_destinations,
    )
    broker = BrokerRequests(
        db,
        **common,
        egress=Egress(
            addresses=AddressPolicy(internal_destinations=settings.internal_destinations),
            resolver=DnsResolver(),
            user_agent="aweb-secrets",
            ca_file=settings.egress_ca_file,
        ),
        tokens=tokens,
        max_dispatch=timedelta(seconds=settings.broker_max_dispatch_seconds),
        approval_authority=lambda principal, admission: UseDispatchAuthority(
            principal=principal, admission=admission, passkeys=passkeys
        ),
    )
    runs = RunDispatch(
        db,
        **common,
        passkeys=passkeys,
        service_key=runner_key,
        origin=settings.public_origin,
        assignment_ttl=timedelta(seconds=settings.runner_assignment_ttl_seconds),
        claim_wait=timedelta(seconds=settings.runner_claim_wait_seconds),
    )
    return _Services(
        console,
        changes,
        containment,
        ConsoleValues(console=console, custody=custody),
        ConsoleUseApprovals(
            console=console, approvals=approvals, use_audit=use_audit, registration_view=use_view
        ),
        ConsoleActivity(console=console, reads=ActivityReads()),
        Catalog(db, fence=fence),
        broker,
        runs,
        UseStatus(db, fence=fence, approvals=approvals, runs=runs.status),
    )


async def _recover(services: _Services, stop: asyncio.Event, interval: int) -> None:
    while not stop.is_set():
        for service in (services.broker, services.runs):
            try:
                await service.sweep()
            except Exception:
                # No retry of an effect: these services recover persisted work.
                _LOG.error("dispatch recovery unavailable")
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except TimeoutError:
            pass


def create_service(
    settings: ServiceSettings,
    *,
    awid_transport: httpx.AsyncBaseTransport | None = None,
    team_server_transport: httpx.AsyncBaseTransport | None = None,
) -> SecretsService:
    """The production entry point; construction and startup require every dependency."""
    key_files = {
        "secret_request_key_file": settings.secret_request_key_file,
        "secret_params_key_file": settings.secret_params_key_file,
        "response_key_file": settings.response_key_file,
        "runner_service_key_file": settings.runner_service_key_file,
        **{f"app_key_files.{kid}": path for kid, path in settings.app_key_files.items()},
    }
    if settings.custody_key_file is not None:
        key_files["custody_key_file"] = settings.custody_key_file
    material = set()
    for name, path in key_files.items():
        # All these loaders use the shared 64-hex key-file format. They still
        # validate that format themselves; comparison never exposes material.
        value = read_key_file(path).rstrip(b"\n").lower()
        if value in material:
            raise ValueError(f"independent key material is required for {name}")
        material.add(value)
    provider: KeyProvider
    if settings.custody_key_file is not None:
        provider = LocalKeyFileProvider(settings.custody_key_file)
    elif settings.kms_key_id:
        provider = AwsKmsProvider(key_id=settings.kms_key_id, region_name=settings.kms_region)
    else:
        raise ValueError("custody provider is required")
    committer = UseCommitter.from_files(
        settings.secret_request_key_file, settings.secret_params_key_file
    )
    response_key = ResponseKey.from_file(settings.response_key_file)
    runner_key = read_signing_key_file(settings.runner_service_key_file)
    email = {
        "EMAIL_SMTP_HOST": settings.email_smtp_host,
        "EMAIL_SMTP_PORT": str(settings.email_smtp_port),
        "EMAIL_TLS": settings.email_tls,
        "EMAIL_USERNAME": settings.email_username,
        "EMAIL_PASSWORD_FILE": str(settings.email_password_file),
        "EMAIL_FROM": settings.email_from,
    }
    if settings.email_ca_file is not None:
        email["EMAIL_CA_FILE"] = str(settings.email_ca_file)
    mailer = Mailer(EmailSettings.from_env("", environ=email))
    active: _Services | None = None

    def current() -> _Services:
        if active is None:
            raise RuntimeError("secrets services are not initialized")
        return active

    async def kms():
        try:
            await asyncio.to_thread(seal_canary, provider)
        except CustodyUnavailable:
            return CheckResult(ok=False)
        return CheckResult(ok=True)

    async def tool_policy(request, principal, tool):
        # B1 validates member/manifest/context/granted scopes. Each business
        # service owns its transaction's role, record, policy and final fences.
        return True

    @asynccontextmanager
    async def prepare(runtime):
        nonlocal active
        active = await _compose(
            runtime, settings, provider, mailer, committer, response_key, runner_key
        )
        stop = asyncio.Event()
        recovery = asyncio.create_task(_recover(active, stop, settings.sweep_interval_seconds))
        try:
            yield
        finally:
            stop.set()
            try:
                await recovery
            finally:
                active = None

    def metadata(runtime: NaappRuntime, authorized: Authorized) -> APIRouter:
        return metadata_router(
            MetadataServices(catalog=lambda: current().catalog), authorized=authorized
        )

    def uses(runtime: NaappRuntime, authorized: Authorized) -> APIRouter:
        services = current()
        return use_router(
            UseServices(
                broker=lambda: services.broker,
                runs=lambda: services.runs,
                status=lambda: services.status,
            ),
            authorized=authorized,
        )

    def contain(runtime: NaappRuntime, authorized: Authorized) -> APIRouter:
        return containment_api_router(current().containment, authorized=authorized)

    def human(factory: Callable[[_Services], APIRouter]) -> ConsoleRouter:
        def build(runtime: NaappRuntime) -> APIRouter:
            return factory(current())

        return build

    return create_app(
        settings,
        policy=tool_policy,
        kms=kms,
        awid_transport=awid_transport,
        team_server_transport=team_server_transport,
        prepare=prepare,
        tool_routers=(metadata, uses, contain),
        console_routers=(
            human(lambda s: owner_console_router(s.console)),
            human(lambda s: console_ui_router(sessions=s.console.sessions)),
            human(lambda s: console_bootstrap_router()),
            human(lambda s: console_values_router(s.values)),
            human(lambda s: console_changes_router(s.changes)),
            human(lambda s: console_forms_router(changes=s.changes)),
            human(lambda s: console_jobs_router(changes=s.changes)),
            human(lambda s: console_use_approvals_router(services=s.use_pages)),
            human(lambda s: console_run_approvals_router(services=s.use_pages)),
            human(lambda s: console_activity_router(services=s.activity)),
            human(lambda s: containment_console_router(s.containment, console=s.console)),
        ),
        runner_routers=(
            lambda rt: runner_registration_router(
                db=rt.db, origin=settings.public_origin, service_key=runner_key
            ),
            lambda rt: runner_dispatch_router(service=lambda: current().runs),
        ),
    )
