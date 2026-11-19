"""Production composition: one runtime and one shared set of business services."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass, replace
from datetime import timedelta
from enum import StrEnum
from functools import partial
from ipaddress import IPv4Network, IPv6Network
from typing import Any

import httpx
from aweb_naapp.console import (
    ClientIdentity,
    ConsoleSession,
    KeyBoundConsoleSession,
)
from aweb_naapp.console.handoff_authority import HandoffAuthority, PreparedSessionTarget
from aweb_naapp.console.handoff_requester import requester_parent
from aweb_naapp.console.handoff_sessions import ConsoleHandoffs
from aweb_naapp.egress import AddressPolicy, DnsResolver, Egress
from aweb_naapp.email import EmailSettings, Mailer
from aweb_naapp.hooks.owner_act import HUMAN_ROLE_ACTS
from aweb_naapp.hooks.owner_act_nonces import OwnerActVerifier
from aweb_naapp.hooks.producer import RegistrationView
from aweb_naapp.key_file import read_key_file
from aweb_naapp.roles import is_holding_scope
from aweb_naapp.runtime.app import NaappRuntime
from aweb_naapp.runtime.approvals import (
    ActionPolicy,
    Approval,
    ApprovalRevocation,
    Approvals,
    Approver,
    PgApprovalStore,
)
from aweb_naapp.runtime.credential_audit import CredentialAudit, GovernanceUnavailable
from aweb_naapp.runtime.db import ApplyMigrations
from aweb_naapp.runtime.health import CheckResult
from aweb_naapp.runtime.human_role_acts import HumanRoleActs
from aweb_naapp.runtime.installation import AdmittedInstallation
from aweb_naapp.runtime.owner_act_delivery import OwnerActEffectResult
from aweb_naapp.runtime.owner_act_router import OwnerActLimiter, mount_owner_act_routes
from aweb_naapp.runtime.passkeys import Passkeys, RelyingParty
from aweb_naapp.signing_key import read_signing_key_file
from awid.dns_verify import DomainVerifier
from fastapi import APIRouter, Request
from pgdbm.core import TransactionManager

from aweb_secrets.activity_service import ActivityReads
from aweb_secrets.app import (
    Authorized,
    ConsoleRouter,
    OwnerApplicationServices,
    SecretsService,
    create_app,
)
from aweb_secrets.approval_email import ApprovalEmailDelivery
from aweb_secrets.approval_kind import ApprovalKind, approval_kind
from aweb_secrets.audit_sink import SecretsAudit
from aweb_secrets.broker_service import BrokerRequests
from aweb_secrets.catalog import Catalog
from aweb_secrets.change import TYPE as CHANGE_TYPE
from aweb_secrets.change_sets import (
    ChangeSetPolicies,
    ChangeSets,
    DraftLimit,
)
from aweb_secrets.config import ServiceSettings
from aweb_secrets.console import OwnerConsole, owner_console_router
from aweb_secrets.console_access import ConsoleAccess, console_access_router
from aweb_secrets.console_activity import ConsoleActivity, console_activity_router
from aweb_secrets.console_audit_delivery import ConsoleAuditDelivery, console_audit_delivery_router
from aweb_secrets.console_bootstrap import console_bootstrap_router
from aweb_secrets.console_changes import ConsoleChanges, console_changes_router
from aweb_secrets.console_forms import console_forms_router
from aweb_secrets.console_forms.native import native_value_forms_router
from aweb_secrets.console_jobs import console_jobs_router
from aweb_secrets.console_reconciliation import ConsoleReconciliation, console_reconciliation_router
from aweb_secrets.console_ui import console_ui_router
from aweb_secrets.console_use_approvals import (
    ConsoleUseApprovals,
    console_run_approvals_router,
    console_use_approvals_router,
)
from aweb_secrets.console_values import ConsoleValues, console_values_router
from aweb_secrets.containment import Containment
from aweb_secrets.containment_routes import containment_api_router, containment_console_router
from aweb_secrets.credential_governance import (
    CREDENTIAL_AUDIT_MIGRATIONS,
    ChangeApprovals,
    credential_role,
)
from aweb_secrets.custody import (
    AwsKmsProvider,
    BackendCredentialOpener,
    Custody,
    KeyProvider,
    LocalKeyFileProvider,
    SecretOpener,
)
from aweb_secrets.custody.opening import UseSecretOpener
from aweb_secrets.human_holders import OwnerHoldingAuthority
from aweb_secrets.human_holding_identity import owner_holding_identity
from aweb_secrets.installation_lookup import InstallationLookup
from aweb_secrets.metadata_routes import MetadataServices, metadata_router
from aweb_secrets.onepassword_reconciliation import BackendReconciler
from aweb_secrets.owners import OWNER_ROLE, OwnerDirectory, is_owner_scope
from aweb_secrets.passkey_context import PasskeyContexts
from aweb_secrets.passkey_email import PasskeyEmailDelivery
from aweb_secrets.reconciliation_control_audit import (
    ReconciliationAudit,
)
from aweb_secrets.reconciliation_policy import ReconciliationApprovers, ReconciliationPolicies
from aweb_secrets.reconciliation_providers import (
    ReconciliationApproverRouter,
    ReconciliationAuditRouter,
    ReconciliationPolicyRouter,
)
from aweb_secrets.reconciliation_reads import ReconciliationReads
from aweb_secrets.reconciliation_service import ReconciliationControls
from aweb_secrets.response_audit import ResponseKey
from aweb_secrets.retirement import retire_team
from aweb_secrets.revisions import bump_config_revision
from aweb_secrets.run_service import RunDispatch
from aweb_secrets.runner_routes import runner_dispatch_router, runner_registration_router
from aweb_secrets.schema import prepare_business_schema
from aweb_secrets.status_service import UseStatus
from aweb_secrets.tokens import ProcessTokenCache
from aweb_secrets.use_approvals import UseApprovers, UsePolicies
from aweb_secrets.use_audit import UseApprovalAudit
from aweb_secrets.use_context import UseCommitter
from aweb_secrets.use_dispatch_authority import UseDispatchAuthority
from aweb_secrets.use_routes import UseServices, use_router

_LOG = logging.getLogger(__name__)


class CustodyMode(StrEnum):
    KMS = "kms"
    LOCAL_KEY_FILE = "local_key_file"


class _Policies:
    def __init__(self, changes: ChangeSetPolicies, uses: UsePolicies) -> None:
        self._changes, self._uses = changes, uses

    async def current(
        self, ref: str, *, tx: TransactionManager | None = None
    ) -> ActionPolicy | None:
        change = await self._changes.current(ref, tx=tx)
        return change if change is not None else await self._uses.current(ref, tx=tx)


class _Approvers:
    def __init__(self, owners: OwnerDirectory, uses: UseApprovers) -> None:
        self._owners, self._uses = owners, uses

    async def candidates(
        self,
        policy: ActionPolicy,
        request: Mapping[str, Any],
        *,
        tx: TransactionManager | None = None,
    ) -> list[Approver]:
        provider = self._owners if request.get("type") == CHANGE_TYPE else self._uses
        return await provider.candidates(policy, request, tx=tx)

    async def is_current(
        self, scope: str, subject: str, *, tx: TransactionManager | None = None
    ) -> bool:
        return await self._uses.is_current(scope, subject, tx=tx)


@dataclass(kw_only=True)
class SecretsServices:
    owner: OwnerApplicationServices
    owner_delivery: APIRouter
    handoffs: ConsoleHandoffs
    changes: ConsoleChanges
    containment: Containment
    values: ConsoleValues
    use_pages: ConsoleUseApprovals
    activity: ConsoleActivity
    audit_delivery: ConsoleAuditDelivery
    catalog: Catalog
    broker: BrokerRequests
    runs: RunDispatch
    status: UseStatus
    custody: Custody
    reconciliation: ConsoleReconciliation

    @property
    def console(self) -> OwnerConsole:
        return self.owner.console


@dataclass(frozen=True, kw_only=True)
class _OwnerDelivery:
    router: APIRouter
    verifier: OwnerActVerifier


async def _advance_owner_revision(
    tx: TransactionManager,
    installation: AdmittedInstallation,
    result: OwnerActEffectResult,
) -> None:
    # The shared writer invokes this after the role/B3 effect in its original
    # nonce/effect/governance transaction; revision remains the final SQL lock.
    await bump_config_revision(tx, installation.installation_id, team_id=installation.team_id)


def _owner_delivery_router(
    *,
    runtime: NaappRuntime,
    settings: ServiceSettings,
    passkeys: Passkeys,
    credentials: CredentialAudit,
    team_key_for: Callable[[str], Awaitable[str]],
) -> _OwnerDelivery:
    """Compose human-role delivery at its human origin (secrets.md:1677-1687)."""
    router = APIRouter()
    verifier = OwnerActVerifier(
        scope=settings.app_id,
        audience=settings.console_origin,
        acts=HUMAN_ROLE_ACTS,
        team_key_for=team_key_for,
    )
    mount_owner_act_routes(
        router,
        runtime=runtime,
        effect=HumanRoleActs(
            roles=frozenset({OWNER_ROLE}),
            notice_roles=frozenset({OWNER_ROLE}),
            passkeys=passkeys,
            recorder=credentials,
            check_member=runtime.check_human_role_member,
            on_applied=_advance_owner_revision,
        ),
        verifier=verifier,
        limiter=OwnerActLimiter(
            client_identity=ClientIdentity(trusted_header=settings.client_address_header),
            limit=12,
            window=timedelta(minutes=1),
        ),
    )
    return _OwnerDelivery(router=router, verifier=verifier)


@dataclass(frozen=True, kw_only=True)
class _ApprovalServices:
    passkeys: Passkeys
    credentials: CredentialAudit
    owners: OwnerDirectory
    approvals: Approvals
    use_audit: UseApprovalAudit
    use_view: Callable[[str], Awaitable[RegistrationView | None]]
    reconciliation_reads: ReconciliationReads
    reconciliation_audit: ReconciliationAudit


async def _compose_approvals(
    *, runtime: NaappRuntime, settings: ServiceSettings, store: PgApprovalStore, mailer: Mailer
) -> _ApprovalServices:
    """Share the B2/B3 and audit lifecycle required by secrets.md §11.2."""
    db = runtime.db()
    fence = runtime.installation_fence()
    registrations = runtime.hook_registrations()

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
        role_of=credential_role,
        human_roles=frozenset({OWNER_ROLE}),
        approvals=ChangeApprovals(approval),
        registration_view=governance_view,
        max_backlog_age=timedelta(seconds=settings.hook_events_stalled_after_seconds),
        migration_module=CREDENTIAL_AUDIT_MIGRATIONS,
    )
    # Run stores are ready before opting this same branch into run recording.
    use_audit = UseApprovalAudit(
        producer=runtime.hook_producer,
        passkeys=shared_passkeys,
        approval=approval,
        max_backlog_age=timedelta(seconds=settings.hook_events_stalled_after_seconds),
        enable_runs=True,
    )
    reads = ReconciliationReads(enable_runs=True)
    control_audit = ReconciliationAudit(reads=reads, approval=approval, passkeys=shared_passkeys)
    audit = ReconciliationAuditRouter(
        standard=SecretsAudit(credentials=credentials, use=use_audit), controls=control_audit
    )
    passkeys = Passkeys(
        db,
        rp=RelyingParty(origin=settings.console_origin, name="Secrets"),
        delivery=PasskeyEmailDelivery(mailer=mailer, console_origin=settings.console_origin),
        audit=audit,
        retirement=ApprovalRevocation(store, audit),
        enrolment_ttl=timedelta(hours=1),
        challenge_ttl=timedelta(minutes=5),
        owner_scopes=is_owner_scope,
        holding_scopes=is_holding_scope,
        proof_context=contexts,
    )
    owners = OwnerDirectory(passkeys, db)
    approvals = Approvals(
        store=store,
        policies=ReconciliationPolicyRouter(
            standard=_Policies(ChangeSetPolicies(db, owners), UsePolicies(db)),
            controls=ReconciliationPolicies(db, owners=owners),
        ),
        approvers=ReconciliationApproverRouter(
            standard=_Approvers(owners, UseApprovers(db, passkeys, owners)),
            controls=ReconciliationApprovers(owners=owners),
        ),
        delivery=ApprovalEmailDelivery(
            mailer=mailer, approval_url=settings.console_origin + "/approvals"
        ),
        authenticators=[passkeys.authenticator()],
        audit=audit,
    )

    return _ApprovalServices(
        passkeys=passkeys,
        credentials=credentials,
        owners=owners,
        approvals=approvals,
        use_audit=use_audit,
        use_view=use_view,
        reconciliation_reads=reads,
        reconciliation_audit=control_audit,
    )


async def _compose(
    runtime: NaappRuntime,
    settings: ServiceSettings,
    provider: KeyProvider,
    mailer: Mailer,
    committer: UseCommitter,
    response_key: ResponseKey,
    run_dispatch: Callable[..., RunDispatch],
) -> SecretsServices:
    db = runtime.db()
    fence = runtime.installation_fence()
    # Configure the shared fence; never create another G1 source or fence.
    fence.on_retire = partial(retire_team, app_id=settings.app_id)
    registrations = runtime.hook_registrations()
    if isinstance(runtime.schema_preparation, ApplyMigrations):
        store = await prepare_business_schema(db)
    else:
        store = PgApprovalStore(db)

    approval_services = await _compose_approvals(
        runtime=runtime, settings=settings, store=store, mailer=mailer
    )
    passkeys = approval_services.passkeys
    credentials = approval_services.credentials
    owners = approval_services.owners
    approvals = approval_services.approvals
    use_audit = approval_services.use_audit
    use_view = approval_services.use_view

    async def current_team_controller_key(team_id: str) -> str:
        return (await runtime.team_cache().get(team_id)).team_did_key

    owner_delivery = _owner_delivery_router(
        runtime=runtime,
        settings=settings,
        passkeys=passkeys,
        credentials=credentials,
        team_key_for=current_team_controller_key,
    )

    # These callbacks close the construction cycle without replacing the
    # console's original sessions, database or passkeys. They are called only
    # after the one factory below has been built.
    handoffs: ConsoleHandoffs

    async def key_bound(request: Request) -> ConsoleSession:
        return await handoffs.current(request)

    async def prepare_key_bound(
        tx: TransactionManager,
        current: KeyBoundConsoleSession,
        *,
        approver_pairs: Sequence[tuple[str, str]],
    ) -> PreparedSessionTarget:
        return await handoffs.prepare(tx, current, approver_pairs=approver_pairs)

    console = OwnerConsole(
        db=db,
        passkeys=passkeys,
        directory=owners,
        fence=fence,
        installation=InstallationLookup(fence),
        credential_audit=credentials,
        client_address_header=settings.client_address_header,
        key_bound=key_bound,
        prepare_key_bound=prepare_key_bound,
    )
    holding = OwnerHoldingAuthority(console=console)
    handoffs = ConsoleHandoffs(
        db=db,
        passkeys=passkeys,
        authority=HandoffAuthority(
            holding.credential_target,
            holding.session_target,
            holding.hold_session_target,
            holding.check_session_target,
            owner_holding_identity,
        ),
        principal=runtime.principal,
        human_member=runtime.check_human_member,
        limiter=console.limiter,
        requester_parent=requester_parent(runtime.registry_client()),
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
        prepare_key_bound=prepare_key_bound,
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
        handoffs=handoffs,
        # All three association stores and their typed pages share this root.
        approval_kind=partial(approval_kind, enabled_kinds=frozenset(ApprovalKind)),
    )
    reconciler = BackendReconciler(db=db, custody=custody, containment=containment, fence=fence)
    opener = UseSecretOpener(
        db,
        native=SecretOpener(provider, db),
        credential_opener=BackendCredentialOpener(provider, db),
    )
    common: dict[str, Any] = dict(
        fence=fence,
        opener=opener,
        reconciler=reconciler,
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
            addresses=AddressPolicy(
                internal_destinations=settings.internal_destinations,
                denied=settings.egress_denied_networks,
            ),
            resolver=DnsResolver(),
            user_agent="aweb-secrets",
            ca_file=settings.egress_ca_file,
        ),
        tokens=tokens,
        max_dispatch=timedelta(seconds=settings.broker_max_dispatch_seconds),
        response_budget_bytes=settings.broker_response_budget_bytes,
        approval_authority=lambda principal, admission: UseDispatchAuthority(
            principal=principal, admission=admission, passkeys=passkeys
        ),
    )
    runs = run_dispatch(
        db,
        **common,
        pins=custody.run_pins,
        passkeys=passkeys,
        origin=settings.public_origin,
        assignment_ttl=timedelta(seconds=settings.runner_assignment_ttl_seconds),
        claim_wait=timedelta(seconds=settings.runner_claim_wait_seconds),
    )
    containment.deregister_runner = runs.deregister_runner
    reconciliation = ConsoleReconciliation(
        console=console,
        reads=approval_services.reconciliation_reads,
        controls=ReconciliationControls(
            reads=approval_services.reconciliation_reads,
            audit=approval_services.reconciliation_audit,
            approvals=approvals,
            passkeys=passkeys,
            use_audit=use_audit,
            broker=broker,
            runs=runs,
        ),
        approvals=approvals,
    )
    return SecretsServices(
        owner=OwnerApplicationServices(console=console, verifier=owner_delivery.verifier),
        owner_delivery=owner_delivery.router,
        handoffs=handoffs,
        changes=changes,
        containment=containment,
        values=ConsoleValues(console=console, custody=custody),
        use_pages=ConsoleUseApprovals(
            console=console, approvals=approvals, use_audit=use_audit, registration_view=use_view
        ),
        activity=ConsoleActivity(console=console, reads=ActivityReads()),
        audit_delivery=ConsoleAuditDelivery(
            console=console,
            registrations=registrations,
            max_backlog_age=timedelta(seconds=settings.hook_events_stalled_after_seconds),
        ),
        catalog=Catalog(db, fence=fence),
        broker=broker,
        runs=runs,
        status=UseStatus(db, fence=fence, approvals=approvals, runs=runs.status),
        custody=custody,
        reconciliation=reconciliation,
    )


async def _recover(services: SecretsServices, stop: asyncio.Event, interval: int) -> None:
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
    awid_domain_verifier: DomainVerifier | None = None,
    team_server_transport: httpx.AsyncBaseTransport | None = None,
    hook_egress: Egress | None = None,
    hook_internal_cidr: IPv4Network | IPv6Network | None = None,
    hook_internal_origins: frozenset[str] = frozenset(),
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
    custody_mode = {
        LocalKeyFileProvider: CustodyMode.LOCAL_KEY_FILE,
        AwsKmsProvider: CustodyMode.KMS,
    }[type(provider)]
    committer = UseCommitter.from_files(
        settings.secret_request_key_file, settings.secret_params_key_file
    )
    response_key = ResponseKey.from_file(settings.response_key_file)
    runner_key = read_signing_key_file(settings.runner_service_key_file)
    run_dispatch = partial(RunDispatch, service_key=runner_key)
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

    def current() -> SecretsServices:
        if service.services is None:
            raise RuntimeError("secrets services are not initialized")
        return service.services

    async def kms():
        if service.services is None:
            return CheckResult(ok=False)
        return CheckResult(ok=(await service.services.custody.health()).ok)

    async def tool_policy(request, principal, tool):
        # B1 validates member/manifest/context/granted scopes. Each business
        # service owns its transaction's role, record, policy and final fences.
        return True

    @asynccontextmanager
    async def prepare(runtime):
        service.services = await _compose(
            runtime, settings, provider, mailer, committer, response_key, run_dispatch
        )
        stop = asyncio.Event()
        recovery = asyncio.create_task(_recover(current(), stop, settings.sweep_interval_seconds))
        try:
            yield
        finally:
            stop.set()
            try:
                await recovery
            finally:
                service.services = None

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

    def human(factory: Callable[[SecretsServices], APIRouter]) -> ConsoleRouter:
        def build(runtime: NaappRuntime) -> APIRouter:
            return factory(current())

        return build

    if hook_egress is None:
        hook_egress = Egress(
            addresses=AddressPolicy(denied=settings.egress_denied_networks),
            resolver=DnsResolver(),
            user_agent="aweb-naapp/hooks",
        )
    else:
        hook_egress = replace(
            hook_egress,
            addresses=replace(
                hook_egress.addresses,
                denied=tuple(
                    dict.fromkeys((*hook_egress.addresses.denied, *settings.egress_denied_networks))
                ),
            ),
        )

    service = create_app(
        settings,
        policy=tool_policy,
        kms=kms,
        health_labels={"custody_mode": custody_mode},
        awid_transport=awid_transport,
        awid_domain_verifier=awid_domain_verifier,
        team_server_transport=team_server_transport,
        hook_egress=hook_egress,
        hook_internal_cidr=hook_internal_cidr,
        hook_internal_origins=hook_internal_origins,
        prepare=prepare,
        tool_routers=(metadata, uses, contain),
        handoff_router=lambda rt: current().handoffs.api_router(),
        console_routers=(
            human(lambda s: s.owner_delivery),
            human(lambda s: s.handoffs.human_router()),
            human(lambda s: owner_console_router(s.console)),
            human(
                lambda s: console_ui_router(
                    sessions=s.console.sessions, banner=s.audit_delivery.banner
                )
            ),
            human(lambda s: console_bootstrap_router()),
            human(lambda s: console_values_router(s.values)),
            human(lambda s: console_changes_router(s.changes)),
            human(lambda s: console_forms_router(changes=s.changes)),
            human(lambda s: native_value_forms_router(values=s.values)),
            human(lambda s: console_jobs_router(changes=s.changes)),
            human(lambda s: console_use_approvals_router(services=s.use_pages)),
            human(lambda s: console_run_approvals_router(services=s.use_pages)),
            human(lambda s: console_activity_router(services=s.activity)),
            human(lambda s: console_reconciliation_router(services=s.reconciliation)),
            human(lambda s: console_access_router(services=ConsoleAccess(console=s.console))),
            human(lambda s: console_audit_delivery_router(services=s.audit_delivery)),
            human(lambda s: containment_console_router(s.containment, console=s.console)),
        ),
        runner_routers=(
            lambda rt: runner_registration_router(
                db=rt.db, origin=settings.public_origin, service_key=runner_key
            ),
            lambda rt: runner_dispatch_router(service=lambda: current().runs),
        ),
        schema_preparation=ApplyMigrations(),
    )
    return service
