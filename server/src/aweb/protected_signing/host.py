"""Runnable independent protected server; no automatic authority bootstrap.

Run ``uvicorn aweb.protected_signing.host:create_app --factory`` with explicit
AWEB_PROTECTED_* operator settings. TLS terminates at the configured human
origin; the shared origin splitter enforces the two route/credential surfaces.
"""

from contextlib import AsyncExitStack, asynccontextmanager
from datetime import timedelta
from pathlib import Path
from typing import Annotated

from aweb_naapp.console import (
    ClientIdentity,
    LoginLimiter,
    apply_console_migrations,
    console_login_router,
)
from aweb_naapp.console.handoff_store import HandoffStore
from aweb_naapp.email import EmailSettings, Mailer
from aweb_naapp.hooks.strictjson import parse_strict
from aweb_naapp.key_file import read_key_file
from aweb_naapp.runtime.origins import OriginApps
from aweb_naapp.runtime.protected_signer import SignerRefused
from awid.db_config import build_database_config
from awid.did import did_key_from_signing_key
from awid.registry import RegistryClient
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pgdbm import AsyncDatabaseManager
from pydantic import Field, SecretStr, StrictInt, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from ..config import load_member_signing_keys
from .composition import IndependentProtectedSigner
from .custody import ProtectedControllerCustody
from .notifications import ProtectedNotifications
from .profile import ProtectedServiceProfile


class HostSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AWEB_PROTECTED_", extra="forbid", hide_input_in_errors=True
    )

    profile_file: Path
    scope_file: Path
    controller_key_file: Path
    controller_keys_file: Path | None = None
    member_keys_file: Path
    worker_uids: list[Annotated[StrictInt, Field(gt=0)]] = Field(min_length=1)
    database_url: SecretStr = Field(default_factory=lambda: SecretStr(""), repr=False)
    database_url_file: Path | None = None
    database_schema: str = Field(
        default="protected_signer", pattern=r"^[a-z][a-z0-9_]{0,62}$"
    )
    database_uses_transaction_pooler: bool = False
    human_csrf_key: str = Field(
        default="aweb.protected.console.csrf", pattern=r"^[A-Za-z0-9._-]{1,128}$"
    )
    trusted_client_header: str | None = Field(
        default=None, pattern=r"^[A-Za-z][A-Za-z0-9_-]{0,127}$"
    )

    def client_identity(self):
        return ClientIdentity(trusted_header=self.trusted_client_header)

    @model_validator(mode="after")
    def database_source(self):
        if self.database_url_file is not None:
            if "database_url" in self.model_fields_set:
                raise ValueError("protected_database_url_sources_conflict")
            try:
                value = (
                    read_key_file(self.database_url_file)
                    .decode("utf-8")
                    .removesuffix("\n")
                )
                if not value or any(char in value for char in ("\n", "\r", "\x00")):
                    raise ValueError()
            except (OSError, ValueError):
                # Configuration failures never expose DSN contents. The
                # existing pgdbm/asyncpg adapter remains the only DSN parser.
                raise ValueError("protected_database_url_file_invalid") from None
            # Preserve declared input provenance on instance revalidation:
            # this compatibility value is derived, not a second DSN source.
            object.__setattr__(self, "database_url", SecretStr(value))
        if not self.database_url.get_secret_value():
            raise ValueError("protected_database_url_required")
        return self


def _member_keys(path):
    """The server's own member-key loader, with the signer's error code."""
    try:
        return load_member_signing_keys(path, allow_empty=True)
    except (OSError, ValueError, TypeError):
        raise ValueError("protected_member_keys_invalid") from None


async def validate_provisioning(composition):
    """Refuse missing/currently mismatched authority without inventing a grant.

    This is startup evidence only. Shared operations still perform their own
    fresh observation and transaction fences on every use.
    """
    c = composition
    if hasattr(c, "components"):
        for component in c.components:
            await validate_provisioning(component)
        return
    observation = await c.authority.observe(c.context, purpose="prepare")
    async with c.db.transaction() as tx:
        row = await c.authority.binding(tx, hold=True)
        if row["generation"] != c.context.generation:
            raise SignerRefused("authority_changed")
        await c.signer.policies.current("aweb.human-assurance/1", tx=tx)
        approver = await tx.fetch_value(
            "SELECT 1 FROM {{tables.passkey_approvers}} "
            "WHERE scope=$1 AND subject=$2 AND superseded_at IS NULL "
            "AND effective_at<=clock_timestamp()",
            row["b3_scope"],
            row["subject"],
        )
        if not approver:
            raise SignerRefused("authority_changed")
        observation.require_fresh()


def load_custodies(settings, *, profile, scope):
    """Validate every private slot before opening a database or registry client."""
    selected = profile.binding_for(scope)
    bindings = [selected]
    paths = {selected.authority_key_did: settings.controller_key_file}
    if settings.controller_keys_file is not None:
        raw = settings.controller_keys_file.read_bytes()
        if len(raw) > 65536:
            raise SignerRefused("custody_not_isolated")
        manifest = parse_strict(raw)
        if type(manifest) is not dict or not manifest or any(type(key) is not str or type(value) is not str or not Path(value).is_absolute() for key, value in manifest.items()):
            raise SignerRefused("custody_not_isolated")
        bindings = list(profile.bindings)
        if set(manifest) != {b.authority_key_did for b in bindings} or Path(manifest[selected.authority_key_did]) != settings.controller_key_file:
            raise SignerRefused("custody_not_isolated")
        paths = {key: Path(value) for key, value in manifest.items()}
    custodians = []
    for binding in bindings:
        context = binding.context()
        custody = ProtectedControllerCustody(
            service_id=context.service_id, team_id=context.authority_id, domain=context.authority_domain,
            key_file=paths[binding.authority_key_did], worker_uids=frozenset(settings.worker_uids), authority_kind=context.authority_kind,
        )
        if custody.team_key_did != binding.authority_key_did:
            raise SignerRefused("authority_changed")
        custodians.append((binding, custody))
    keys = _member_keys(settings.member_keys_file)
    if any(binding.context().authority_kind == "team_controller" and binding.context().authority_id not in keys for binding, _ in custodians):
        raise SignerRefused("custody_not_isolated")
    private_keys = {custody.team_key_did for _, custody in custodians}
    if any(did_key_from_signing_key(key) in private_keys for key in keys.values()):
        raise SignerRefused("custody_not_isolated")
    return selected, keys, custodians


@asynccontextmanager
async def open_composition(
    settings, *, profile, scope, mailer, registry_transport=None
):
    """The same isolated custody and owned DB/client for host and local admin."""
    selected, keys, custodians = load_custodies(settings, profile=profile, scope=scope)
    async with AsyncExitStack() as resources:
        db = AsyncDatabaseManager(
            build_database_config(
                connection_string=settings.database_url.get_secret_value(),
                schema=settings.database_schema,
                min_connections=1,
                max_connections=5,
                uses_transaction_pooler=settings.database_uses_transaction_pooler,
            )
        )
        resources.push_async_callback(db.disconnect)
        await db.connect()
        registry = RegistryClient(
            registry_url=profile.registry_origin,
            transport=registry_transport,
            member_signing_keys=keys,
        )
        resources.push_async_callback(registry.aclose)
        groups = []

        async def proof_context(scope, *, tx):
            if not groups:
                raise SignerRefused("scope_refused")
            return await groups[0].context_for_scope(scope, tx=tx)

        components = [IndependentProtectedSigner.from_profile(
            db, profile=profile, scope=binding.scope.model_dump(mode="json"), registry_client=registry, custody=custody,
            delivery=ProtectedNotifications(db=db, mailer=mailer, human_origin=profile.human_origin),
            proof_context=proof_context if len(custodians) > 1 else None,
        ) for binding, custody in custodians]
        composition = components[0]
        if len(components) > 1:
            from .group import ProtectedSignerGroup

            composition = ProtectedSignerGroup(components,
                selected=next(c for c in components if c.context == selected.context()))
            groups.append(composition)
        yield composition


def create_app(settings=None, *, mailer=None, registry_transport=None):
    """Own one DB/registry lifetime and mount the sole shared human page.

    In-process hosts may supply their existing configured mailer/transport;
    the process entry point uses the existing TLS Mailer settings. Neither
    injection constructs sessions, UV assertions, authority or signed effects.
    """
    settings = HostSettings() if settings is None else settings
    profile = ProtectedServiceProfile.from_json(settings.profile_file.read_bytes())
    scope = parse_strict(settings.scope_file.read_bytes())
    profile.binding_for(scope)
    # Validate origin separation before any resource opens, even when both
    # origins share a process behind a TLS reverse proxy.
    human = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @asynccontextmanager
    async def lifespan(api):
        async with AsyncExitStack() as resources:
            resources.callback(
                api.router.routes.__setitem__, slice(None), list(api.router.routes)
            )
            resources.callback(
                human.router.routes.__setitem__, slice(None), list(human.router.routes)
            )
            composition = await resources.enter_async_context(
                open_composition(
                    settings,
                    profile=profile,
                    scope=scope,
                    mailer=configured_mailer,
                    registry_transport=registry_transport,
                )
            )
            db = composition.db
            await composition.migrate()
            await apply_console_migrations(db)
            await validate_provisioning(composition)
            # The page source is a composed dependency. Load it only when
            # mounting the complete host, not for local settings validation.
            from aweb_naapp.console.handoff_page import handoff_page_router

            from .bootstrap import bootstrap_router

            sessions = composition.protected_sessions()
            limiter = LoginLimiter(
                db,
                client_identity=settings.client_identity(),
                limit=30,
                window=timedelta(minutes=1),
            )
            human.include_router(
                bootstrap_router(
                    composition,
                    csrf_key=settings.human_csrf_key,
                    limiter=limiter,
                )
            )
            mount = composition.operations_http(
                limiter=limiter,
                human_sessions=sessions,
                human_csrf_key=settings.human_csrf_key,
            )
            api.include_router(mount.api_router())
            human.include_router(
                console_login_router(sessions=sessions, limiter=limiter)
            )
            human.include_router(mount.human_router())
            human.include_router(
                handoff_page_router(
                    store=HandoffStore(db), limiter=limiter, protected_operations=mount
                )
            )
            api.state.composition = human.state.composition = composition
            api.state.protected_ready = True
            try:
                yield
            finally:
                api.state.protected_ready = False
                del api.state.composition
                del human.state.composition

    api = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    api.state.protected_ready = False

    @api.get("/readyz")
    async def readiness():
        ready = api.state.protected_ready
        return JSONResponse(
            {"ready": ready},
            status_code=200 if ready else 503,
            headers={"Cache-Control": "no-store"},
        )

    host = OriginApps(
        api,
        human,
        agent_origin=profile.request_origin,
        human_origin=profile.human_origin,
    )
    configured_mailer = (
        Mailer(EmailSettings.from_env("AWEB_PROTECTED_")) if mailer is None else mailer
    )
    if not callable(getattr(configured_mailer, "send", None)):
        raise TypeError("protected_notification_mailer_required")
    return host
