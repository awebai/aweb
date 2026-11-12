"""Runnable independent protected server; no controller or authorizer bootstrap.

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
from aweb_naapp.console.handoff_page import handoff_page_router
from aweb_naapp.console.handoff_store import HandoffStore
from aweb_naapp.email import EmailSettings, Mailer
from aweb_naapp.hooks.strictjson import parse_strict
from aweb_naapp.runtime.origins import OriginApps
from aweb_naapp.runtime.protected_signer import SignerRefused
from awid.db_config import build_database_config
from awid.did import did_from_public_key
from awid.registry import RegistryClient
from awid.signing import load_signing_key_pem
from awid.team_ids import build_team_id, parse_team_id
from fastapi import FastAPI
from nacl.signing import SigningKey
from pgdbm import AsyncDatabaseManager
from pydantic import Field, SecretStr, StrictInt
from pydantic_settings import BaseSettings, SettingsConfigDict

from .composition import IndependentProtectedSigner
from .custody import ProtectedControllerCustody
from .notifications import ProtectedNotifications
from .profile import ProtectedServiceProfile


class HostSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AWEB_PROTECTED_", extra="forbid")

    profile_file: Path
    scope_file: Path
    controller_key_file: Path
    member_keys_file: Path
    worker_uids: list[Annotated[StrictInt, Field(gt=0)]] = Field(min_length=1)
    database_url: SecretStr = Field(repr=False)
    database_schema: str = Field(
        default="protected_signer", pattern=r"^[a-z][a-z0-9_]{0,62}$"
    )
    database_uses_transaction_pooler: bool = False
    human_csrf_key: str = Field(
        default="aweb.protected.console.csrf", pattern=r"^[A-Za-z0-9._-]{1,128}$"
    )


def _member_keys(path):
    """Same canonical-team/Ed25519-PEM manifest format as aweb configuration."""
    try:
        entries = parse_strict(path.read_bytes())
        if not isinstance(entries, dict) or not entries:
            raise ValueError()
        keys = {}
        for team_id, filename in entries.items():
            if build_team_id(*parse_team_id(team_id)) != team_id:
                raise ValueError()
            if not isinstance(filename, str) or not filename:
                raise ValueError()
            key_file = Path(filename)
            if not key_file.is_absolute():
                key_file = path.parent / key_file
            keys[team_id] = load_signing_key_pem(key_file.read_bytes())
        return keys
    except (OSError, ValueError, TypeError):
        raise ValueError("protected_member_keys_invalid") from None


async def validate_provisioning(composition):
    """Refuse missing/currently mismatched authority without inventing a grant.

    This is startup evidence only. Shared operations still perform their own
    fresh observation and transaction fences on every use.
    """
    c = composition
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


def create_app(settings=None, *, mailer=None, registry_transport=None):
    """Own one DB/registry lifetime and mount the sole shared human page.

    In-process hosts may supply their existing configured mailer/transport;
    the process entry point uses the existing TLS Mailer settings. Neither
    injection constructs sessions, UV assertions, authority or signed effects.
    """
    settings = HostSettings() if settings is None else settings
    profile = ProtectedServiceProfile.from_json(settings.profile_file.read_bytes())
    scope = parse_strict(settings.scope_file.read_bytes())
    binding = profile.binding_for(scope)
    context = binding.context()
    if context.authority_kind != "team_controller":
        raise SignerRefused("operation_refused")
    # Validate origin separation before any resource opens, even when both
    # origins share a process behind a TLS reverse proxy.
    human = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @asynccontextmanager
    async def lifespan(api):
        custody = ProtectedControllerCustody(
            service_id=context.service_id,
            team_id=context.authority_id,
            domain=context.authority_domain,
            key_file=settings.controller_key_file,
            worker_uids=frozenset(settings.worker_uids),
        )
        if custody.team_key_did != binding.authority_key_did:
            raise SignerRefused("authority_changed")
        keys = _member_keys(settings.member_keys_file)
        if context.authority_id not in keys or any(
            did_from_public_key(bytes(SigningKey(key).verify_key))
            == custody.team_key_did
            for key in keys.values()
        ):
            raise SignerRefused("custody_not_isolated")
        async with AsyncExitStack() as resources:
            resources.callback(api.router.routes.clear)
            resources.callback(human.router.routes.clear)
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
            composition = IndependentProtectedSigner.from_profile(
                db,
                profile=profile,
                scope=scope,
                registry_client=registry,
                custody=custody,
                delivery=ProtectedNotifications(
                    db=db, mailer=configured_mailer, human_origin=profile.human_origin
                ),
            )
            await composition.migrate()
            await apply_console_migrations(db)
            await validate_provisioning(composition)
            sessions = composition.protected_sessions()
            limiter = LoginLimiter(
                db,
                client_identity=ClientIdentity(),
                limit=30,
                window=timedelta(minutes=1),
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
            try:
                yield
            finally:
                api.router.routes.clear()
                human.router.routes.clear()
                del api.state.composition
                del human.state.composition

    api = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
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
