"""The operator's complete Secrets schema recipe, before runtime DML (§15).

The erasure initializer calls this recipe before binding its protected schema
identity. Runtime integrity checks compare the returned source fingerprint;
they do not use service credentials to apply migrations.
"""

from collections.abc import Iterator
from functools import partial
from hashlib import sha256
from importlib.resources import files
from importlib.resources.abc import Traversable

from aweb_naapp.console import apply_console_migrations
from aweb_naapp.dispatch import apply_dispatch_migrations
from aweb_naapp.hooks.owner_act_nonces import apply_owner_act_migrations
from aweb_naapp.nonces import apply_nonce_migrations
from aweb_naapp.runtime.approvals import PgApprovalStore
from aweb_naapp.runtime.credential_audit import apply_credential_audit_migrations
from aweb_naapp.runtime.db import prepare_naapp_schema
from aweb_naapp.runtime.passkeys import apply_passkey_migrations
from pgdbm import AsyncDatabaseManager

from aweb_secrets.app import MIGRATIONS_PATH, MODULE_NAME, STORES
from aweb_secrets.broker_outcomes import prepare_legacy_broker_outcomes
from aweb_secrets.change_policy import apply_change_policy_migrations
from aweb_secrets.change_sets import apply_change_set_migrations
from aweb_secrets.credential_governance import CREDENTIAL_AUDIT_MIGRATIONS
from aweb_secrets.custody import apply_custody_migrations
from aweb_secrets.jobs import apply_job_migrations
from aweb_secrets.owners import apply_owner_migrations
from aweb_secrets.reconciliation_control_audit import apply_reconciliation_migrations
from aweb_secrets.run_context import apply_run_dispatch_migrations
from aweb_secrets.runners import apply_runner_migrations
from aweb_secrets.use_approvals import apply_use_approval_migrations
from aweb_secrets.use_context import apply_use_context_migrations


class SchemaFilesUnavailable(RuntimeError):
    code = "schema_files_unavailable"

    def __init__(self) -> None:
        super().__init__(
            "Reinstall the pinned image: its schema preparation files are unavailable."
        )


def _sql_sources(directory: Traversable, *, prefix: str = "") -> Iterator[tuple[str, bytes]]:
    for entry in sorted(directory.iterdir(), key=lambda resource: resource.name):
        name = prefix + entry.name
        if entry.is_dir():
            yield from _sql_sources(entry, prefix=name + "/")
        elif entry.name.endswith(".sql"):
            yield name, entry.read_bytes()


def service_schema_fingerprint() -> str:
    """Bind the preparation recipe and packaged migration bytes, never DB data."""
    digest = sha256()
    try:
        for package in ("aweb_naapp", "aweb_secrets"):
            directory = files(package)
            sources = list(_sql_sources(directory))
            if not sources:
                raise SchemaFilesUnavailable()
            recipe = "runtime/db.py" if package == "aweb_naapp" else "schema.py"
            sources.append((recipe, directory.joinpath(recipe).read_bytes()))
            for name, content in sorted(sources):
                digest.update((package + "/" + name + "\0").encode("utf-8"))
                digest.update(sha256(content).digest())
    except OSError:
        raise SchemaFilesUnavailable() from None
    return "sha256:" + digest.hexdigest()


async def prepare_business_schema(db: AsyncDatabaseManager) -> PgApprovalStore:
    """Prepare B2, owned stores, B3 and credential audit in dependency order."""
    store = PgApprovalStore(db)
    await store.migrate()
    for migrate in (
        apply_owner_act_migrations,
        apply_owner_migrations,
        apply_console_migrations,
        apply_change_policy_migrations,
        apply_custody_migrations,
        apply_change_set_migrations,
        partial(apply_dispatch_migrations, before_upgrade=prepare_legacy_broker_outcomes),
        apply_nonce_migrations,
        apply_job_migrations,
        apply_runner_migrations,
        apply_use_approval_migrations,
        apply_use_context_migrations,
        apply_run_dispatch_migrations,
        apply_reconciliation_migrations,
    ):
        await migrate(db)
    await apply_passkey_migrations(db)
    await apply_credential_audit_migrations(db, module_name=CREDENTIAL_AUDIT_MIGRATIONS)
    return store


async def prepare_service_schema(db: AsyncDatabaseManager) -> str:
    """Use a connected operator DB; return a receipt only after every stage succeeds.

    The initializer must first reject nonempty content with no matching erasure
    identity. It records this fingerprint in the protected ledger after this
    operation completes, before transferring ownership and starting runtime.
    """
    fingerprint = service_schema_fingerprint()
    await prepare_naapp_schema(
        db, module_name=MODULE_NAME, migrations_path=MIGRATIONS_PATH, stores=STORES
    )
    await prepare_business_schema(db)
    return fingerprint
