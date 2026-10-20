"""Installed apps' hook bindings (docs/design/audit-substrate.md §A3).

A registration is a hook the app receives through one of its tools; a
production is a hook the app may emit. Each install generation writes its
declared bindings as pending. A new generation supersedes every earlier
binding, so an owner's activation is never inherited, and uninstall revokes the
live ones. Activation and owner revocation take an owner act and are not here.

Binding times are stored at millisecond precision, the precision hook events
spell them in, so a reader reports exactly what is stored.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from aweb.app_registry import normalize_app_id, normalize_digest, normalize_origin, validate_team_id
from aweb.service_errors import ValidationError

REGISTRATION = "registration"
PRODUCTION = "production"


@dataclass(frozen=True)
class HookBindingDeclaration:
    """One binding an install declares, read from its pinned manifest bytes.

    A registration names its resolved tool, method, raw path and scopes; a
    production names the tools whose reads it reports.
    """

    kind: str
    catalog_id: str
    catalog_version: int
    hook: str
    tool: str | None = None
    method: str | None = None
    path: str | None = None
    scopes: tuple[str, ...] = ()
    reads: tuple[str, ...] = ()


@dataclass(frozen=True)
class HookBinding:
    binding_id: UUID
    kind: str
    team_id: str
    installation_id: str | None
    generation: int | None
    app_id: str
    origin: str
    digest: str
    catalog_id: str
    catalog_version: int
    hook: str
    tool: str | None
    method: str | None
    path: str | None
    scopes: tuple[str, ...]
    reads: tuple[str, ...]
    state: str
    ended_by: str | None
    activated_at: datetime | None
    active_from: datetime | None
    revoked_at: datetime | None


BINDING_COLUMNS = """
    binding_id, kind, team_id, installation_id, generation, app_id, origin, digest,
    catalog_id, catalog_version, hook, tool, method, path, scopes, reads, state,
    ended_by, activated_at, active_from, revoked_at
"""


def binding_from_row(row) -> HookBinding:
    """A HookBinding from a row selected with BINDING_COLUMNS."""
    values = dict(row)
    values["scopes"] = tuple(values["scopes"])
    values["reads"] = tuple(values["reads"])
    return HookBinding(**values)


def _canonical_names(values: tuple[str, ...], field: str) -> list[str]:
    """Sorted by code point and distinct: the order an owner act's subject uses."""
    if len(set(values)) != len(values):
        raise ValidationError(f"hook binding {field} must be distinct")
    if any(not isinstance(value, str) or not value.strip() for value in values):
        raise ValidationError(f"hook binding {field} must be non-empty names")
    return sorted(values)


def _validated(declaration: HookBindingDeclaration) -> HookBindingDeclaration:
    if declaration.kind not in (REGISTRATION, PRODUCTION):
        raise ValidationError("hook binding kind must be registration or production")
    target = (declaration.tool, declaration.method, declaration.path)
    if declaration.kind == REGISTRATION:
        if any(not value for value in target):
            raise ValidationError("a registration names its tool, method and path")
        if declaration.reads:
            raise ValidationError("a registration declares no reads")
    else:
        if any(value is not None for value in target):
            raise ValidationError("a production names no tool, method or path")
        if declaration.scopes:
            raise ValidationError("a production declares no scopes")
    return HookBindingDeclaration(
        kind=declaration.kind,
        catalog_id=declaration.catalog_id,
        catalog_version=declaration.catalog_version,
        hook=declaration.hook,
        tool=declaration.tool,
        method=declaration.method,
        path=declaration.path,
        scopes=tuple(_canonical_names(declaration.scopes, "scopes")),
        reads=tuple(_canonical_names(declaration.reads, "reads")),
    )


async def write_pending_bindings(
    tx,
    *,
    team_id: str,
    app_id: str,
    origin: str,
    digest: str,
    installation_id: str | None,
    generation: int | None,
    declarations: list[HookBindingDeclaration],
) -> list[HookBinding]:
    """Write one install generation's declared bindings as pending.

    Runs in the install's transaction, after the install record is written:
    the bindings must name that record's origin and digest. The install row is
    locked first, so writes for one install run one at a time. Every earlier
    binding of the app in the team, pending or active, is superseded. Writing
    the same generation again keeps its live bindings and their states; ended
    bindings are history, so a reinstall after uninstall writes fresh pending
    ones. A generation older than the installation's live one is refused. Returns the generation's
    bindings in declaration order.
    """

    team_id = validate_team_id(team_id)
    app_id = normalize_app_id(app_id)
    origin = normalize_origin(origin)
    digest = normalize_digest(digest)
    if (installation_id is None) != (generation is None):
        raise ValidationError("installation_id and generation are given together")
    validated = [_validated(declaration) for declaration in declarations]

    install = await tx.fetch_one(
        """
        SELECT origin, digest FROM {{tables.team_app_installs}}
        WHERE team_id = $1 AND app_id = $2
        FOR UPDATE
        """,
        team_id,
        app_id,
    )
    if install is None:
        raise ValidationError("the app is not installed in this team")
    if (install["origin"], install["digest"]) != (origin, digest):
        raise ValidationError("hook bindings must name the install's origin and digest")
    if installation_id is not None:
        newer = await tx.fetch_value(
            """
            SELECT MAX(generation) FROM {{tables.app_hook_bindings}}
            WHERE team_id = $1 AND app_id = $2 AND installation_id = $3
              AND state IN ('pending', 'active')
            """,
            team_id,
            app_id,
            installation_id,
        )
        if newer is not None and newer > generation:
            raise ValidationError("the installation already has a newer generation")

    await tx.execute(
        """
        UPDATE {{tables.app_hook_bindings}}
        SET state = 'superseded', ended_by = 'generation', revoked_at = date_trunc('milliseconds', NOW())
        WHERE team_id = $1 AND app_id = $2 AND state IN ('pending', 'active')
          AND (digest <> $3
               OR origin <> $6
               OR COALESCE(installation_id, '') <> COALESCE($4::TEXT, '')
               OR COALESCE(generation, 0) <> COALESCE($5::INTEGER, 0))
        """,
        team_id,
        app_id,
        digest,
        installation_id,
        generation,
        origin,
    )
    written = []
    for declaration in validated:
        await tx.execute(
            """
            INSERT INTO {{tables.app_hook_bindings}} (
                kind, team_id, installation_id, generation, app_id, origin, digest,
                catalog_id, catalog_version, hook, tool, method, path, scopes, reads
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14::TEXT[], $15::TEXT[])
            ON CONFLICT DO NOTHING
            """,
            declaration.kind,
            team_id,
            installation_id,
            generation,
            app_id,
            origin,
            digest,
            declaration.catalog_id,
            declaration.catalog_version,
            declaration.hook,
            declaration.tool,
            declaration.method,
            declaration.path,
            list(declaration.scopes),
            list(declaration.reads),
        )
        row = await tx.fetch_one(
            f"""
            SELECT {BINDING_COLUMNS} FROM {{{{tables.app_hook_bindings}}}}
            WHERE team_id = $1 AND app_id = $2 AND digest = $10 AND origin = $11 AND state IN ('pending', 'active')
              AND COALESCE(installation_id, '') = COALESCE($3::TEXT, '')
              AND COALESCE(generation, 0) = COALESCE($4::INTEGER, 0)
              AND kind = $5 AND catalog_id = $6 AND catalog_version = $7 AND hook = $8
              AND COALESCE(tool, '') = COALESCE($9::TEXT, '')
            """,
            team_id,
            app_id,
            installation_id,
            generation,
            declaration.kind,
            declaration.catalog_id,
            declaration.catalog_version,
            declaration.hook,
            declaration.tool,
            digest,
            origin,
        )
        written.append(binding_from_row(row))
    return written


async def revoke_uninstalled_bindings(tx, *, team_id: str, app_id: str) -> int:
    """Revoke the app's live bindings in the team, in the uninstall's transaction."""

    result = await tx.execute(
        """
        UPDATE {{tables.app_hook_bindings}}
        SET state = 'revoked', ended_by = 'uninstall', revoked_at = date_trunc('milliseconds', NOW())
        WHERE team_id = $1 AND app_id = $2 AND state IN ('pending', 'active')
        """,
        validate_team_id(team_id),
        normalize_app_id(app_id),
    )
    return int(result.split()[-1])


async def list_app_bindings(db, *, team_id: str, app_id: str) -> list[HookBinding]:
    """The app's bindings in the team, in every state, oldest first."""

    rows = await db.fetch_all(
        f"""
        SELECT {BINDING_COLUMNS} FROM {{{{tables.app_hook_bindings}}}}
        WHERE team_id = $1 AND app_id = $2
        ORDER BY created_at, kind DESC, catalog_id, catalog_version, hook, tool
        """,
        validate_team_id(team_id),
        normalize_app_id(app_id),
    )
    return [binding_from_row(row) for row in rows]
