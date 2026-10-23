"""Installed apps' hook bindings (docs/design/audit-substrate.md §A3).

A registration is a hook the app receives through one of its tools; a
production is a hook the app may emit. Each install generation writes its
declared bindings as pending. A new generation supersedes every earlier
binding, so an owner's activation is never inherited, and uninstall revokes the
live ones. Only the team owner activates or revokes a binding, with an
``aweb.owner-act/1`` naming exactly the stored binding, verified by the hooks
kit against the team's current controller key.

Binding times are stored at millisecond precision, the precision hook events
spell them in, so a reader reports exactly what is stored.
"""

from __future__ import annotations

import hashlib
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from aweb_naapp.hooks.owner_act import CORE_ACTS, hook_binding_subject
from aweb_naapp.hooks.owner_act_nonces import OwnerActVerifier
from aweb_naapp.hooks.strictjson import Refused
from awid.team_ids import parse_team_id

from aweb.app_registry import normalize_app_id, normalize_digest, normalize_origin, validate_team_id
from aweb.awid_error_handling import AWID_DEPENDENCY_ERRORS
from aweb.service_errors import ConflictError, ForbiddenError, NotFoundError, ServiceError, ValidationError

REGISTRATION = "registration"
PRODUCTION = "production"
ACTIVATE = "hook-binding.activate"
REVOKE = "hook-binding.revoke"
# The owner-act nonce scope of the coordination server's verifier.
OWNER_ACT_SCOPE = "aweb"
# The purpose a production's registered key must declare: consumers verify its
# events' content signatures with a hook-event key.
HOOK_EVENT_PURPOSE = "hook-event"


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
               OR COALESCE(generation, 0) <> COALESCE($5::BIGINT, 0))
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
              AND COALESCE(generation, 0) = COALESCE($4::BIGINT, 0)
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


class OwnerActTeamKeyUnavailable(Exception):
    """An AWID dependency failure confined to the owner-act team-key read."""

    def __init__(self, dependency_error: Exception) -> None:
        self.dependency_error = dependency_error
        super().__init__(str(dependency_error))


def core_owner_act_verifier(*, audience: str, registry_client: Any) -> OwnerActVerifier:
    """The server's owner-act verifier: core's closed vocabulary, its public
    origin as audience, and the team's controller key read fresh from AWID."""

    async def team_key_for(team_id: str) -> str:
        domain, name = parse_team_id(team_id)
        try:
            team = await registry_client.get_team_fresh(domain, name)
        except AWID_DEPENDENCY_ERRORS as exc:
            raise OwnerActTeamKeyUnavailable(exc) from exc
        if team is None or not team.team_did_key:
            raise Refused("owner_required", "the team has no controller key at its registry")
        return team.team_did_key

    try:
        return OwnerActVerifier(scope=OWNER_ACT_SCOPE, audience=audience, acts=CORE_ACTS, team_key_for=team_key_for)
    except Refused as refused:
        raise _service_error(refused) from refused


# Every refusal of the act itself is 403 with its code, except that a valid act
# meeting a binding that has moved on, or one already used, is a conflict. A
# verifier the server built wrongly is the server's fault.
_CONFLICT_REFUSALS = frozenset({"subject_mismatch", "nonce_reused"})


def _service_error(refused: Refused) -> ServiceError:
    detail = str(refused)
    if refused.code in _CONFLICT_REFUSALS:
        return ConflictError(detail)
    if refused.code == "verifier_misconfigured":
        return ServiceError(detail)
    return ForbiddenError(detail)


def _require_live(binding: HookBinding, *, act: str) -> None:
    if binding.state == "superseded":
        raise ConflictError("the binding was superseded by a newer install generation")
    if binding.state == "revoked":
        raise ConflictError("the binding has already ended")
    if act == ACTIVATE and binding.state != "pending":
        raise ConflictError("the binding is not pending")
    if binding.installation_id is None or binding.generation is None:
        raise ConflictError("the binding's install has no installation identity yet")


def _subject(binding: HookBinding) -> dict[str, Any]:
    registration = binding.kind == REGISTRATION
    return hook_binding_subject(
        binding_id=str(binding.binding_id),
        installation_id=binding.installation_id or "",
        generation=binding.generation or 0,
        app_id=binding.app_id,
        origin=binding.origin,
        digest=binding.digest,
        kind=binding.kind,
        catalog_id=binding.catalog_id,
        catalog_version=binding.catalog_version,
        hook=binding.hook,
        tool=binding.tool,
        method=binding.method,
        path=binding.path,
        scopes=list(binding.scopes) if registration else None,
        reads=None if registration else list(binding.reads),
    )


async def _binding(db, *, team_id: str, binding_id: UUID | str, lock: bool) -> HookBinding:
    try:
        binding_uuid = UUID(str(binding_id))
    except ValueError as exc:
        raise NotFoundError() from exc
    row = await db.fetch_one(
        f"SELECT {BINDING_COLUMNS} FROM {{{{tables.app_hook_bindings}}}}"
        f" WHERE binding_id = $1 AND team_id = $2{' FOR UPDATE' if lock else ''}",
        binding_uuid,
        team_id,
    )
    if row is None:
        raise NotFoundError()
    return binding_from_row(row)


async def _require_production_keys(tx, binding: HookBinding) -> None:
    """A production's events are trusted by its registered keys, so it activates
    only when those keys were registered from the pinned manifest bytes."""
    from_bytes = await tx.fetch_value(
        """
        SELECT registered_from_manifest_bytes FROM {{tables.team_app_installs}}
        WHERE team_id = $1 AND app_id = $2 AND origin = $3 AND digest = $4
        """,
        binding.team_id,
        binding.app_id,
        binding.origin,
        binding.digest,
    )
    if not from_bytes:
        raise ConflictError("a production activates only for an install registered from its pinned manifest bytes")
    keys = await tx.fetch_value(
        """
        SELECT COUNT(*) FROM {{tables.team_app_keys}}
        WHERE team_id = $1 AND app_id = $2 AND origin = $3 AND digest = $4
          AND revoked_at IS NULL AND $5 = ANY(purposes)
        """,
        binding.team_id,
        binding.app_id,
        binding.origin,
        binding.digest,
        HOOK_EVENT_PURPOSE,
    )
    if not keys:
        raise ConflictError("a production activates only once the install registers hook keys (hook-event) from its pinned bytes")


async def _apply_owner_act(
    db,
    verifier: OwnerActVerifier,
    *,
    act: str,
    team_id: str,
    binding_id: UUID | str,
    signing: bytes,
    signature: str,
    in_transaction: Callable[[Any], Awaitable[None]] | None,
) -> HookBinding:
    team_id = validate_team_id(team_id)
    # Refusals that need no signature come first; the transaction checks them again.
    _require_live(await _binding(db, team_id=team_id, binding_id=binding_id, lock=False), act=act)
    try:
        prepared = await verifier.prepare(signing, signature, team_id=team_id)
    except Refused as refused:
        raise _service_error(refused) from refused
    if prepared.act_name != act:
        raise ForbiddenError(f"act_not_allowed: this change takes {act}, not {prepared.act_name}")
    act_sha256 = hashlib.sha256(signing).hexdigest()
    async with db.transaction() as tx:
        binding = await _binding(tx, team_id=team_id, binding_id=binding_id, lock=False)
        # Lock the install row before the binding, in the order installs write them.
        await tx.fetch_one(
            "SELECT 1 FROM {{tables.team_app_installs}} WHERE team_id = $1 AND app_id = $2 FOR UPDATE",
            team_id,
            binding.app_id,
        )
        binding = await _binding(tx, team_id=team_id, binding_id=binding_id, lock=True)
        _require_live(binding, act=act)
        if act == ACTIVATE and binding.kind == PRODUCTION:
            await _require_production_keys(tx, binding)
        try:
            await verifier.consume_in(tx, prepared, expected_subject=_subject(binding))
        except Refused as refused:
            raise _service_error(refused) from refused
        if act == ACTIVATE:
            row = await tx.fetch_one(
                f"""
                UPDATE {{{{tables.app_hook_bindings}}}}
                SET state = 'active', activated_at = date_trunc('milliseconds', NOW()),
                    active_from = date_trunc('milliseconds', NOW()) + INTERVAL '60 seconds',
                    activation_act_sha256 = $2
                WHERE binding_id = $1
                RETURNING {BINDING_COLUMNS}
                """,
                binding.binding_id,
                act_sha256,
            )
        else:
            row = await tx.fetch_one(
                f"""
                UPDATE {{{{tables.app_hook_bindings}}}}
                SET state = 'revoked', ended_by = 'owner_act', revoked_at = date_trunc('milliseconds', NOW()),
                    revocation_act_sha256 = $2
                WHERE binding_id = $1
                RETURNING {BINDING_COLUMNS}
                """,
                binding.binding_id,
                act_sha256,
            )
        if in_transaction is not None:
            await in_transaction(tx)
    return binding_from_row(row)


async def activate_binding(
    db,
    verifier: OwnerActVerifier,
    *,
    team_id: str,
    binding_id: UUID | str,
    signing: bytes,
    signature: str,
    in_transaction: Callable[[Any], Awaitable[None]] | None = None,
) -> HookBinding:
    """Activate a pending binding under the team owner's ``hook-binding.activate``
    act. It applies from 60 s after activation, so every producer has refreshed
    its view before the binding receives anything. ``in_transaction`` runs in
    the transaction that changes the binding, where the change's hook event is
    enqueued."""
    return await _apply_owner_act(
        db, verifier, act=ACTIVATE, team_id=team_id, binding_id=binding_id, signing=signing, signature=signature,
        in_transaction=in_transaction,
    )


async def revoke_binding(
    db,
    verifier: OwnerActVerifier,
    *,
    team_id: str,
    binding_id: UUID | str,
    signing: bytes,
    signature: str,
    in_transaction: Callable[[Any], Awaitable[None]] | None = None,
) -> HookBinding:
    """Revoke a pending or active binding under the team owner's
    ``hook-binding.revoke`` act. ``in_transaction`` runs in the
    transaction that changes the binding."""
    return await _apply_owner_act(
        db, verifier, act=REVOKE, team_id=team_id, binding_id=binding_id, signing=signing, signature=signature,
        in_transaction=in_transaction,
    )
