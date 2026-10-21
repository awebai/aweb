"""Core app registry and per-team app grants."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from aweb_naapp.manifest import ManifestError, load_manifest
from awid.team_ids import parse_team_id

from aweb.service_errors import BadRequestError, ConflictError, ValidationError

APP_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SCOPE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}$")
LOCAL_EVENT_TYPE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
DELIVERY_INTENTS = frozenset({"wake", "steer", "ambient"})

RESERVED_APP_IDS_ARTIFACT = "reserved-app-ids-v1.json"
RESERVED_APP_IDS_SCHEMA = "aweb.reserved-app-ids.v1"


@dataclass(frozen=True)
class AppInstall:
    app_id: str
    origin: str
    app_version: str
    manifest_version: int
    digest: str
    granted_scopes: list[str]
    installation_id: str | None = None
    generation: int | None = None
    state: str = "pending_origin_verification"
    origin_verified: bool = False
    origin_verification_error: str | None = None


@dataclass(frozen=True)
class AppEventType:
    type: str
    default_delivery_intent: str = "ambient"
    description: str = ""


@dataclass(frozen=True)
class AppEmitKey:
    kid: str
    did_key: str


@dataclass(frozen=True)
class AppKey:
    """A manifest_version 2 app key and the purposes the pinned bytes declare for it."""

    kid: str
    did_key: str
    purposes: tuple[str, ...]


def _reserved_app_ids_source_path() -> Path:
    """Locate the CLI-owned reserved app-id artifact from a source checkout."""

    for parent in Path(__file__).resolve().parents:
        candidate = parent / "test-vectors" / RESERVED_APP_IDS_ARTIFACT
        if candidate.is_file():
            return candidate
    raise RuntimeError(f"missing reserved app ids artifact: test-vectors/{RESERVED_APP_IDS_ARTIFACT}")


def _read_reserved_app_ids_artifact() -> str:
    """Read packaged reserved app-id artifact, with source fallback for editable checkouts."""

    packaged = files("aweb").joinpath("data", RESERVED_APP_IDS_ARTIFACT)
    if packaged.is_file():
        return packaged.read_text(encoding="utf-8")
    return _reserved_app_ids_source_path().read_text(encoding="utf-8")


@lru_cache(maxsize=1)
def reserved_app_ids() -> frozenset[str]:
    """Return CLI-owned reserved app ids from the packaged artifact.

    The aw CLI owns the top-level namespace and drift-gates the root artifact in
    its own tests. The server wheel packages a copy so deployed registries do not
    depend on source-checkout paths.
    """

    payload = json.loads(_read_reserved_app_ids_artifact())
    if payload.get("schema") != RESERVED_APP_IDS_SCHEMA:
        raise RuntimeError("reserved app ids artifact has unsupported schema")
    values = payload.get("reserved_app_ids")
    if not isinstance(values, list) or not values:
        raise RuntimeError("reserved app ids artifact must contain a non-empty reserved_app_ids list")
    ids: set[str] = set()
    for value in values:
        if not isinstance(value, str) or not APP_ID_RE.fullmatch(value):
            raise RuntimeError(f"reserved app ids artifact contains invalid app id: {value!r}")
        ids.add(value)
    return frozenset(ids)


def normalize_app_id(value: str) -> str:
    app_id = (value or "").strip().lower()
    if not APP_ID_RE.match(app_id):
        raise ValidationError("app_id must match ^[a-z][a-z0-9-]{0,62}$")
    if app_id.endswith("-") or "--" in app_id:
        raise ValidationError("app_id must not end with '-' or contain '--'")
    if app_id in reserved_app_ids():
        raise ConflictError(f"app_id {app_id!r} is reserved")
    return app_id


def normalize_origin(value: str) -> str:
    raw = (value or "").strip()
    try:
        parsed = urlparse(raw)
        scheme = parsed.scheme.lower()
        username = parsed.username
        password = parsed.password
        params = parsed.params
        query = parsed.query
        fragment = parsed.fragment
        hostname = parsed.hostname
        path = (parsed.path or "").rstrip("/")
        parsed_port = parsed.port
    except ValueError as exc:
        detail = "origin port is invalid" if "port" in str(exc).lower() else "origin URL is invalid"
        raise ValidationError(detail) from exc

    if scheme not in {"http", "https"}:
        raise ValidationError("origin scheme must be http or https")
    if username or password:
        raise ValidationError("origin must not include userinfo")
    if params or query or fragment:
        raise ValidationError("origin must not include params, query, or fragment")
    if not hostname:
        raise ValidationError("origin host is required")
    if path:
        raise ValidationError("origin must be an origin URL, not a path")
    host = hostname.lower()
    host_out = f"[{host}]" if ":" in host and not host.startswith("[") else host
    default_port = 80 if scheme == "http" else 443
    port = None if parsed_port in {None, default_port} else parsed_port
    return f"{scheme}://{host_out}{f':{port}' if port is not None else ''}"


def normalize_digest(value: str) -> str:
    digest = (value or "").strip().lower()
    if not DIGEST_RE.match(digest):
        raise ValidationError("digest must be sha256:<64 lowercase hex characters>")
    return digest


def normalize_app_version(value: str) -> str:
    version = (value or "").strip()
    if not version:
        raise ValidationError("app_version is required")
    if len(version) > 128:
        raise ValidationError("app_version is too long")
    return version


def normalize_manifest_version(value: int) -> int:
    if value <= 0:
        raise ValidationError("manifest_version must be positive")
    return value


def normalize_scopes(values: list[str]) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for raw in values:
        scope = (raw or "").strip()
        if not SCOPE_RE.match(scope):
            raise ValidationError(f"invalid scope {raw!r}")
        if scope not in seen:
            normalized.append(scope)
            seen.add(scope)
    return sorted(normalized)


def normalize_delivery_intent(value: str | None, *, default: str = "ambient") -> str:
    intent = (value or default).strip().lower()
    if intent not in DELIVERY_INTENTS:
        raise ValidationError("delivery_intent must be wake, steer, or ambient")
    return intent


def normalize_local_event_type(value: str) -> str:
    event_type = (value or "").strip().lower()
    if not LOCAL_EVENT_TYPE_RE.match(event_type):
        raise ValidationError("event type must be lower-case app-local text")
    if "/" in event_type:
        raise ValidationError("manifest event type must be app-local, not app-qualified")
    return event_type


def normalize_app_event_type(value: str) -> tuple[str, str]:
    raw = (value or "").strip().lower()
    if raw.count("/") != 1:
        raise ValidationError("event type must be <app_id>/<event_type>")
    app_id, local_type = raw.split("/", 1)
    return normalize_app_id(app_id), normalize_local_event_type(local_type)


def normalize_key_id(value: str) -> str:
    kid = (value or "").strip()
    if not KEY_ID_RE.match(kid):
        raise ValidationError("key id is invalid")
    return kid


def normalize_did_key(value: str) -> str:
    did_key = (value or "").strip()
    if not did_key.startswith("did:key:"):
        raise ValidationError("did_key must be did:key")
    return did_key


def normalize_event_types(values: list[AppEventType]) -> list[AppEventType]:
    out: list[AppEventType] = []
    seen: set[str] = set()
    for item in values:
        event_type = normalize_local_event_type(item.type)
        if event_type in seen:
            continue
        out.append(
            AppEventType(
                type=event_type,
                default_delivery_intent=normalize_delivery_intent(item.default_delivery_intent),
                description=(item.description or "").strip()[:4096],
            )
        )
        seen.add(event_type)
    return out


def normalize_emit_keys(values: list[AppEmitKey]) -> list[AppEmitKey]:
    out: list[AppEmitKey] = []
    seen: set[str] = set()
    for item in values:
        kid = normalize_key_id(item.kid)
        did_key = normalize_did_key(item.did_key)
        if kid in seen:
            continue
        out.append(AppEmitKey(kid=kid, did_key=did_key))
        seen.add(kid)
    return out


def validate_team_id(team_id: str) -> str:
    value = (team_id or "").strip()
    try:
        parse_team_id(value)
    except ValueError as exc:
        raise BadRequestError("invalid team_id") from exc
    return value


async def install_app(
    db,
    *,
    team_id: str,
    app_id: str,
    origin: str,
    app_version: str,
    manifest_version: int,
    digest: str,
    granted_scopes: list[str],
    installed_by_agent_id: str | None = None,
    event_types: list[AppEventType] | None = None,
    emit_keys: list[AppEmitKey] | None = None,
    manifest: bytes | None = None,
    audit: Callable[[Any], Awaitable[None]] | None = None,
) -> AppInstall:
    """Install or explicitly re-install an app for a team.

    Re-install/update is explicit: the caller supplies the new pinned digest and
    scopes. Reusing an app id for a different origin within the team is
    rejected as an app-id collision.

    With ``manifest``, the exact bytes that hash to the pinned digest supply the
    event declarations and emit keys. Separately supplied declarations, keys or
    versions must equal the bytes', and the granted scopes must be a subset of
    the scopes the bytes' tools request. ``audit`` runs inside the install
    transaction, after the registrations are written.
    """

    team_id = validate_team_id(team_id)
    app_id = normalize_app_id(app_id)
    origin = normalize_origin(origin)
    app_version = normalize_app_version(app_version)
    manifest_version = normalize_manifest_version(manifest_version)
    digest = normalize_digest(digest)
    granted_scopes = normalize_scopes(granted_scopes)
    event_types = normalize_event_types(event_types or [])
    emit_keys = normalize_emit_keys(emit_keys or [])
    app_keys: list[AppKey] = []
    if manifest is not None:
        event_types, emit_keys, app_keys = _registrations_from_manifest(
            manifest,
            app_id=app_id,
            origin=origin,
            digest=digest,
            app_version=app_version,
            manifest_version=manifest_version,
            granted_scopes=granted_scopes,
            event_types=event_types,
            emit_keys=emit_keys,
        )

    existing = await db.fetch_one(
        """
        SELECT origin FROM {{tables.team_app_installs}}
        WHERE team_id = $1 AND app_id = $2
        """,
        team_id,
        app_id,
    )
    if existing and existing["origin"] != origin:
        raise ConflictError("app_id is already installed for this team from a different origin")

    async with db.transaction() as tx:
        await tx.execute(
            """
            INSERT INTO {{tables.app_registry_apps}} (app_id, origin, updated_at)
            VALUES ($1, $2, NOW())
            ON CONFLICT (app_id, origin) DO NOTHING
            """,
            app_id,
            origin,
        )
        await tx.execute(
            """
            INSERT INTO {{tables.app_registry_entries}} (
                app_id, origin, digest, app_version, manifest_version, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, NOW())
            ON CONFLICT (app_id, origin, digest) DO NOTHING
            """,
            app_id,
            origin,
            digest,
            app_version,
            manifest_version,
        )
        await tx.execute(
            """
            INSERT INTO {{tables.team_app_installs}} (
                team_id, app_id, origin, digest, app_version, manifest_version,
                granted_scopes, installed_by_agent_id, registered_from_manifest_bytes, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7::TEXT[], $8::UUID, $9, NOW())
            ON CONFLICT (team_id, app_id) DO UPDATE SET
                origin = EXCLUDED.origin,
                digest = EXCLUDED.digest,
                app_version = EXCLUDED.app_version,
                manifest_version = EXCLUDED.manifest_version,
                granted_scopes = EXCLUDED.granted_scopes,
                installed_by_agent_id = EXCLUDED.installed_by_agent_id,
                registered_from_manifest_bytes = EXCLUDED.registered_from_manifest_bytes,
                updated_at = NOW()
            """,
            team_id,
            app_id,
            origin,
            digest,
            app_version,
            manifest_version,
            granted_scopes,
            installed_by_agent_id,
            manifest is not None,
        )
        # The install row upsert above locks (team_id, app_id), so concurrent
        # installs of one app in one team write registrations one at a time.
        await _write_team_registrations(
            tx,
            team_id=team_id,
            app_id=app_id,
            origin=origin,
            digest=digest,
            event_types=event_types,
            emit_keys=emit_keys,
            app_keys=app_keys,
        )
        if audit is not None:
            await audit(tx)

    return AppInstall(
        app_id=app_id,
        origin=origin,
        app_version=app_version,
        manifest_version=manifest_version,
        digest=digest,
        granted_scopes=granted_scopes,
    )


def _registrations_from_manifest(
    manifest: bytes,
    *,
    app_id: str,
    origin: str,
    digest: str,
    app_version: str,
    manifest_version: int,
    granted_scopes: list[str],
    event_types: list[AppEventType],
    emit_keys: list[AppEmitKey],
) -> tuple[list[AppEventType], list[AppEmitKey], list[AppKey]]:
    registration = manifest_registration(manifest, app_id=app_id, origin=origin, digest=digest)
    if app_version != registration.app_version or manifest_version != registration.manifest_version:
        raise ValidationError("install version does not match the manifest bytes")
    if event_types and set(event_types) != set(registration.event_types):
        raise ValidationError("install events do not match the manifest bytes")
    if emit_keys and set(emit_keys) != set(registration.emit_keys):
        raise ValidationError("install event_emitters do not match the manifest bytes")
    if not set(granted_scopes) <= set(registration.requested_scopes):
        raise ValidationError("granted_scopes must be a subset of the scopes the manifest requests")
    return registration.event_types, registration.emit_keys, registration.app_keys


def _revocation_carried_across_digests(table: str) -> str:
    """The earliest revocation of one key in the team, under any of the app's digests.

    A team's revocation of a key outlives the digest it was made under, so new
    bytes that list the same key register it already revoked. For an INSERT
    whose parameters are $1 team_id, $2 app_id, $5 key_id and $6 did_key.
    """
    return (
        f"(SELECT MIN(revoked_at) FROM {{{{tables.{table}}}}} "
        "WHERE team_id = $1 AND app_id = $2 AND key_id = $5 AND did_key = $6)"
    )


async def _write_team_registrations(
    tx,
    *,
    team_id: str,
    app_id: str,
    origin: str,
    digest: str,
    event_types: list[AppEventType],
    emit_keys: list[AppEmitKey],
    app_keys: list[AppKey],
) -> None:
    """Write one team's event declarations, emit keys and app keys for an installed digest.

    The caller holds the team's install row lock. Declarations are replaced;
    a key id keeps its first did_key and a revoked key stays revoked.
    """

    for event_type in event_types:
        await tx.execute(
            """
            INSERT INTO {{tables.team_app_event_types}} (
                team_id, app_id, origin, digest, event_type,
                default_delivery_intent, description, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
            ON CONFLICT (team_id, app_id, origin, digest, event_type) DO UPDATE SET
                default_delivery_intent = EXCLUDED.default_delivery_intent,
                description = EXCLUDED.description,
                updated_at = NOW()
            """,
            team_id,
            app_id,
            origin,
            digest,
            event_type.type,
            event_type.default_delivery_intent,
            event_type.description,
        )
    for emit_key in emit_keys:
        conflicting = await tx.fetch_one(
            """
            SELECT 1 FROM {{tables.team_app_emit_keys}}
            WHERE team_id = $1 AND app_id = $2 AND key_id = $3 AND did_key <> $4
            LIMIT 1
            """,
            team_id,
            app_id,
            emit_key.kid,
            emit_key.did_key,
        )
        if conflicting:
            raise ConflictError("emit key id is already registered with a different key")
        await tx.execute(
            f"""
            INSERT INTO {{{{tables.team_app_emit_keys}}}} (
                team_id, app_id, origin, digest, key_id, did_key, revoked_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, {_revocation_carried_across_digests("team_app_emit_keys")})
            ON CONFLICT (team_id, app_id, origin, digest, key_id) DO NOTHING
            """,
            team_id,
            app_id,
            origin,
            digest,
            emit_key.kid,
            emit_key.did_key,
        )
    for app_key in app_keys:
        conflicting = await tx.fetch_one(
            """
            SELECT 1 FROM {{tables.team_app_keys}}
            WHERE team_id = $1 AND app_id = $2 AND key_id = $3 AND did_key <> $4
            LIMIT 1
            """,
            team_id,
            app_id,
            app_key.kid,
            app_key.did_key,
        )
        if conflicting:
            raise ConflictError("app key id is already registered with a different key")
        # A team's revocation of a key outlives the digest it was made under:
        # new bytes listing the same key register it already revoked.
        await tx.execute(
            f"""
            INSERT INTO {{{{tables.team_app_keys}}}} (
                team_id, app_id, origin, digest, key_id, did_key, purposes, revoked_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7::TEXT[], {_revocation_carried_across_digests("team_app_keys")})
            ON CONFLICT (team_id, app_id, origin, digest, key_id) DO NOTHING
            """,
            team_id,
            app_id,
            origin,
            digest,
            app_key.kid,
            app_key.did_key,
            list(app_key.purposes),
        )


@dataclass(frozen=True)
class ManifestRegistration:
    app_version: str
    manifest_version: int
    event_types: list[AppEventType]
    emit_keys: list[AppEmitKey]
    app_keys: list[AppKey]
    requested_scopes: list[str]


def _parse_manifest(manifest: bytes) -> dict:
    try:
        parsed = json.loads(manifest)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValidationError("manifest is not valid JSON") from exc
    if not isinstance(parsed, dict) or not isinstance(parsed.get("app"), dict):
        raise ValidationError("manifest app is required")
    return parsed


def manifest_registration(manifest: bytes, *, app_id: str, origin: str, digest: str) -> ManifestRegistration:
    """Read an install's event declarations and keys from its pinned bytes.

    The bytes must hash to the pinned digest, be valid to the one manifest
    reader (``aweb_naapp.manifest``), and name the installed app id and origin;
    nothing is taken from anywhere else. Version 1 ``event_emitters`` are emit
    keys; version 2 ``app_keys`` are app keys with their declared purposes.
    """

    app_id = normalize_app_id(app_id)
    origin = normalize_origin(origin)
    digest = normalize_digest(digest)
    if "sha256:" + hashlib.sha256(manifest).hexdigest() != digest:
        raise ValidationError("manifest bytes do not match the pinned digest")
    try:
        resolved = load_manifest(manifest, reserved_names=reserved_app_ids())
    except ManifestError as exc:
        raise ValidationError({"code": exc.code, "message": str(exc)}) from exc
    app = resolved.document["app"]
    if normalize_app_id(str(app.get("id") or "")) != app_id:
        raise ValidationError("manifest app id does not match the install")
    if normalize_origin(str(app.get("origin") or "")) != origin:
        raise ValidationError("manifest origin does not match the install")
    prefix = app_id + "/"
    event_types = []
    for event in resolved.document.get("events") or []:
        event_type = str(event.get("type") or "").strip()
        event_types.append(
            AppEventType(
                type=event_type[len(prefix):] if event_type.startswith(prefix) else event_type,
                default_delivery_intent=normalize_delivery_intent(event.get("default_delivery_intent")),
                description=str(event.get("description") or ""),
            )
        )
    if resolved.manifest_version == 1:
        emit_keys = [
            AppEmitKey(kid=str(emitter["kid"]), did_key=str(emitter["did_key"]))
            for emitter in resolved.document.get("event_emitters") or []
        ]
        app_keys: list[AppKey] = []
    else:
        emit_keys = []
        app_keys = [AppKey(kid=kid, did_key=did_key, purposes=tuple(purposes)) for kid, did_key, purposes in resolved.app_keys]
    return ManifestRegistration(
        app_version=normalize_app_version(str(app.get("version") or "")),
        manifest_version=resolved.manifest_version,
        event_types=normalize_event_types(event_types),
        emit_keys=normalize_emit_keys(emit_keys),
        app_keys=app_keys,
        requested_scopes=normalize_scopes(list(resolved.install_scopes)),
    )


@dataclass(frozen=True)
class ReseedReport:
    app_id: str
    origin: str
    digest: str
    reseeded: list[str]
    digest_mismatch: list[str]
    key_conflict: list[str]


async def reseed_app_registrations(db, *, origin: str, manifest: bytes) -> ReseedReport:
    """Recreate team-scoped declarations and emit keys from an app's manifest bytes.

    Every team whose install pins the digest of these bytes gets the bytes'
    declarations, emit keys and version projection. Teams pinned to another
    digest, and teams whose key id already holds a different key, are reported
    and left unchanged. Subscriptions are never touched. Running it again
    changes nothing further.
    """

    origin = normalize_origin(origin)
    app_id = normalize_app_id(str(_parse_manifest(manifest)["app"].get("id") or ""))
    digest = "sha256:" + hashlib.sha256(manifest).hexdigest()
    registration = manifest_registration(manifest, app_id=app_id, origin=origin, digest=digest)
    installs = await db.fetch_all(
        """
        SELECT team_id FROM {{tables.team_app_installs}}
        WHERE app_id = $1 AND origin = $2
        ORDER BY team_id ASC
        """,
        app_id,
        origin,
    )
    reseeded: list[str] = []
    digest_mismatch: list[str] = []
    key_conflict: list[str] = []
    for install in installs:
        team_id = install["team_id"]
        try:
            async with db.transaction() as tx:
                locked = await tx.fetch_one(
                    """
                    SELECT digest FROM {{tables.team_app_installs}}
                    WHERE team_id = $1 AND app_id = $2 AND origin = $3
                    FOR UPDATE
                    """,
                    team_id,
                    app_id,
                    origin,
                )
                if locked is None or locked["digest"] != digest:
                    digest_mismatch.append(team_id)
                    continue
                await tx.execute(
                    """
                    UPDATE {{tables.team_app_installs}}
                    SET app_version = $3, manifest_version = $4, updated_at = NOW()
                    WHERE team_id = $1 AND app_id = $2
                    """,
                    team_id,
                    app_id,
                    registration.app_version,
                    registration.manifest_version,
                )
                await _write_team_registrations(
                    tx,
                    team_id=team_id,
                    app_id=app_id,
                    origin=origin,
                    digest=digest,
                    event_types=registration.event_types,
                    emit_keys=registration.emit_keys,
                    app_keys=registration.app_keys,
                )
        except ConflictError:
            key_conflict.append(team_id)
            continue
        reseeded.append(team_id)
    return ReseedReport(
        app_id=app_id,
        origin=origin,
        digest=digest,
        reseeded=reseeded,
        digest_mismatch=digest_mismatch,
        key_conflict=key_conflict,
    )


async def next_installation_generation_on(tx, *, team_id: str, app_id: str) -> int:
    """Allocate authority order in the caller's installation transaction.

    Every install, reinstall, update and scope change uses this persistent
    counter. Uninstall never deletes it. Existing-installation writers first
    lock the current installation row and check the expected generation.
    Rollback of the caller also rolls back this unissued allocation.
    """
    team_id = validate_team_id(team_id)
    app_id = normalize_app_id(app_id)
    generation = await tx.fetch_value(
        """INSERT INTO {{tables.team_app_install_counters}} AS c
               (team_id, app_id, last_generation) VALUES ($1, $2, 1)
           ON CONFLICT (team_id, app_id) DO UPDATE
               SET last_generation = c.last_generation + 1
           RETURNING last_generation""",
        team_id, app_id,
    )
    return int(generation)


async def get_installation_on(
    tx, *, team_id: str, app_id: str, for_update: bool = False,
) -> dict[str, Any] | None:
    """Read current installation authority in the caller's transaction.

    Task admission/receipt and lifecycle mutations use ``for_update=True`` on
    this same row, serializing retirement with admitted task work. A pending
    origin verification or uninstalled state confers no ordinary authority.
    Pinned manifest bytes are read separately when needed, so credential checks
    never fetch a multi-megabyte manifest just to check an installation.
    """
    team_id = validate_team_id(team_id)
    app_id = normalize_app_id(app_id)
    lock = " FOR UPDATE OF i" if for_update else ""
    row = await tx.fetch_one(
        """SELECT i.team_id, i.app_id, i.installation_id, i.generation, i.state,
                  i.origin, i.digest, i.granted_scopes, i.origin_verified,
                  i.app_version, i.manifest_version, i.origin_verification_error
           FROM {{tables.team_app_installs}} AS i
           WHERE i.team_id = $1 AND i.app_id = $2""" + lock,
        team_id, app_id,
    )
    return dict(row) if row is not None else None


async def list_installed_apps(db, *, team_id: str) -> list[AppInstall]:
    team_id = validate_team_id(team_id)
    rows = await db.fetch_all(
        """
        SELECT
            i.app_id,
            i.origin,
            i.app_version,
            i.manifest_version,
            i.digest,
            i.granted_scopes, i.installation_id, i.generation, i.state,
            i.origin_verified, i.origin_verification_error
        FROM {{tables.team_app_installs}} AS i
        WHERE i.team_id = $1 AND i.state = 'active' AND i.origin_verified
        ORDER BY i.app_id ASC
        """,
        team_id,
    )
    return [
        AppInstall(
            app_id=row["app_id"],
            origin=row["origin"],
            app_version=row["app_version"],
            manifest_version=row["manifest_version"],
            digest=row["digest"],
            granted_scopes=list(row["granted_scopes"] or []),
            installation_id=row["installation_id"], generation=row["generation"],
            state=row["state"], origin_verified=row["origin_verified"],
            origin_verification_error=row["origin_verification_error"],
        )
        for row in rows
    ]


async def get_installed_app(db, *, team_id: str, app_id: str, digest: str) -> AppInstall | None:
    """The team's installation of ``app_id``, only while it is pinned to ``digest``."""
    row = await get_installation_on(db, team_id=team_id, app_id=app_id)
    if row is None or row["digest"] != normalize_digest(digest):
        return None
    return AppInstall(**{key: value for key, value in row.items() if key != "team_id"})


async def get_installed_app_event_type(
    db,
    *,
    team_id: str,
    app_id: str,
    local_event_type: str,
) -> dict | None:
    team_id = validate_team_id(team_id)
    app_id = normalize_app_id(app_id)
    local_event_type = normalize_local_event_type(local_event_type)
    return await db.fetch_one(
        """
        SELECT
            i.origin,
            i.digest,
            e.default_delivery_intent
        FROM {{tables.team_app_installs}} AS i
        JOIN {{tables.team_app_event_types}} AS e
          ON e.team_id = i.team_id
         AND e.app_id = i.app_id
         AND e.origin = i.origin
         AND e.digest = i.digest
        WHERE i.team_id = $1 AND i.state = 'active' AND i.origin_verified
          AND i.app_id = $2
          AND e.event_type = $3
        """,
        team_id,
        app_id,
        local_event_type,
    )


async def get_active_app_key(
    db,
    *,
    team_id: str,
    app_id: str,
    kid: str,
    did_key: str,
    purpose: str,
) -> dict | None:
    """The team's active registered app key for ``purpose``, under its installed digest."""
    team_id = validate_team_id(team_id)
    app_id = normalize_app_id(app_id)
    kid = normalize_key_id(kid)
    did_key = normalize_did_key(did_key)
    return await db.fetch_one(
        """
        SELECT k.app_id, k.origin, k.digest, k.key_id, k.did_key, k.purposes
        FROM {{tables.team_app_installs}} AS i
        JOIN {{tables.team_app_keys}} AS k
          ON k.team_id = i.team_id
         AND k.app_id = i.app_id
         AND k.origin = i.origin
         AND k.digest = i.digest
        WHERE i.team_id = $1
          AND ($5 = 'app-grant-read' OR (i.state = 'active' AND i.origin_verified))
          AND i.app_id = $2
          AND k.key_id = $3
          AND k.did_key = $4
          AND $5 = ANY(k.purposes)
          AND k.revoked_at IS NULL
        """,
        team_id,
        app_id,
        kid,
        did_key,
        purpose,
    )


async def get_active_app_emit_key(
    db,
    *,
    team_id: str,
    app_id: str,
    kid: str,
    did_key: str,
) -> dict | None:
    team_id = validate_team_id(team_id)
    app_id = normalize_app_id(app_id)
    kid = normalize_key_id(kid)
    did_key = normalize_did_key(did_key)
    return await db.fetch_one(
        """
        SELECT k.app_id, k.origin, k.digest, k.key_id, k.did_key
        FROM {{tables.team_app_installs}} AS i
        JOIN {{tables.team_app_emit_keys}} AS k
          ON k.team_id = i.team_id
         AND k.app_id = i.app_id
         AND k.origin = i.origin
         AND k.digest = i.digest
        WHERE i.team_id = $1 AND i.state = 'active' AND i.origin_verified
          AND i.app_id = $2
          AND k.key_id = $3
          AND k.did_key = $4
          AND k.revoked_at IS NULL
        """,
        team_id,
        app_id,
        kid,
        did_key,
    )
