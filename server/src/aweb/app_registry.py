"""Core app registry and per-team app grants."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files
from pathlib import Path
from urllib.parse import urlparse

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


@dataclass(frozen=True)
class AppEventType:
    type: str
    default_delivery_intent: str = "ambient"
    description: str = ""


@dataclass(frozen=True)
class AppEmitKey:
    kid: str
    did_key: str


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
        if not isinstance(value, str) or not APP_ID_RE.match(value):
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
) -> AppInstall:
    """Install or explicitly re-install an app for a team.

    Re-install/update is explicit: the caller supplies the new pinned digest and
    scopes. Reusing an app id for a different origin is rejected as an app-id
    collision.
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

    registered = await db.fetch_one(
        """
        SELECT origin FROM {{tables.app_registry_apps}}
        WHERE app_id = $1
        """,
        app_id,
    )
    if registered and registered["origin"] != origin:
        raise ConflictError("app_id is already registered from a different origin")

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
            ON CONFLICT (app_id) DO NOTHING
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
            ON CONFLICT (app_id, origin, digest) DO UPDATE SET
                app_version = EXCLUDED.app_version,
                manifest_version = EXCLUDED.manifest_version,
                updated_at = NOW()
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
                team_id, app_id, origin, digest, granted_scopes,
                installed_by_agent_id, updated_at
            )
            VALUES ($1, $2, $3, $4, $5::TEXT[], $6::UUID, NOW())
            ON CONFLICT (team_id, app_id) DO UPDATE SET
                origin = EXCLUDED.origin,
                digest = EXCLUDED.digest,
                granted_scopes = EXCLUDED.granted_scopes,
                installed_by_agent_id = EXCLUDED.installed_by_agent_id,
                updated_at = NOW()
            """,
            team_id,
            app_id,
            origin,
            digest,
            granted_scopes,
            installed_by_agent_id,
        )
        for event_type in event_types:
            await tx.execute(
                """
                INSERT INTO {{tables.app_registry_event_types}} (
                    app_id, origin, digest, event_type, default_delivery_intent,
                    description, updated_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, NOW())
                ON CONFLICT (app_id, origin, digest, event_type) DO UPDATE SET
                    default_delivery_intent = EXCLUDED.default_delivery_intent,
                    description = EXCLUDED.description,
                    updated_at = NOW()
                """,
                app_id,
                origin,
                digest,
                event_type.type,
                event_type.default_delivery_intent,
                event_type.description,
            )
        for emit_key in emit_keys:
            await tx.execute(
                """
                INSERT INTO {{tables.app_registry_emit_keys}} (app_id, key_id, did_key)
                VALUES ($1, $2, $3)
                ON CONFLICT (app_id, key_id) DO UPDATE SET
                    did_key = EXCLUDED.did_key,
                    revoked_at = NULL
                """,
                app_id,
                emit_key.kid,
                emit_key.did_key,
            )

    return AppInstall(
        app_id=app_id,
        origin=origin,
        app_version=app_version,
        manifest_version=manifest_version,
        digest=digest,
        granted_scopes=granted_scopes,
    )


async def list_installed_apps(db, *, team_id: str) -> list[AppInstall]:
    team_id = validate_team_id(team_id)
    rows = await db.fetch_all(
        """
        SELECT
            i.app_id,
            i.origin,
            r.app_version,
            r.manifest_version,
            i.digest,
            i.granted_scopes
        FROM {{tables.team_app_installs}} AS i
        JOIN {{tables.app_registry_entries}} AS r
          ON r.app_id = i.app_id
         AND r.origin = i.origin
         AND r.digest = i.digest
        WHERE i.team_id = $1
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
        )
        for row in rows
    ]


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
        JOIN {{tables.app_registry_event_types}} AS e
          ON e.app_id = i.app_id
         AND e.origin = i.origin
         AND e.digest = i.digest
        WHERE i.team_id = $1
          AND i.app_id = $2
          AND e.event_type = $3
        """,
        team_id,
        app_id,
        local_event_type,
    )


async def get_active_app_emit_key(
    db,
    *,
    app_id: str,
    kid: str,
    did_key: str,
) -> dict | None:
    app_id = normalize_app_id(app_id)
    kid = normalize_key_id(kid)
    did_key = normalize_did_key(did_key)
    return await db.fetch_one(
        """
        SELECT app_id, key_id, did_key
        FROM {{tables.app_registry_emit_keys}}
        WHERE app_id = $1
          AND key_id = $2
          AND did_key = $3
          AND revoked_at IS NULL
        """,
        app_id,
        kid,
        did_key,
    )
