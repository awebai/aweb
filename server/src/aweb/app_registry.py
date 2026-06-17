"""Core app registry and per-team app grants."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

from awid.team_ids import parse_team_id

from aweb.service_errors import BadRequestError, ConflictError, ValidationError

APP_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SCOPE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}$")

RESERVED_APP_IDS = frozenset(
    {
        "a2a",
        "agent",
        "agents",
        "chat",
        "claim",
        "claims",
        "connect",
        "contact",
        "contacts",
        "control",
        "heartbeat",
        "help",
        "id",
        "instruction",
        "instructions",
        "lock",
        "locks",
        "mail",
        "mcp",
        "mcp-config",
        "plugin",
        "plugins",
        "repo",
        "repos",
        "reservation",
        "reservations",
        "role",
        "roles",
        "run",
        "status",
        "task",
        "tasks",
        "team",
        "teams",
        "work",
        "workspace",
        "workspaces",
    }
)


@dataclass(frozen=True)
class AppInstall:
    app_id: str
    origin: str
    app_version: str
    manifest_version: int
    digest: str
    granted_scopes: list[str]


def normalize_app_id(value: str) -> str:
    app_id = (value or "").strip().lower()
    if not APP_ID_RE.match(app_id):
        raise ValidationError("app_id must match ^[a-z][a-z0-9-]{0,62}$")
    if app_id.endswith("-") or "--" in app_id:
        raise ValidationError("app_id must not end with '-' or contain '--'")
    if app_id in RESERVED_APP_IDS:
        raise ConflictError(f"app_id {app_id!r} is reserved")
    return app_id


def normalize_origin(value: str) -> str:
    raw = (value or "").strip()
    parsed = urlparse(raw)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValidationError("origin scheme must be http or https")
    if parsed.username or parsed.password:
        raise ValidationError("origin must not include userinfo")
    if parsed.params or parsed.query or parsed.fragment:
        raise ValidationError("origin must not include params, query, or fragment")
    if not parsed.hostname:
        raise ValidationError("origin host is required")
    path = (parsed.path or "").rstrip("/")
    if path:
        raise ValidationError("origin must be an origin URL, not a path")
    host = parsed.hostname.lower()
    host_out = f"[{host}]" if ":" in host and not host.startswith("[") else host
    default_port = 80 if scheme == "http" else 443
    port = None if parsed.port in {None, default_port} else parsed.port
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
