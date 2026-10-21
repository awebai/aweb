"""Transactional registry writes from server-fetched installation evidence.

HTTP callers check current install-admin policy in this same transaction before
calling the writer. Fetching happens beforehand, outside installation locks.
"""

from __future__ import annotations

from uuid import uuid4

from aweb.app_manifests import FetchedManifest
from aweb.app_registry import (
    _write_team_registrations,
    get_installation_on,
    manifest_registration,
    next_installation_generation_on,
    normalize_scopes,
    validate_team_id,
)
from aweb.service_errors import ServiceError


class InstallationError(ServiceError):
    def __init__(self, code: str, message: str, status_code: int = 422) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code


async def install_verified_manifest_on(
    tx,
    *,
    team_id: str,
    fetched: FetchedManifest,
    granted_scopes: list[str],
    expected_generation: int | None = None,
    installed_by_agent_id: str | None = None,
) -> dict:
    """Confirm exact fetched bytes inside the caller's authorized transaction.

    A persistent advisory lock serializes creation when no installation row
    exists yet. Existing rows are locked through the same reader C2 uses. The
    installation row precedes the generation counter on every mutation path.
    """
    team_id = validate_team_id(team_id)
    app_id = fetched.manifest.app_id
    registration = manifest_registration(
        fetched.data, app_id=app_id, origin=fetched.origin, digest=fetched.digest,
    )
    scopes = normalize_scopes(granted_scopes)
    if not set(scopes) <= set(registration.requested_scopes):
        raise InstallationError("scope_not_requested", "Granted scopes must be requested by the manifest")
    if expected_generation is not None and (
        type(expected_generation) is not int or not 1 <= expected_generation <= 9223372036854775807
    ):
        raise InstallationError("generation_invalid", "Expected generation must be a positive BIGINT")

    await tx.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
        "aweb.installation:" + team_id + ":" + app_id,
    )
    current = await get_installation_on(tx, team_id=team_id, app_id=app_id, for_update=True)
    if current is not None:
        if expected_generation is None:
            raise InstallationError("generation_required", "Supply the current installation generation")
        if expected_generation != current["generation"]:
            raise InstallationError("generation_conflict", "Installation changed; read it again", 409)
        if current["origin"] != fetched.origin and current["state"] != "uninstalled":
            raise InstallationError("app_origin_conflict", "This app is installed from another origin", 409)
    elif expected_generation is not None:
        raise InstallationError("generation_conflict", "The expected installation no longer exists", 409)

    installation_id = (
        current["installation_id"] if current is not None and current["state"] != "uninstalled" else str(uuid4())
    )
    generation = await next_installation_generation_on(tx, team_id=team_id, app_id=app_id)
    await tx.execute(
        """INSERT INTO {{tables.app_registry_apps}} (app_id, origin, updated_at)
           VALUES ($1, $2, NOW()) ON CONFLICT (app_id, origin) DO NOTHING""",
        app_id, fetched.origin,
    )
    await tx.execute(
        """INSERT INTO {{tables.app_registry_entries}}
           (app_id, origin, digest, app_version, manifest_version, updated_at)
           VALUES ($1, $2, $3, $4, $5, NOW())
           ON CONFLICT (app_id, origin, digest) DO NOTHING""",
        app_id, fetched.origin, fetched.digest, registration.app_version, registration.manifest_version,
    )
    await tx.execute(
        """INSERT INTO {{tables.team_app_installs}}
           (team_id, app_id, origin, digest, app_version, manifest_version,
            granted_scopes, installed_by_agent_id, registered_from_manifest_bytes,
            installation_id, generation, state, origin_verified, manifest_bytes, updated_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7::TEXT[], $8::UUID, TRUE,
                   $9, $10, 'active', TRUE, $11, NOW())
           ON CONFLICT (team_id, app_id) DO UPDATE SET
               origin = EXCLUDED.origin, digest = EXCLUDED.digest,
               app_version = EXCLUDED.app_version, manifest_version = EXCLUDED.manifest_version,
               granted_scopes = EXCLUDED.granted_scopes,
               installed_by_agent_id = EXCLUDED.installed_by_agent_id,
               registered_from_manifest_bytes = TRUE,
               installation_id = EXCLUDED.installation_id, generation = EXCLUDED.generation,
               state = 'active', origin_verified = TRUE,
               origin_verification_error = NULL, manifest_bytes = EXCLUDED.manifest_bytes,
               updated_at = NOW()""",
        team_id, app_id, fetched.origin, fetched.digest, registration.app_version,
        registration.manifest_version, scopes, installed_by_agent_id,
        installation_id, generation, fetched.data,
    )
    await _write_team_registrations(
        tx, team_id=team_id, app_id=app_id, origin=fetched.origin, digest=fetched.digest,
        event_types=registration.event_types, emit_keys=registration.emit_keys,
        app_keys=registration.app_keys,
    )
    return await get_installation_on(tx, team_id=team_id, app_id=app_id)
