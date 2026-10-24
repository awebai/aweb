"""Transactional registry writes from server-fetched installation evidence.

HTTP callers check current install-admin policy in this same transaction before
calling the writer. Fetching happens beforehand, outside installation locks.
"""

from __future__ import annotations

from uuid import uuid4

from aweb.app_manifests import FetchedManifest, ManifestFetcher
from aweb.app_registry import (
    _write_team_registrations,
    get_installation_on,
    manifest_registration,
    next_installation_generation_on,
    normalize_app_id,
    normalize_scopes,
    validate_team_id,
)
from aweb.hook_bindings import revoke_uninstalled_bindings
from aweb.installation_hooks import write_manifest_bindings_on
from aweb.service_errors import ServiceError


class InstallationError(ServiceError):
    def __init__(self, code: str, message: str, status_code: int = 422) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code


async def _lock_installation_on(tx, *, team_id: str, app_id: str) -> dict | None:
    """Serialize final policy reads and writes, including an absent row.

    Routes take this before final authorization; the writer retakes the same
    transaction locks. Always acquire the advisory lock before the row lock.
    """
    team_id = validate_team_id(team_id)
    app_id = normalize_app_id(app_id)
    await tx.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
        "aweb.installation:" + team_id + ":" + app_id,
    )
    return await get_installation_on(tx, team_id=team_id, app_id=app_id, for_update=True)


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

    current = await _lock_installation_on(tx, team_id=team_id, app_id=app_id)
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
        """INSERT INTO {{tables.team_app_installs}} AS previous
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
               installed_at = CASE WHEN previous.installation_id = EXCLUDED.installation_id
                   THEN previous.installed_at ELSE EXCLUDED.installed_at END,
               state = 'active', origin_verified = TRUE,
               origin_verification_error = NULL, manifest_bytes = EXCLUDED.manifest_bytes,
               updated_at = NOW()""",
        team_id, app_id, fetched.origin, fetched.digest, registration.app_version,
        registration.manifest_version, scopes, installed_by_agent_id,
        installation_id, generation, fetched.data,
    )
    await _write_verified_registrations(tx, team_id=team_id, app_id=app_id, fetched=fetched, registration=registration)
    await write_manifest_bindings_on(tx, team_id=team_id, fetched=fetched, installation_id=installation_id, generation=generation)
    return await get_installation_on(tx, team_id=team_id, app_id=app_id)


async def cleanup_installation_on(tx, *, installation: dict) -> None:
    """Run cleanups under the current installation row lock, in its transaction.

    This is the single seam for installation-scoped retirement. Do not commit,
    open a separate transaction or suppress a cleanup failure.
    """
    from aweb.coordination.app_tasks import cancel_installation_requests_on

    await revoke_uninstalled_bindings(tx, team_id=installation["team_id"], app_id=installation["app_id"])
    await cancel_installation_requests_on(
        tx, team_id=installation["team_id"], app_id=installation["app_id"],
        installation_id=installation["installation_id"],
    )


async def uninstall_installation_on(tx, *, team_id: str, app_id: str, expected_generation: int) -> dict:
    """Retire authority without fetching or deleting the retained installation.

    The route checks current admin policy in this transaction. Keep the pin,
    keys and identity so an authenticated app can observe confirmed uninstall
    even when its origin is unavailable. App content remains with its owner.
    """
    team_id = validate_team_id(team_id)
    app_id = normalize_app_id(app_id)
    if type(expected_generation) is not int or not 1 <= expected_generation <= 9223372036854775807:
        raise InstallationError("generation_invalid", "Expected generation must be a positive BIGINT")
    current = await get_installation_on(tx, team_id=team_id, app_id=app_id, for_update=True)
    if current is None:
        raise InstallationError("installation_not_found", "Installation not found", 404)
    if current["generation"] != expected_generation:
        raise InstallationError("generation_conflict", "Installation changed; read it again", 409)
    if current["state"] == "uninstalled":
        return current
    await cleanup_installation_on(tx, installation=current)
    # A confirmation prepared before uninstall must conflict rather than
    # silently reinstalling after the administrator removed the app.
    generation = await next_installation_generation_on(tx, team_id=team_id, app_id=app_id)
    await tx.execute(
        "UPDATE {{tables.team_app_installs}} SET state='uninstalled', generation=$3, "
        "origin_verification_error=NULL, updated_at=NOW() WHERE team_id=$1 AND app_id=$2",
        team_id, app_id, generation,
    )
    retired = await get_installation_on(tx, team_id=team_id, app_id=app_id)
    assert retired is not None  # The same transaction still holds this row lock.
    return retired


async def _write_verified_registrations(tx, *, team_id, app_id, fetched, registration):
    # Pre-F6 rows may have declarations supplied independently of these bytes.
    # Keep key history/revocations, but never activate an undeclared key.
    event_keys = {(key.kid, key.did_key) for key in registration.emit_keys}
    event_keys.update((key.kid, key.did_key) for key in registration.app_keys if "app-event" in key.purposes)
    app_purposes = {(key.kid, key.did_key): list(key.purposes) for key in registration.app_keys}
    for identity in event_keys:
        app_purposes.setdefault(identity, ["app-event"])
    # Older v2 clients stored declared event keys in the v1 emitter table.
    # Compare logical identities, so verification never invents a revocation
    # merely because the bytes use the other physical representation.
    for table, identities in (("team_app_emit_keys", event_keys), ("team_app_keys", app_purposes)):
        identities = sorted(identities)
        await tx.execute(
            "UPDATE {{tables." + table + "}} AS existing SET revoked_at=COALESCE(existing.revoked_at,clock_timestamp()) "
            "WHERE team_id=$1 AND app_id=$2 AND origin=$3 AND digest=$4 AND NOT EXISTS ("
            "SELECT 1 FROM unnest($5::TEXT[],$6::TEXT[]) AS declared(kid,did) "
            "WHERE declared.kid=existing.key_id AND declared.did=existing.did_key)",
            team_id, app_id, fetched.origin, fetched.digest,
            [identity[0] for identity in identities], [identity[1] for identity in identities],
        )
    await tx.execute(
        "DELETE FROM {{tables.team_app_event_types}} WHERE team_id=$1 AND app_id=$2 AND origin=$3 AND digest=$4 AND NOT (event_type=ANY($5::TEXT[]))",
        team_id, app_id, fetched.origin, fetched.digest, [event.type for event in registration.event_types],
    )
    await _write_team_registrations(
        tx, team_id=team_id, app_id=app_id, origin=fetched.origin, digest=fetched.digest,
        event_types=registration.event_types, emit_keys=registration.emit_keys, app_keys=registration.app_keys,
    )
    for (kid, did), purposes in app_purposes.items():
        await tx.execute(
            "UPDATE {{tables.team_app_keys}} SET purposes=$7::TEXT[] WHERE team_id=$1 AND app_id=$2 AND origin=$3 AND digest=$4 AND key_id=$5 AND did_key=$6",
            team_id, app_id, fetched.origin, fetched.digest, kid, did, purposes,
        )


def _same_pending(current, expected):
    return current is not None and current["state"] == "pending_origin_verification" and all(
        current[key] == expected[key] for key in ("installation_id", "generation", "origin", "digest")
    )


async def verify_pending_installations(db, *, fetcher: ManifestFetcher | None = None, team_id: str | None = None, app_id: str | None = None, expected_identity: tuple[str, int, str] | None = None) -> list[dict]:
    """Operator/job verification, never a migration or request-path fetch.

    The network read holds no installation lock. The same pinned pending row
    must still exist when we lock it to activate, or record a failure reason.
    """
    if team_id is not None:
        team_id = validate_team_id(team_id)
    rows = await db.fetch_all(
        "SELECT team_id,app_id,installation_id,generation,origin,digest,manifest_version "
        "FROM {{tables.team_app_installs}} WHERE state='pending_origin_verification' "
        "AND ($1::TEXT IS NULL OR team_id=$1) AND ($2::TEXT IS NULL OR app_id=$2) ORDER BY team_id,app_id", team_id, app_id,
    )
    fetcher = fetcher or ManifestFetcher()
    reports = []
    for expected in rows:
        if expected_identity is not None and tuple(expected[key] for key in ("installation_id", "generation", "digest")) != expected_identity:
            continue
        report = {key: expected[key] for key in ("team_id", "app_id", "installation_id", "generation")}
        try:
            fetched = await fetcher.fetch(
                expected["origin"], expected_digest=expected["digest"], manifest_version=expected["manifest_version"],
            )
            registration = manifest_registration(
                fetched.data, app_id=expected["app_id"], origin=expected["origin"], digest=expected["digest"],
            )
            async with db.transaction() as tx:
                current = await get_installation_on(tx, team_id=expected["team_id"], app_id=expected["app_id"], for_update=True)
                if not _same_pending(current, expected):
                    reports.append(dict(report, outcome="superseded"))
                    continue
                if not set(current["granted_scopes"]) <= set(registration.requested_scopes):
                    raise InstallationError("scope_not_requested", "Stored scopes are not requested by the pinned manifest")
                await _write_verified_registrations(
                    tx, team_id=expected["team_id"], app_id=expected["app_id"], fetched=fetched, registration=registration,
                )
                await tx.execute(
                    "UPDATE {{tables.team_app_installs}} SET state='active', origin_verified=TRUE, "
                    "origin_verification_error=NULL, manifest_bytes=$3, app_version=$4, manifest_version=$5, "
                    "registered_from_manifest_bytes=TRUE, updated_at=NOW() WHERE team_id=$1 AND app_id=$2",
                    expected["team_id"], expected["app_id"], fetched.data, registration.app_version, registration.manifest_version,
                )
                await write_manifest_bindings_on(
                    tx, team_id=expected["team_id"], fetched=fetched,
                    installation_id=current["installation_id"], generation=current["generation"],
                )
            reports.append(dict(report, outcome="verified"))
        except ServiceError as exc:
            code = str(getattr(exc, "code", "origin_verification_failed"))[:128]
            async with db.transaction() as tx:
                current = await get_installation_on(tx, team_id=expected["team_id"], app_id=expected["app_id"], for_update=True)
                if not _same_pending(current, expected):
                    reports.append(dict(report, outcome="superseded"))
                    continue
                await tx.execute(
                    "UPDATE {{tables.team_app_installs}} SET origin_verification_error=$3 WHERE team_id=$1 AND app_id=$2",
                    expected["team_id"], expected["app_id"], code,
                )
            reports.append(dict(report, outcome="pending", error=code))
    return reports
