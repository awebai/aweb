"""Member installation requests and durable origin-verification jobs.

Neither a member request nor a queued verification grants authority. Callers
authenticate and check current admin policy before approval or job creation.
"""

import json
from dataclasses import asdict

from aweb.app_registry import get_installation_on, normalize_scopes
from aweb.installations import (
    InstallationError,
    install_verified_manifest_on,
    verify_pending_installations,
)


async def request_installation_on(tx, *, team_id, fetched, requested_scopes, actor):
    scopes = normalize_scopes(requested_scopes)
    if not set(scopes) <= set(fetched.manifest.install_scopes):
        raise InstallationError("scope_not_requested", "Requested scopes must be declared by the manifest")
    row = await tx.fetch_one(
        """INSERT INTO {{tables.app_installation_requests}}
           (team_id,app_id,origin,digest,requested_scopes,requested_by,manifest_bytes)
           VALUES ($1,$2,$3,$4,$5::TEXT[],$6::JSONB,$7)
           RETURNING request_id,app_id,origin,digest,requested_scopes,state,created_at""",
        team_id, fetched.manifest.app_id, fetched.origin, fetched.digest, scopes, json.dumps(asdict(actor)), fetched.data,
    )
    return dict(row)


async def get_installation_request_on(tx, *, team_id, request_id, for_update=False):
    row = await tx.fetch_one(
        "SELECT * FROM {{tables.app_installation_requests}} WHERE team_id=$1 AND request_id=$2" +
        (" FOR UPDATE" if for_update else ""), team_id, request_id,
    )
    if row is None:
        raise InstallationError("installation_request_not_found", "Installation request not found", 404)
    return dict(row)


async def approve_installation_request_on(tx, *, team_id, request_id, fetched, granted_scopes, expected_generation, installed_by_agent_id=None, hook_context=None):
    requested = await get_installation_request_on(tx, team_id=team_id, request_id=request_id, for_update=True)
    if requested["state"] != "pending":
        raise InstallationError("installation_request_resolved", "Installation request has already been resolved", 409)
    if (requested["app_id"], requested["origin"], requested["digest"]) != (fetched.manifest.app_id, fetched.origin, fetched.digest):
        raise InstallationError("manifest_changed", "Preview the changed manifest before confirming", 409)
    if not set(granted_scopes) <= set(requested["requested_scopes"]):
        raise InstallationError("scope_not_requested", "Approval scopes must be a subset of the member request")
    installation = await install_verified_manifest_on(
        tx, team_id=team_id, fetched=fetched, granted_scopes=granted_scopes,
        expected_generation=expected_generation, installed_by_agent_id=installed_by_agent_id,
        hook_context=hook_context,
    )
    await tx.execute(
        "UPDATE {{tables.app_installation_requests}} SET state='approved',installation_id=$3,generation=$4,resolved_at=clock_timestamp() "
        "WHERE team_id=$1 AND request_id=$2", team_id, request_id, installation["installation_id"], installation["generation"],
    )
    return installation


async def queue_installation_verification_on(tx, *, team_id, app_id, expected_generation):
    current = await get_installation_on(tx, team_id=team_id, app_id=app_id, for_update=True)
    if current is None:
        raise InstallationError("installation_not_found", "Installation not found", 404)
    if current["generation"] != expected_generation:
        raise InstallationError("generation_conflict", "Installation changed; read it again", 409)
    if current["state"] != "pending_origin_verification":
        raise InstallationError("verification_not_pending", "This installation does not need origin verification", 409)
    await tx.execute(
        """UPDATE {{tables.app_installation_verifications}} SET state='complete',lease_until=NULL,
                  result='{"outcome":"superseded"}'::JSONB
           WHERE team_id=$1 AND app_id=$2 AND state IN ('queued','running')
           AND (installation_id<>$3 OR generation<>$4 OR digest<>$5)""",
        team_id, app_id, current["installation_id"], current["generation"], current["digest"],
    )
    row = await tx.fetch_one(
        """INSERT INTO {{tables.app_installation_verifications}} (team_id,app_id,installation_id,generation,digest)
           VALUES ($1,$2,$3,$4,$5) ON CONFLICT (team_id,app_id) WHERE state IN ('queued','running')
           DO UPDATE SET app_id=EXCLUDED.app_id RETURNING job_id,state""",
        team_id, app_id, current["installation_id"], current["generation"], current["digest"],
    )
    return dict(row)


async def run_installation_verifications(db, *, fetcher=None, limit=25):
    """Process bounded queued work. Leases recover jobs after worker crashes."""
    reports = []
    for _ in range(limit):
        async with db.transaction() as tx:
            job = await tx.fetch_one(
                """SELECT * FROM {{tables.app_installation_verifications}}
                   WHERE state='queued' OR (state='running' AND lease_until < clock_timestamp())
                   ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1""",
            )
            if job is None:
                break
            await tx.execute(
                "UPDATE {{tables.app_installation_verifications}} SET state='running',lease_until=clock_timestamp()+INTERVAL '2 minutes' WHERE job_id=$1", job["job_id"],
            )
        # The verifier rechecks the pin and pending identity after its fetch.
        current = await get_installation_on(db, team_id=job["team_id"], app_id=job["app_id"])
        if current is None or any(current[key] != job[key] for key in ("installation_id", "generation", "digest")):
            result = {"outcome": "superseded"}
        else:
            results = await verify_pending_installations(
                db, fetcher=fetcher, team_id=job["team_id"], app_id=job["app_id"],
                expected_identity=(job["installation_id"], job["generation"], job["digest"]),
            )
            result = results[0] if results else {"outcome": "superseded"}
        await db.execute(
            "UPDATE {{tables.app_installation_verifications}} SET state='complete',lease_until=NULL,result=$2::JSONB WHERE job_id=$1",
            job["job_id"], json.dumps(result),
        )
        reports.append({"job_id": str(job["job_id"]), **result})
    return reports
