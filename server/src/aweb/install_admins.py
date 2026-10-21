"""Standalone install-admin grants managed only by the local server operator.

Member/profile/certificate role labels are never an authority source. HTTP
routes only read this table through InstallAdminPolicy; no route manages it.
"""

from typing import TYPE_CHECKING

from awid.did import public_key_from_did
from pgdbm.errors import QueryError

from aweb.app_registry import validate_team_id
from aweb.service_errors import ServiceError

if TYPE_CHECKING:
    from aweb.install_authority import InstallAdminSubject


class InstallAdminGrantError(ServiceError):
    def __init__(self, code, message, status_code=422):
        super().__init__(message)
        self.code = code
        self.status_code = status_code


def _principal(value):
    value = value.strip()
    try:
        public_key_from_did(value)
    except ValueError as exc:
        raise InstallAdminGrantError("principal_invalid", "Use the member's Ed25519 did:key") from exc
    return value


async def standalone_install_admin_policy(tx, subject: "InstallAdminSubject", *, action, app_id) -> bool:
    if subject.kind != "certificate":
        return False
    try:
        row = await tx.fetch_one(
            "SELECT role FROM {{tables.team_app_install_admins}} "
            "WHERE team_id=$1 AND principal_did=$2 AND revoked_at IS NULL FOR SHARE",
            subject.team_id, subject.did_key,
        )
    except QueryError as exc:
        raise InstallAdminGrantError("authority_unavailable", "Installation administration is unavailable", 503) from exc
    return row is not None and row["role"] in ("owner", "admin")


async def _operator_lock(tx, team_id):
    await tx.execute("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", "aweb.install-admin:" + team_id)
    if not await tx.fetch_value("SELECT EXISTS(SELECT 1 FROM {{tables.teams}} WHERE team_id=$1)", team_id):
        raise InstallAdminGrantError("team_not_found", "Team not found", 404)
    return await tx.fetch_value("SELECT current_user")


async def _protect_last_owner(tx, team_id, current, force):
    if current is not None and current["role"] == "owner" and current["revoked_at"] is None and not force:
        owners = await tx.fetch_value(
            "SELECT count(*) FROM {{tables.team_app_install_admins}} WHERE team_id=$1 AND role='owner' AND revoked_at IS NULL", team_id,
        )
        if owners == 1:
            raise InstallAdminGrantError("last_owner", "Refusing to remove the last owner; use --force explicitly", 409)


async def _audit(tx, *, team_id, principal_did, role, action, operator, force):
    await tx.execute(
        "INSERT INTO {{tables.app_install_admin_audit}} (team_id,principal_did,role,action,operator,forced) VALUES ($1,$2,$3,$4,$5,$6)",
        team_id, principal_did, role, action, operator, force,
    )


async def grant_install_admin_on(tx, *, team_id, principal_did, role="admin", force=False):
    """Local operator only; the caller owns the transaction and audit outcome."""
    team_id, principal_did = validate_team_id(team_id), _principal(principal_did)
    if role not in ("owner", "admin"):
        raise InstallAdminGrantError("role_invalid", "Role must be owner or admin")
    operator = await _operator_lock(tx, team_id)
    current = await tx.fetch_one(
        "SELECT role,revoked_at FROM {{tables.team_app_install_admins}} WHERE team_id=$1 AND principal_did=$2 FOR UPDATE", team_id, principal_did,
    )
    if role != "owner":
        await _protect_last_owner(tx, team_id, current, force)
    row = await tx.fetch_one(
        "INSERT INTO {{tables.team_app_install_admins}} (team_id,principal_did,role,granted_by) VALUES ($1,$2,$3,$4) "
        "ON CONFLICT (team_id,principal_did) DO UPDATE SET role=EXCLUDED.role,granted_by=EXCLUDED.granted_by,"
        "granted_at=clock_timestamp(),revoked_at=NULL RETURNING *",
        team_id, principal_did, role, operator,
    )
    await _audit(tx, team_id=team_id, principal_did=principal_did, role=role, action="grant", operator=operator, force=force)
    return dict(row)


async def revoke_install_admin_on(tx, *, team_id, principal_did, force=False):
    team_id, principal_did = validate_team_id(team_id), _principal(principal_did)
    operator = await _operator_lock(tx, team_id)
    current = await tx.fetch_one(
        "SELECT role,revoked_at FROM {{tables.team_app_install_admins}} WHERE team_id=$1 AND principal_did=$2 FOR UPDATE", team_id, principal_did,
    )
    if current is None or current["revoked_at"] is not None:
        return False
    await _protect_last_owner(tx, team_id, current, force)
    await tx.execute(
        "UPDATE {{tables.team_app_install_admins}} SET revoked_at=clock_timestamp() WHERE team_id=$1 AND principal_did=$2", team_id, principal_did,
    )
    await _audit(tx, team_id=team_id, principal_did=principal_did, role=current["role"], action="revoke", operator=operator, force=force)
    return True


async def list_install_admins_on(tx, *, team_id):
    rows = await tx.fetch_all(
        "SELECT * FROM {{tables.team_app_install_admins}} WHERE team_id=$1 ORDER BY principal_did", validate_team_id(team_id),
    )
    return [dict(row) for row in rows]


INSTALL_ADMIN_SETUP_MESSAGE = (
    "No standalone installation admins are granted. Bootstrap the first owner locally: "
    "aweb install-admin grant --team-id <team> --principal-did <member-did:key> --role owner. "
    "Member requests remain available; core mail and chat do not require an install-admin grant."
)


async def install_admin_setup_message(db):
    try:
        exists = await db.fetch_value("SELECT EXISTS(SELECT 1 FROM {{tables.team_app_install_admins}} WHERE revoked_at IS NULL)")
    except QueryError:
        # Startup is not an authority grant. Missing migration/admin state must
        # never prevent the core communication service from starting.
        return INSTALL_ADMIN_SETUP_MESSAGE
    return None if exists else INSTALL_ADMIN_SETUP_MESSAGE
