"""Generic current install administration policy for standalone and mounted hosts.

Authentication supplies the subject. A host-supplied policy establishes install
authority from its controller/delegation model inside the caller's transaction.
Ordinary membership, role strings and audit attribution grant no authority.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Protocol

from fastapi import HTTPException, Request
from pgdbm.core import TransactionManager

from aweb.app_registry import validate_team_id
from aweb.install_admins import standalone_install_admin_policy
from aweb.internal_auth import parse_internal_auth_context
from aweb.service_errors import RESOURCE_NOT_FOUND_DETAIL, ServiceError
from aweb.team_auth_deps import TeamIdentity


@dataclass(frozen=True, kw_only=True)
class CertificateInstallAdminSubject:
    team_id: str
    agent_id: str
    certificate_id: str
    did_key: str
    kind: Literal["certificate"] = field(default="certificate", init=False)


@dataclass(frozen=True, kw_only=True)
class InternalInstallAdminSubject:
    team_id: str
    principal_type: str
    principal_id: str
    actor_id: str
    kind: Literal["internal"] = field(default="internal", init=False)


InstallAdminSubject = CertificateInstallAdminSubject | InternalInstallAdminSubject


class InstallAdminPolicy(Protocol):
    async def __call__(
        self,
        tx: TransactionManager,
        subject: InstallAdminSubject,
        *,
        action: str,
        app_id: str,
        verified_origin: str | None = None,
    ) -> bool:
        """Read current controller/delegation authority; return True to permit.

        The policy belongs on ``request.app.state.install_admin_policy`` of
        the actual serving/mounted app. Do not cache a positive decision or
        infer authority from a certificate role, custody or an audit actor.
        Install/update and request approval supply the server-fetched origin
        in the writing transaction; other actions omit it.
        """
        ...


class InstallAdmissionPolicy(Protocol):
    async def __call__(
        self,
        tx: TransactionManager,
        subject: InstallAdminSubject,
        *,
        action: str,
        app_id: str,
        unverified_origin: str,
    ) -> bool:
        """Permit fetching from an unverified hint, never an installation write."""
        ...


def _admin_required() -> HTTPException:
    return HTTPException(
        status_code=403,
        detail={"code": "admin_required", "message": "Ask a team administrator to approve this installation action"},
    )


async def require_install_admin(
    tx: TransactionManager,
    request: Request,
    identity: TeamIdentity | None,
    team_id: str,
    *,
    action: str,
    app_id: str,
    verified_origin: str | None = None,
) -> None:
    """Check current install authority in the mutation's transaction.

    Certificate routes pass their already authenticated TeamIdentity. Internal
    callers are parsed and authenticated by the existing internal-auth verifier,
    with explicit proxy trust and a matching HMAC. A configured host policy is
    the only authority source; otherwise standalone operator grants apply.
    Exceptions and non-True policy results never authorize a mutation.
    """
    subject = _install_subject(request, identity, team_id)
    policy: InstallAdminPolicy | None = getattr(request.app.state, "install_admin_policy", None)
    if policy is None:
        policy = standalone_install_admin_policy
    context = {} if verified_origin is None else {"verified_origin": verified_origin}
    await _check_policy(policy, tx, subject, action=action, app_id=app_id, **context)


async def require_install_admission(
    tx: TransactionManager,
    request: Request,
    identity: TeamIdentity | None,
    team_id: str,
    *,
    action: str,
    app_id: str,
    unverified_origin: str,
) -> None:
    """Admit network work only; final authority must be checked after fetching."""
    policy: InstallAdmissionPolicy | None = getattr(request.app.state, "install_admission_policy", None)
    if policy is None:
        await require_install_admin(tx, request, identity, team_id, action=action, app_id=app_id)
        return
    subject = _install_subject(request, identity, team_id)
    await _check_policy(policy, tx, subject, action=action, app_id=app_id, unverified_origin=unverified_origin)


async def _check_policy(policy, tx, subject, **context) -> None:
    try:
        permitted = await policy(tx, subject, **context)
    except ServiceError:
        # Preserve the standalone policy's named authority-unavailable response.
        raise
    except Exception as exc:
        raise HTTPException(status_code=503, detail={
            "code": "install_policy_unavailable", "message": "Installation policy is unavailable",
        }) from exc
    if permitted is not True:
        raise _admin_required()


def _install_subject(request: Request, identity: TeamIdentity | None, team_id: str) -> InstallAdminSubject:
    team_id = validate_team_id(team_id)
    if identity is not None:
        if identity.team_id != team_id:
            raise HTTPException(status_code=404, detail=RESOURCE_NOT_FOUND_DETAIL)
        if identity.grant is not None:
            raise _admin_required()

    subject: InstallAdminSubject
    internal = parse_internal_auth_context(request)
    if internal is not None:
        if internal["team_id"] != team_id:
            raise HTTPException(status_code=404, detail=RESOURCE_NOT_FOUND_DETAIL)
        subject = InternalInstallAdminSubject(
            team_id=team_id, principal_type=internal["principal_type"],
            principal_id=internal["principal_id"], actor_id=internal["actor_id"],
        )
    elif identity is not None:
        subject = CertificateInstallAdminSubject(
            team_id=team_id, agent_id=identity.agent_id,
            certificate_id=identity.certificate_id, did_key=identity.did_key,
        )
    else:
        raise HTTPException(status_code=401, detail="Authentication required")

    return subject
