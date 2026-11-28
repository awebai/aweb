"""Generic current install administration policy for standalone and mounted hosts.

Authentication supplies the subject. A host-supplied policy establishes install
authority from its controller/delegation model inside the caller's transaction.
Ordinary membership, role strings and audit attribution grant no authority.
"""

from __future__ import annotations

from collections.abc import Generator
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol, overload

from fastapi import HTTPException, Request
from pgdbm.core import TransactionManager

from aweb.app_registry import validate_team_id
from aweb.install_admins import standalone_install_admin_policy
from aweb.internal_auth import parse_internal_auth_context, resolve_internal_actor
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
        detail={
            "code": "admin_required",
            "message": "Ask a team administrator to approve this installation action",
        },
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
    subject = await _install_subject(tx, request, identity, team_id)
    policy: InstallAdminPolicy | None = getattr(
        request.app.state, "install_admin_policy", None
    )
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
    policy: InstallAdmissionPolicy | None = getattr(
        request.app.state, "install_admission_policy", None
    )
    if policy is None:
        await require_install_admin(
            tx, request, identity, team_id, action=action, app_id=app_id
        )
        return
    subject = await _install_subject(tx, request, identity, team_id)
    await _check_policy(
        policy,
        tx,
        subject,
        action=action,
        app_id=app_id,
        unverified_origin=unverified_origin,
    )


@overload
def policy_verdict(returned: object = None, *, raised: Exception) -> Exception: ...


@overload
def policy_verdict(
    returned: object = None, *, raised: None = None
) -> Exception | None: ...


def policy_verdict(
    returned: object = None, *, raised: Exception | None = None
) -> Exception | None:
    """How install authority reads a policy's answer: None permits.

    The policy either returned a value or raised. The standalone policy's
    named service errors pass through as they are; any other failure is the
    policy being unavailable; only a returned ``True`` permits.
    """
    if isinstance(raised, ServiceError):
        return raised
    if raised is not None:
        return HTTPException(
            status_code=503,
            detail={
                "code": "install_policy_unavailable",
                "message": "Installation policy is unavailable",
            },
        )
    if returned is not True:
        return _admin_required()
    return None


async def _check_policy(policy, tx, subject, **context) -> None:
    try:
        permitted = await policy(tx, subject, **context)
    except Exception as exc:  # noqa: BLE001 - a host policy's failure is its answer
        failure = policy_verdict(raised=exc)
        if failure is exc:
            raise
        raise failure from exc
    refusal = policy_verdict(permitted)
    if refusal is not None:
        raise refusal


# The fact the subject rule asks for once a certificate caller passes: the
# verified internal-auth context, or None.
INTERNAL = "internal"


def install_subject_rule(
    team_id: str, identity: TeamIdentity | None
) -> Generator[str, Any, InstallAdminSubject | HTTPException]:
    """The subject install authority asks the policy about, or the refusal.

    ``identity`` is the route's authenticated certificate caller. A
    certificate caller must be in the team and act without a delegated grant;
    only then does the rule ask for the internal-auth context, whose caller
    must name the team and is the subject when present.
    """
    if identity is not None:
        if identity.team_id != team_id:
            return HTTPException(status_code=404, detail=RESOURCE_NOT_FOUND_DETAIL)
        if identity.grant is not None:
            return _admin_required()
    internal = yield INTERNAL
    if internal is not None:
        if internal["team_id"] != team_id:
            return HTTPException(status_code=404, detail=RESOURCE_NOT_FOUND_DETAIL)
        return InternalInstallAdminSubject(
            team_id=team_id,
            principal_type=internal["principal_type"],
            principal_id=internal["principal_id"],
            actor_id=internal["actor_id"],
        )
    if identity is not None:
        return CertificateInstallAdminSubject(
            team_id=team_id,
            agent_id=identity.agent_id,
            certificate_id=identity.certificate_id,
            did_key=identity.did_key,
        )
    return HTTPException(status_code=401, detail="Authentication required")


async def _install_subject(
    tx: TransactionManager,
    request: Request,
    identity: TeamIdentity | None,
    team_id: str,
) -> InstallAdminSubject:
    team_id = validate_team_id(team_id)
    rule = install_subject_rule(team_id, identity)
    internal = None
    try:
        next(rule)
        # Verification raises its own 401 here, where it always did.
        internal = parse_internal_auth_context(request)
        rule.send(internal)
    except StopIteration as done:
        subject = done.value
    else:
        raise RuntimeError("install_subject_rule asks for one fact")
    if isinstance(subject, HTTPException):
        raise subject
    if internal is not None:
        # The subject is the verified internal caller. A forwarded actor that
        # names an agent must be an active member, read in the mutation's
        # transaction; one that names no agent is the proxy's team-level
        # principal, whose authority the policy decides.
        await resolve_internal_actor(tx, internal)
    return subject
