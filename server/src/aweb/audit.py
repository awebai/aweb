"""Content-free operator audit shared by OSS and embedding hosts.

Only trusted authentication code constructs AuditActor. Headers are never an
actor source here. The caller owns the aweb-schema transaction and its outcome.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal
from uuid import UUID, uuid4

from fastapi import HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute

from aweb.deps import get_db

PrincipalType = Literal['u', 'k', 'c', 'm', 'p']
AuthMode = Literal['team_auth_v1', 'team_auth_v2', 'session', 'api_key', 'identity_grant', 'internal']
AuditOutcome = Literal['success', 'denied']
_ACTIONS = {
    'create_team_roles_endpoint': 'roles.create',
    'activate_team_roles_endpoint': 'roles.activate',
    'reset_team_roles_to_default_endpoint': 'roles.reset',
    'deactivate_team_roles_endpoint': 'roles.deactivate',
    'delete_repo': 'repos.delete',
    'install_app_route': 'apps.install',
}


@dataclass(frozen=True, kw_only=True)
class AuditActor:
    team_id: str
    principal_type: PrincipalType
    auth_mode: AuthMode
    did_key: str | None = None
    did_aw: str | None = None
    user_id: str | None = None
    grant_id: str | None = None

    def __post_init__(self) -> None:
        if not self.team_id or not (self.did_key or self.user_id):
            raise ValueError('audit requires a team and an attributable actor')
        if self.principal_type not in ('u', 'k', 'c', 'm', 'p'):
            raise ValueError('invalid audit principal type')
        if self.auth_mode not in ('team_auth_v1', 'team_auth_v2', 'session', 'api_key', 'identity_grant', 'internal'):
            raise ValueError('invalid audit auth mode')
        if self.auth_mode == 'identity_grant':
            if not self.did_key or not self.grant_id:
                raise ValueError('grant audit requires subject and grant id')
            UUID(self.grant_id)
        elif self.grant_id is not None:
            raise ValueError('grant id requires identity_grant auth')


async def record_coordination_audit(
    tx, *, actor: AuditActor, action: str, target: str,
    outcome: AuditOutcome, request_id: str,
) -> None:
    """Insert only; never commit, suppress failures or accept request content."""
    if not isinstance(actor, AuditActor):
        raise ValueError('audit actor must come from verified context')
    if action not in _ACTIONS.values() or outcome not in ('success', 'denied'):
        raise ValueError('invalid operator audit event')
    await tx.execute(
        """INSERT INTO {{tables.audit_log}}
        (team_id, event_type, resource, actor_did_key, actor_did_aw, actor_user_id,
         principal_type, auth_mode, outcome, request_id, actor_grant_id, created_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,clock_timestamp())""",
        actor.team_id, action, target, actor.did_key, actor.did_aw, actor.user_id,
        actor.principal_type, actor.auth_mode, outcome, UUID(request_id),
        UUID(actor.grant_id) if actor.grant_id else None,
    )


def set_verified_audit_actor(request: Request, actor: AuditActor) -> None:
    """Preserve an embedding host's verified principal (notably API-key k)."""
    existing = getattr(request.state, 'operator_audit_actor', None)
    if existing is not None:
        if not isinstance(existing, AuditActor) or existing.team_id != actor.team_id:
            raise ValueError('inconsistent verified audit context')
        return
    request.state.operator_audit_actor = actor


def _target(request: Request, action: str, actor: AuditActor) -> str:
    if action == 'roles.activate':
        value = request.path_params['team_roles_id']
        try:
            return f'roles:{UUID(str(value))}'
        except ValueError:
            return 'roles:invalid'
    if action == 'repos.delete':
        value = request.path_params['repo_id']
        try:
            return f'repo:{UUID(str(value))}'
        except ValueError:
            return 'repo:invalid'
    if action == 'apps.install':
        return getattr(request.state, 'operator_audit_target', None) or 'app:invalid'
    return f'roles:{actor.team_id}'


async def audit_success(tx, request: Request, team_id: str) -> None:
    actor = getattr(request.state, 'operator_audit_actor', None)
    if not isinstance(actor, AuditActor) or actor.team_id != team_id:
        raise ValueError('missing verified operator audit context')
    action = _ACTIONS[request.scope['route'].name]
    await record_coordination_audit(
        tx, actor=actor, action=action, target=_target(request, action, actor),
        outcome='success', request_id=request.state.operator_audit_request_id,
    )


class OperatorAuditRoute(APIRoute):
    """Record authenticated refusals after the mutation transaction rolls back.

    Success is recorded explicitly inside each route's write transaction. Only
    the named operator routes are covered; ordinary reads are unchanged.
    """
    def get_route_handler(self):
        handler = super().get_route_handler()
        action = _ACTIONS.get(self.name)
        if action is None:
            return handler

        async def audited(request: Request):
            if getattr(request.state, 'operator_audit_request_id', None) is None:
                request.state.operator_audit_request_id = str(uuid4())
            try:
                return await handler(request)
            except (HTTPException, RequestValidationError) as exc:
                status = exc.status_code if isinstance(exc, HTTPException) else 422
                actor = getattr(request.state, 'operator_audit_actor', None)
                if 400 <= status < 500 and isinstance(actor, AuditActor):
                    db = get_db(request)
                    manager = db.get_manager('aweb') if hasattr(db, 'get_manager') else db
                    async with manager.transaction() as tx:
                        await record_coordination_audit(
                            tx, actor=actor, action=action, target=_target(request, action, actor),
                            outcome='denied', request_id=request.state.operator_audit_request_id,
                        )
                raise
        return audited


def is_operator_audit_request(request: Request) -> bool:
    return getattr(request.scope.get('route'), 'name', None) in _ACTIONS
