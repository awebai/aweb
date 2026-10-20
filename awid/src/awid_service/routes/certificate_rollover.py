"""Atomic controller-authorized same-member certificate replacement."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Request
from pgdbm import QueryError
from pydantic import BaseModel, ConfigDict

from awid.controller_request import ControllerAuthRoute
from awid.credential_policy import CredentialPolicyError, verify_credential_policy
from awid.ratelimit import rate_limit_dep
from awid.team_ids import build_team_id
from awid_service.deps import get_db
from awid_service.routes.teams import (
    CertificateRegisterRequest, _parse_certificate_blob, _require_member_address_owned_by_did_aw,
    _require_team_controller, _verify_certificate_blob,
)

router = APIRouter(prefix='/v1/namespaces/{domain}/teams', tags=['certificate-rollover'], route_class=ControllerAuthRoute)


async def certificate_policy_limit(tx, team, certificate: str | None):
    """Resolve the current signed policy while the caller holds the team lock."""
    row = await tx.fetch_one('SELECT record_json, signature FROM {{tables.team_credential_policies}} WHERE team_uuid=$1', team['team_uuid'])
    cert = _parse_certificate_blob(certificate) or {}
    if cert.get('version') == 2 and os.getenv('AWID_CERTIFICATE_V2_ISSUANCE_ENABLED', '').lower() != 'true':
        raise HTTPException(status_code=409, detail={'code': 'certificate_verifier_adoption_required'})
    if row is None:
        return None
    try:
        policy = verify_credential_policy(json.loads(row['record_json']), row['signature'], team_id=cert.get('team_id', ''), team_did_key=team['team_did_key'])
    except (CredentialPolicyError, ValueError) as exc:
        raise HTTPException(status_code=503, detail={'code': 'authority_unavailable'}) from exc
    if cert.get('version') != 2 and any(policy[key] is not None for key in ('member_certificate', 'ephemeral_certificate')):
        raise HTTPException(status_code=422, detail={'code': 'certificate_lifetime_exceeded', 'message': 'Team policy requires a v2 certificate'})
    return policy['ephemeral_certificate' if cert.get('validity_class') == 'ephemeral' else 'member_certificate']


class RolloverRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    replacement: CertificateRegisterRequest


@router.post('/{name}/certificates/{old_id}/rollover', dependencies=[Depends(rate_limit_dep('certificate_register', allow_trusted_service=True))])
async def rollover(request: Request, domain: str, name: str, old_id: str, body: RolloverRequest, db_infra=Depends(get_db)):
    if request.headers.get('X-AWEB-Signed-Payload') is None:
        raise HTTPException(status_code=401, detail='Covering AWID controller envelope required')
    new = body.replacement
    if new.certificate_id == old_id:
        raise HTTPException(status_code=422, detail='Replacement ID must be new')
    db = db_infra.get_manager('aweb')
    caller, team = await _require_team_controller(request, db, domain=domain, name=name, operation='rollover_certificate', certificate_id=old_id, replacement_certificate_id=new.certificate_id)
    try:
        async with db.transaction() as tx:
            locked = await tx.fetch_one('SELECT team_did_key FROM {{tables.teams}} WHERE team_uuid=$1 AND deleted_at IS NULL FOR UPDATE', team['team_uuid'])
            if not locked or locked['team_did_key'] != caller:
                raise HTTPException(status_code=409, detail='Team controller changed')
            old = await tx.fetch_one('SELECT * FROM {{tables.team_certificates}} WHERE team_uuid=$1 AND certificate_id=$2 FOR UPDATE', team['team_uuid'], old_id)
            if old is None:
                raise HTTPException(status_code=404, detail='Certificate not found')
            for field in ('member_did_key', 'member_did_aw', 'member_address', 'alias', 'identity_scope'):
                if (old[field] or '') != (getattr(new, field) or ''):
                    raise HTTPException(status_code=409, detail='Rollover cannot change membership')
            existing = await tx.fetch_one('SELECT certificate,revoked_at FROM {{tables.team_certificates}} WHERE team_uuid=$1 AND certificate_id=$2', team['team_uuid'], new.certificate_id)
            if old['revoked_at'] is not None:
                if old['replaced_by_certificate_id'] == new.certificate_id and existing and existing['revoked_at'] is None and existing['certificate'] == new.certificate:
                    return {'replaced': True, 'old_certificate_id': old_id, 'certificate_id': new.certificate_id}
                raise HTTPException(status_code=409, detail='Certificate revoked or already replaced')
            if existing is not None:
                raise HTTPException(status_code=409, detail='Replacement ID already exists')
            await _require_member_address_owned_by_did_aw(tx, member_address=new.member_address, member_did_aw=new.member_did_aw)
            maximum = await certificate_policy_limit(tx, team, new.certificate)
            _verify_certificate_blob(new.certificate, team_id=build_team_id(domain, name), team_did_key=caller, body=new, max_lifetime_seconds=maximum)
            # Uncommitted revocation releases the partial alias index. Any
            # insertion failure rolls this back; readers see only the commit.
            await tx.execute('UPDATE {{tables.team_certificates}} SET revoked_at=$3 WHERE team_uuid=$1 AND certificate_id=$2', team['team_uuid'], old_id, datetime.now(timezone.utc))
            await tx.execute(
                'INSERT INTO {{tables.team_certificates}} (team_uuid,certificate_id,member_did_key,member_did_aw,member_address,alias,identity_scope,certificate) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
                team['team_uuid'], new.certificate_id, new.member_did_key, new.member_did_aw, new.member_address, new.alias, new.identity_scope, new.certificate,
            )
            await tx.execute('UPDATE {{tables.team_certificates}} SET replaced_by_certificate_id=$3 WHERE team_uuid=$1 AND certificate_id=$2', team['team_uuid'], old_id, new.certificate_id)
    except QueryError as exc:
        if isinstance(exc.__cause__, asyncpg.UniqueViolationError):
            raise HTTPException(status_code=409, detail='Certificate rollover collision') from exc
        raise
    return {'replaced': True, 'old_certificate_id': old_id, 'certificate_id': new.certificate_id}
