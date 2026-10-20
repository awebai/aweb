"""Controller-published credential policy and anonymous authenticated-artifact reads."""
from __future__ import annotations

import json
import os
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request

from awid.controller_request import ControllerAuthRoute
from awid.credential_policy import CredentialPolicyError, verify_credential_policy
from awid.ratelimit import rate_limit_dep
from awid.signing import canonical_json_bytes
from awid.team_ids import build_team_id
from awid_service.attestation_rotation import SignedRecord
from awid_service.deps import get_db
from awid_service.routes.teams import _require_team_controller

router = APIRouter(prefix='/v1/namespaces/{domain}/teams', tags=['credential-policy'], route_class=ControllerAuthRoute)


@router.get('/{name}/credential-lifetimes', dependencies=[Depends(rate_limit_dep('team_get', allow_trusted_service=True))])
async def get_policy(domain: str, name: str, db_infra=Depends(get_db)):
    row = await db_infra.get_manager('aweb').fetch_one(
        'SELECT t.team_did_key, p.record_json, p.signature FROM {{tables.teams}} t '
        'LEFT JOIN {{tables.team_credential_policies}} p ON p.team_uuid=t.team_uuid '
        'WHERE t.domain=$1 AND t.name=$2 AND t.deleted_at IS NULL', domain, name,
    )
    if row is None:
        raise HTTPException(status_code=404, detail='Team not found')
    return {'team_id': build_team_id(domain, name), 'team_did_key': row['team_did_key'],
            'record': json.loads(row['record_json']) if row['record_json'] else None, 'signature': row['signature']}


@router.post('/{name}/credential-lifetimes', dependencies=[Depends(rate_limit_dep('team_update', allow_trusted_service=True))])
async def set_policy(request: Request, domain: str, name: str, body: SignedRecord, db_infra=Depends(get_db)):
    if request.headers.get('X-AWEB-Signed-Payload') is None:
        raise HTTPException(status_code=401, detail='Covering AWID controller envelope required')
    db = db_infra.get_manager('aweb')
    caller, team = await _require_team_controller(request, db, domain=domain, name=name, operation='set_credential_lifetimes')
    record = body.record
    async with db.transaction() as tx:
        locked = await tx.fetch_one('SELECT team_did_key FROM {{tables.teams}} WHERE team_uuid=$1 AND deleted_at IS NULL FOR UPDATE', team['team_uuid'])
        if not locked or locked['team_did_key'] != caller:
            raise HTTPException(status_code=409, detail='Team controller changed; re-sign and retry')
        try:
            verify_credential_policy(record, body.signature, team_id=build_team_id(domain, name), team_did_key=caller)
        except CredentialPolicyError as exc:
            raise HTTPException(status_code=422, detail={'code': 'policy_invalid', 'message': str(exc)}) from exc
        # Issuance must remain disabled until operators measure verifier adoption.
        if any(record[field] is not None for field in ('member_certificate', 'ephemeral_certificate')) and os.getenv('AWID_CERTIFICATE_V2_ISSUANCE_ENABLED', '').lower() != 'true':
            raise HTTPException(status_code=409, detail={'code': 'certificate_verifier_adoption_required'})
        old = await tx.fetch_one('SELECT record_json, signature, revision FROM {{tables.team_credential_policies}} WHERE team_uuid=$1 FOR UPDATE', team['team_uuid'])
        canonical = canonical_json_bytes(record).decode()
        if old and old['record_json'] == canonical and old['signature'] == body.signature:
            return {'record': record, 'signature': body.signature}
        if record['revision'] != (old['revision'] + 1 if old else 1):
            raise HTTPException(status_code=409, detail={'code': 'policy_revision_conflict'})
        await tx.execute(
            'INSERT INTO {{tables.team_credential_policies}} (team_uuid,record_json,signature,team_did_key,revision,issued_at) '
            'VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT(team_uuid) DO UPDATE SET record_json=EXCLUDED.record_json, '
            'signature=EXCLUDED.signature,team_did_key=EXCLUDED.team_did_key,revision=EXCLUDED.revision,issued_at=EXCLUDED.issued_at,updated_at=NOW()',
            team['team_uuid'], canonical, body.signature, caller, record['revision'], datetime.fromisoformat(record['issued_at'].replace('Z', '+00:00')),
        )
        await tx.execute(
            'INSERT INTO {{tables.team_credential_policy_audit}} (team_uuid,actor_did_key,old_record_json,new_record_json) VALUES ($1,$2,$3,$4)',
            team['team_uuid'], caller, old['record_json'] if old else None, canonical,
        )
    return {'record': record, 'signature': body.signature}
