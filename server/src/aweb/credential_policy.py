"""The server consumes current, signed AWID policy; absence preserves defaults."""
import logging

from fastapi import HTTPException
from awid.team_ids import parse_team_id

logger = logging.getLogger(__name__)


async def team_credential_policy(request, team_id):
    try:
        domain, name = parse_team_id(team_id)
        client = request.app.state.awid_registry_client
        return await client.get_team_credential_policy(domain, name)
    except Exception as exc:
        logger.warning('Credential policy authority unavailable for team %s', team_id, exc_info=True)
        raise HTTPException(status_code=503, detail={'code': 'authority_unavailable', 'message': 'Team credential policy unavailable'}) from exc


async def issuer_certificate_revoked(request, team_id, certificate_id, member_did_key=None, *, known_revoked=False):
    from aweb.config import require_registered_certificates
    try:
        domain, name = parse_team_id(team_id)
        active = await request.app.state.awid_registry_client.resolve_active_certificate(domain, name, certificate_id, member_did_key=member_did_key)
        if active is not None and not isinstance(active, dict):
            raise ValueError('Malformed certificate authority result')
        return active is None
    except Exception as exc:
        if getattr(exc, 'status_code', None) == 404:
            if known_revoked:
                return True
            if require_registered_certificates():
                raise HTTPException(status_code=403, detail='grant issuing certificate not registered') from exc
            return False
        logger.warning('Issuing certificate authority unavailable', exc_info=True)
        raise HTTPException(status_code=503, detail={'code': 'authority_unavailable'}) from exc
