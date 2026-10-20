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
