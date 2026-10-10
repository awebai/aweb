from datetime import datetime, timedelta, timezone

import pytest
from aweb.routes.identity_grants import GrantMintRequest, _status

@pytest.mark.parametrize("ttl", ["never", None])
def test_never_grant_request(ttl):
    req = GrantMintRequest(grant_did_key="did:key:zSynthetic", scopes=["mail.read"], ttl_seconds=ttl)
    assert req.ttl_seconds == ttl

def test_omitted_ttl_is_never():
    assert GrantMintRequest(grant_did_key="did:key:zSynthetic", scopes=["mail.read"]).ttl_seconds is None

def test_never_status_survives_horizon_but_revocation_wins():
    issued = datetime(2000, 1, 1, tzinfo=timezone.utc)
    row = dict(issued_at=issued, expires_at=issued.replace(year=2100), revoked_at=None)
    now = issued.replace(year=2200)
    assert _status(row, now) == "active"
    row["revoked_at"] = now
    assert _status(row, now) == "revoked"
    row.update(expires_at=issued+timedelta(hours=1), revoked_at=None)
    assert _status(row, now) == "expired"
