"""Real grant presence must stop when its issuing membership stops authorizing."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import StrEnum

import pytest
from aweb.certificate_registration import RegistrationMode
from aweb.grant_liveness import valid_grant_liveness_by_workspace
from aweb.identity_grant_status import GrantValidityState, grant_validity
from test_dashboard_privacy import TEAM
from test_dashboard_privacy import privacy_app as privacy_app
from test_identity_grants import _grant_headers, _session_keypair
from test_member_team_key import _certificate, _change_key, _connect, _new_member, _row
from test_messages_http import _signed_team_headers
from test_team_key_pinning import pinning as pinning

__all__ = ["pinning"]


class IssuerReacceptance(StrEnum):
    SUPERSEDED = "superseded"
    REACCEPTED = "reaccepted"
    REGISTRY_REVOKED = "registry-revoked"


@dataclass(frozen=True)
class PresenceGrant:
    signing_key: bytes
    did_key: str
    grant_id: str

    def headers(self, *, method: str, path: str, audience: str):
        return _grant_headers(
            signing_key=self.signing_key,
            did_key=self.did_key,
            grant_id=self.grant_id,
            method=method,
            path=path,
            aud=audience,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("issuer", list(IssuerReacceptance))
async def test_grant_liveness_and_request_auth_share_current_issuer_eligibility(
    pinning, issuer
):
    # docs/identity.md:807-811: delegation ends with its issuing certificate;
    # reconnecting the same identity does not resurrect an older delegation.
    env = pinning
    member = _new_member("presentworker")
    certificate = _certificate(env.team_sk, env.team_did, member, "presence-before")
    registry = env.app.state.awid_registry_client
    if issuer is IssuerReacceptance.REGISTRY_REVOKED:
        claims = json.loads(base64.b64decode(certificate))
        await registry.register_team_certificate(
            "example.test",
            TEAM.split(":", 1)[0],
            team_controller_signing_key=env.team_sk,
            certificate_id=claims["certificate_id"],
            member_did_key=member[1],
            member_did_aw=None,
            member_address=None,
            alias=member[2],
            identity_scope="local",
            certificate=certificate,
        )
    assert (await _connect(env, member, certificate)).status_code == 200
    signing_key, did_key = _session_keypair()
    body = json.dumps(
        {
            "grant_did_key": did_key,
            "scopes": ["presence.write", "mail.read"],
            "ttl_seconds": 600,
        }
    ).encode()
    minted = await env.client.post(
        "/v1/identity-grants",
        content=body,
        headers={
            **_signed_team_headers(member[0], member[1], TEAM, certificate, body),
            "Content-Type": "application/json",
        },
    )
    assert minted.status_code == 200, minted.text
    grant = PresenceGrant(signing_key, did_key, minted.json()["grant_id"])
    heartbeat = await env.client.post(
        "/v1/agents/heartbeat",
        headers=grant.headers(
            method="POST",
            path="/v1/agents/heartbeat",
            audience=env.app.state.public_origin,
        ),
    )
    assert heartbeat.status_code == 200, heartbeat.text
    member_row = await _row(env, member)
    workspace = str(
        await env.db.fetch_value(
            "SELECT workspace_id FROM {{tables.workspaces}} WHERE agent_id=$1 AND deleted_at IS NULL",
            member_row["agent_id"],
        )
    )
    before = await valid_grant_liveness_by_workspace(
        env.db, [workspace], registry_client=env.app.state.awid_registry_client
    )
    assert str(before[workspace]["grant_id"]) == grant.grant_id

    if issuer is IssuerReacceptance.REGISTRY_REVOKED:
        await registry.revoke_team_certificate(
            "example.test",
            TEAM.split(":", 1)[0],
            team_controller_signing_key=env.team_sk,
            certificate_id=claims["certificate_id"],
        )
    else:
        next_sk, next_did = await _change_key(env)
    if issuer is IssuerReacceptance.REACCEPTED:
        reconnected = await _connect(
            env,
            member,
            _certificate(next_sk, next_did, member, "presence-after"),
        )
        assert reconnected.status_code == 200, reconnected.text
    refused = await env.client.get(
        "/v1/messages/inbox",
        headers=grant.headers(
            method="GET",
            path="/v1/messages/inbox",
            audience=env.app.state.public_origin,
        ),
    )
    assert refused.status_code == 403, refused.text
    assert refused.json()["detail"].endswith(
        "Ask the issuer for a new grant, or enable renewal on launch and restart the seat if you use OATS."
    )
    # This is the same public native reader used by roster/status. Root Redis
    # presence cannot mask the grant-specific question in this assertion.
    assert workspace not in await valid_grant_liveness_by_workspace(
        env.db, [workspace], registry_client=env.app.state.awid_registry_client
    )


@pytest.mark.asyncio
async def test_historical_missing_certificate_cannot_keep_grant_valid():
    now = datetime.now(timezone.utc)
    observation = await grant_validity(
        row={
            "issued_at": now - timedelta(minutes=1),
            "expires_at": now + timedelta(minutes=1),
            "revoked_at": None,
            "subject_status": "active",
            "subject_deleted_at": None,
            "accepted_team_did_key": "same-current-key",
            "current_team_did_key": "same-current-key",
            "issued_by_certificate_id": "original-certificate",
            "certificate_id": None,
        },
        now=now,
        registry_client=None,
        registration_mode=RegistrationMode.REQUIRED,
    )
    assert observation.state is GrantValidityState.ISSUER_SUPERSEDED
