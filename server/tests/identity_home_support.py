"""Real aw identity homes for fixture actors, for CLI tests against the real serving stacks."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import json

from team_request_support import _team_request
from test_dashboard_privacy import TEAM
from test_identity_grants import _session_keypair


def _pem(path, kind, raw):
    path.write_text(
        f"-----BEGIN {kind}-----\n{base64.b64encode(raw).decode()}\n-----END {kind}-----\n"
    )
    path.chmod(0o600)


def _team_home(env, tmp_path, actor):
    identity = env.actors[actor]
    home = tmp_path / ".aw"
    (home / "team-certs").mkdir(parents=True, mode=0o700)
    cert_path = "team-certs/" + TEAM.replace("__", "____").replace(":", "__") + ".pem"
    (home / cert_path).write_text(base64.b64decode(identity.certificate).decode())
    (home / cert_path).chmod(0o600)
    membership = {"team_id": TEAM, "alias": actor, "cert_path": cert_path}
    (home / "teams.yaml").write_text(
        json.dumps({"active_team": TEAM, "memberships": [membership]})
    )
    (home / "workspace.yaml").write_text(
        json.dumps(
            {
                "aweb_url": str(env.client.base_url).rstrip("/"),
                "memberships": [
                    {**membership, "workspace_id": str(identity.workspace)}
                ],
            }
        )
    )
    _pem(home / "signing.key", "ED25519 PRIVATE KEY", identity.sk)
    return home


async def _grant_home(env, tmp_path, actor, scopes):
    env.app.state.public_origin = str(env.client.base_url).rstrip("/")
    session_key, session_did = _session_keypair()
    minted = await _team_request(
        env,
        actor,
        "POST",
        "/v1/identity-grants",
        {"grant_did_key": session_did, "scopes": scopes, "ttl_seconds": 600},
    )
    assert minted.status_code == 200, minted.text
    home = tmp_path / "grant.aw"
    home.mkdir(mode=0o700)
    (home / "grant.yaml").write_text(
        json.dumps(
            {
                "version": 1,
                "grant_id": minted.json()["grant_id"],
                "team_id": TEAM,
                "subject": {"did_key": env.actors[actor].did, "alias": actor},
                "scopes": scopes,
                "expires_at": (
                    datetime.now(timezone.utc) + timedelta(minutes=10)
                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "aweb_url": str(env.client.base_url).rstrip("/"),
            }
        )
    )
    _pem(home / "grant-signing.key", "ED25519 PRIVATE KEY", session_key)
    return home, session_did
