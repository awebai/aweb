"""Tests for the team certificate FastAPI auth dependency."""

from __future__ import annotations

import base64
import json
import uuid
from datetime import datetime, timezone

import pytest

from nacl.signing import SigningKey

from awid.did import did_from_public_key
from awid.signing import canonical_json_bytes, sign_message


def _make_keypair():
    sk = SigningKey.generate()
    pk = bytes(sk.verify_key)
    did_key = did_from_public_key(pk)
    return bytes(sk), pk, did_key


def _make_certificate(team_sk, team_did_key, member_did_key, **kwargs):
    cert = {
        "version": 1,
        "certificate_id": kwargs.get("certificate_id", "cert-001"),
        "team": kwargs.get("team_address", "acme.com/backend"),
        "team_did_key": team_did_key,
        "member_did_key": member_did_key,
        "member_did_aw": "",
        "member_address": "",
        "alias": kwargs.get("alias", "alice"),
        "lifetime": kwargs.get("lifetime", "persistent"),
        "issued_at": datetime.now(timezone.utc).isoformat(),
    }
    payload = canonical_json_bytes(cert)
    sig = sign_message(team_sk, payload)
    cert["signature"] = sig
    return cert


def _encode_certificate(cert):
    return base64.b64encode(json.dumps(cert).encode()).decode()


class TestTeamIdentity:
    def test_dataclass_fields(self):
        from aweb.team_auth_deps import TeamIdentity

        identity = TeamIdentity(
            team_address="acme.com/backend",
            alias="alice",
            did_key="did:key:z6Mktest",
            agent_id="agent-uuid",
            lifetime="persistent",
            certificate_id="cert-001",
        )

        assert identity.team_address == "acme.com/backend"
        assert identity.alias == "alice"
        assert identity.did_key == "did:key:z6Mktest"
        assert identity.agent_id == "agent-uuid"
        assert identity.lifetime == "persistent"
        assert identity.certificate_id == "cert-001"

    def test_frozen(self):
        from aweb.team_auth_deps import TeamIdentity

        identity = TeamIdentity(
            team_address="acme.com/backend",
            alias="alice",
            did_key="did:key:z6Mktest",
            agent_id="agent-uuid",
            lifetime="persistent",
            certificate_id="cert-001",
        )

        with pytest.raises(AttributeError):
            identity.team_address = "other"


class TestResolveTeamIdentity:
    @pytest.mark.asyncio
    async def test_resolves_from_cert_info_and_db(self, aweb_cloud_db):
        from aweb.team_auth_deps import resolve_team_identity

        db = aweb_cloud_db.aweb_db

        team_sk, _, team_did_key = _make_keypair()
        _, _, agent_did_key = _make_keypair()

        # Provision team + agent via connect
        from aweb.routes.connect import connect_agent

        result = await connect_agent(
            db=db,
            cert_info={
                "team_address": "acme.com/backend",
                "alias": "alice",
                "did_key": agent_did_key,
                "lifetime": "persistent",
                "certificate_id": "cert-001",
            },
            team_did_key=team_did_key,
            hostname="Mac.local",
            workspace_path="/project",
            repo_origin="",
            role="developer",
            human_name="",
            agent_type="agent",
        )

        cert_info = {
            "team_address": "acme.com/backend",
            "alias": "alice",
            "did_key": agent_did_key,
            "lifetime": "persistent",
            "certificate_id": "cert-001",
        }

        identity = await resolve_team_identity(db, cert_info)

        assert identity.team_address == "acme.com/backend"
        assert identity.alias == "alice"
        assert identity.did_key == agent_did_key
        assert identity.agent_id == result["agent_id"]
        assert identity.lifetime == "persistent"
        assert identity.certificate_id == "cert-001"

    @pytest.mark.asyncio
    async def test_unknown_agent_raises(self, aweb_cloud_db):
        from aweb.team_auth_deps import resolve_team_identity

        db = aweb_cloud_db.aweb_db
        _, _, unknown_did_key = _make_keypair()

        cert_info = {
            "team_address": "acme.com/backend",
            "alias": "unknown",
            "did_key": unknown_did_key,
            "lifetime": "ephemeral",
            "certificate_id": "cert-002",
        }

        with pytest.raises(ValueError, match="not connected"):
            await resolve_team_identity(db, cert_info)
