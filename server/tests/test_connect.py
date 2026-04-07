"""Tests for POST /v1/connect — agent auto-provisioning via team certificate."""

from __future__ import annotations

import uuid

import pytest

from nacl.signing import SigningKey

from awid.did import did_from_public_key


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_keypair():
    sk = SigningKey.generate()
    pk = bytes(sk.verify_key)
    did_key = did_from_public_key(pk)
    return bytes(sk), pk, did_key


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestConnect:
    @pytest.mark.asyncio
    async def test_auto_provisions_team_and_agent(self, aweb_cloud_db):
        from aweb.routes.connect import connect_agent

        db = aweb_cloud_db.aweb_db

        team_sk, _, team_did_key = _make_keypair()
        agent_sk, _, agent_did_key = _make_keypair()

        cert_info = {
            "team_address": "acme.com/backend",
            "alias": "alice",
            "did_key": agent_did_key,
            "lifetime": "persistent",
            "certificate_id": "cert-001",
        }

        result = await connect_agent(
            db=db,
            cert_info=cert_info,
            team_did_key=team_did_key,
            hostname="Mac.local",
            workspace_path="/Users/alice/project",
            repo_origin="https://github.com/acme/backend.git",
            role="developer",
            human_name="Alice",
            agent_type="agent",
        )

        assert result["team_address"] == "acme.com/backend"
        assert result["alias"] == "alice"
        assert result["role"] == "developer"
        assert result["agent_id"] is not None
        assert result["workspace_id"] is not None

        # Verify team row was created
        team = await db.fetch_one(
            "SELECT * FROM {{tables.teams}} WHERE team_address = $1",
            "acme.com/backend",
        )
        assert team is not None
        assert team["team_did_key"] == team_did_key
        assert team["namespace"] == "acme.com"
        assert team["team_name"] == "backend"

        # Verify agent row was created
        agent = await db.fetch_one(
            "SELECT * FROM {{tables.agents}} WHERE agent_id = $1",
            uuid.UUID(result["agent_id"]),
        )
        assert agent is not None
        assert agent["alias"] == "alice"
        assert agent["did_key"] == agent_did_key
        assert agent["lifetime"] == "persistent"

    @pytest.mark.asyncio
    async def test_idempotent_reconnect(self, aweb_cloud_db):
        from aweb.routes.connect import connect_agent

        db = aweb_cloud_db.aweb_db

        team_sk, _, team_did_key = _make_keypair()
        _, _, agent_did_key = _make_keypair()

        cert_info = {
            "team_address": "acme.com/backend",
            "alias": "alice",
            "did_key": agent_did_key,
            "lifetime": "persistent",
            "certificate_id": "cert-001",
        }

        kwargs = dict(
            db=db,
            cert_info=cert_info,
            team_did_key=team_did_key,
            hostname="Mac.local",
            workspace_path="/Users/alice/project",
            repo_origin="",
            role="developer",
            human_name="",
            agent_type="agent",
        )

        result1 = await connect_agent(**kwargs)
        result2 = await connect_agent(**kwargs)

        assert result1["agent_id"] == result2["agent_id"]
        assert result1["team_address"] == result2["team_address"]
        assert result1["workspace_id"] == result2["workspace_id"]

    @pytest.mark.asyncio
    async def test_team_address_parsed_correctly(self, aweb_cloud_db):
        from aweb.routes.connect import connect_agent

        db = aweb_cloud_db.aweb_db

        team_sk, _, team_did_key = _make_keypair()
        _, _, agent_did_key = _make_keypair()

        cert_info = {
            "team_address": "example.org/frontend",
            "alias": "bob",
            "did_key": agent_did_key,
            "lifetime": "ephemeral",
            "certificate_id": "cert-002",
        }

        result = await connect_agent(
            db=db,
            cert_info=cert_info,
            team_did_key=team_did_key,
            hostname="",
            workspace_path="",
            repo_origin="",
            role="",
            human_name="",
            agent_type="agent",
        )

        team = await db.fetch_one(
            "SELECT * FROM {{tables.teams}} WHERE team_address = $1",
            "example.org/frontend",
        )
        assert team["namespace"] == "example.org"
        assert team["team_name"] == "frontend"

    @pytest.mark.asyncio
    async def test_workspace_created_with_repo(self, aweb_cloud_db):
        from aweb.routes.connect import connect_agent

        db = aweb_cloud_db.aweb_db

        _, _, team_did_key = _make_keypair()
        _, _, agent_did_key = _make_keypair()

        cert_info = {
            "team_address": "acme.com/backend",
            "alias": "alice",
            "did_key": agent_did_key,
            "lifetime": "persistent",
            "certificate_id": "cert-001",
        }

        result = await connect_agent(
            db=db,
            cert_info=cert_info,
            team_did_key=team_did_key,
            hostname="Mac.local",
            workspace_path="/Users/alice/project",
            repo_origin="https://github.com/acme/backend.git",
            role="developer",
            human_name="Alice",
            agent_type="agent",
        )

        workspace = await db.fetch_one(
            "SELECT * FROM {{tables.workspaces}} WHERE workspace_id = $1",
            uuid.UUID(result["workspace_id"]),
        )
        assert workspace is not None
        assert workspace["hostname"] == "Mac.local"
        assert workspace["workspace_path"] == "/Users/alice/project"
        assert workspace["alias"] == "alice"
