import json

import pytest

from aweb.coordination.routes.team_roles import (
    SelectedRoleInfo,
    _resolve_selected_role_name,
)
from aweb.mcp.auth import AuthContext
from aweb.mcp.tools import _common as common_tools
from aweb.mcp.tools import team_instructions as team_instructions_tools
from aweb.mcp.tools import team_roles as team_roles_tools


def test_selected_role_info_emits_role_name_and_role():
    selected = SelectedRoleInfo(
        role_name="developer",
        title="Developer",
        playbook_md="Ship code",
    )
    data = selected.model_dump()
    assert data["role_name"] == "developer"
    assert data["role"] == "developer"


def test_resolve_selected_role_name_accepts_legacy_or_canonical_query():
    assert _resolve_selected_role_name(role="Developer", role_name=None) == "developer"
    assert _resolve_selected_role_name(role=None, role_name="Developer") == "developer"


def test_resolve_selected_role_name_rejects_conflicts():
    with pytest.raises(ValueError, match="role and role_name must match"):
        _resolve_selected_role_name(role="developer", role_name="reviewer")


class _FakeAwebDB:
    async def fetch_one(self, _query: str, *_args):
        return {"role": "developer"}


class _FakeDBInfra:
    def get_manager(self, name: str):
        assert name == "aweb"
        return _FakeAwebDB()


class _FakeTeamRolesVersion:
    id = "roles-123"
    team_id = "backend:acme.com"
    version = 4
    created_at = type(
        "FakeCreatedAt",
        (),
        {"isoformat": lambda self: "2026-01-01T00:00:00Z"},
    )()
    updated_at = None
    bundle = type(
        "FakeBundle",
        (),
        {
            "roles": {
                "developer": {
                    "title": "Developer",
                    "playbook_md": "Ship code",
                }
            },
            "adapters": {},
        },
    )()


class _FakeInstructionsDB:
    async def fetch_one(self, _query: str, *_args):
        return {
            "id": "instr-123",
            "team_id": "backend:acme.com",
            "version": 2,
            "document_json": {"body_md": "Use aw", "format": "markdown"},
            "created_at": type(
                "FakeCreatedAt",
                (),
                {"isoformat": lambda self: "2026-02-01T00:00:00Z"},
            )(),
            "updated_at": None,
        }


class _FakeInstructionsDBInfra:
    def get_manager(self, name: str):
        assert name == "aweb"
        return _FakeInstructionsDB()


@pytest.mark.asyncio
async def test_mcp_roles_show_emits_team_roles_ids(monkeypatch):
    async def fake_get_active_team_roles(*_args, **_kwargs):
        return _FakeTeamRolesVersion()

    monkeypatch.setattr(
        common_tools,
        "get_auth",
        lambda: AuthContext(
            certificate_id="cert-1",
            team_id="backend:acme.com",
            agent_id="agent-1",
            alias="alice",
            did_key="did:key:z6Mkexample",
        ),
    )
    monkeypatch.setattr(
        team_roles_tools,
        "get_active_team_roles",
        fake_get_active_team_roles,
    )

    payload = await team_roles_tools.roles_show(_FakeDBInfra())
    data = json.loads(payload)

    assert data["team_roles_id"] == "roles-123"
    assert data["active_team_roles_id"] == "roles-123"
    assert data["updated_at"] == "2026-01-01T00:00:00Z"
    assert data["selected_role"]["role_name"] == "developer"


@pytest.mark.asyncio
async def test_mcp_instructions_show_falls_back_to_created_at_when_updated_at_missing(
    monkeypatch,
):
    monkeypatch.setattr(
        common_tools,
        "get_auth",
        lambda: AuthContext(
            certificate_id="cert-1",
            team_id="backend:acme.com",
            agent_id="agent-1",
            alias="alice",
            did_key="did:key:z6Mkexample",
        ),
    )

    payload = await team_instructions_tools.instructions_show(
        _FakeInstructionsDBInfra(),
        team_instructions_id="instr-123",
    )
    data = json.loads(payload)

    assert data["team_instructions_id"] == "instr-123"
    assert data["updated_at"] == "2026-02-01T00:00:00Z"
