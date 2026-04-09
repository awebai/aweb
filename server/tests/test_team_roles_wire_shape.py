import json

import pytest

from aweb.coordination.routes.team_roles import (
    ActiveTeamRolesResponse,
    CreateTeamRolesRequest,
    DeactivateTeamRolesResponse,
    TeamRolesHistoryItem,
    TeamRolesHistoryResponse,
    SelectedRoleInfo,
    _resolve_selected_role_name,
)
from aweb.coordination.routes.team_instructions import (
    ActiveTeamInstructionsResponse,
    CreateTeamInstructionsRequest,
    TeamInstructionsHistoryItem,
    TeamInstructionsHistoryResponse,
)
from aweb.mcp.auth import AuthContext
from aweb.mcp.tools import team_roles as team_roles_tools


def test_create_team_roles_request_uses_base_team_roles_id():
    req = CreateTeamRolesRequest(
        bundle={"roles": {}, "adapters": {}},
        base_team_roles_id="550e8400-e29b-41d4-a716-446655440000",
    )
    assert req.base_team_roles_id == "550e8400-e29b-41d4-a716-446655440000"


def test_selected_role_info_emits_role_name_and_role():
    selected = SelectedRoleInfo(
        role_name="developer",
        title="Developer",
        playbook_md="Ship code",
    )
    data = selected.model_dump()
    assert data["role_name"] == "developer"
    assert data["role"] == "developer"


def test_active_team_roles_response_uses_team_roles_ids():
    response = ActiveTeamRolesResponse(
        team_roles_id="550e8400-e29b-41d4-a716-446655440000",
        active_team_roles_id="550e8400-e29b-41d4-a716-446655440000",
        team_address="acme.com/backend",
        version=3,
        updated_at="2026-01-01T00:00:00Z",
        roles={"developer": {"title": "Developer", "playbook_md": "Ship code"}},
        selected_role=SelectedRoleInfo(
            role_name="developer",
            title="Developer",
            playbook_md="Ship code",
        ),
        adapters={},
    )
    data = response.model_dump()
    assert data["team_roles_id"] == "550e8400-e29b-41d4-a716-446655440000"
    assert data["active_team_roles_id"] == "550e8400-e29b-41d4-a716-446655440000"
    assert data["selected_role"]["role_name"] == "developer"
    assert data["selected_role"]["role"] == "developer"


def test_team_roles_history_response_emits_team_roles_versions():
    item = TeamRolesHistoryItem(
        team_roles_id="550e8400-e29b-41d4-a716-446655440000",
        version=2,
        created_at="2026-01-01T00:00:00Z",
        created_by_alias="alice",
        is_active=True,
    )
    response = TeamRolesHistoryResponse(team_roles_versions=[item])
    data = response.model_dump()
    assert data["team_roles_versions"][0]["team_roles_id"] == item.team_roles_id


def test_deactivate_team_roles_response_emits_active_team_roles_id():
    response = DeactivateTeamRolesResponse(
        deactivated=True,
        active_team_roles_id="550e8400-e29b-41d4-a716-446655440000",
        version=3,
    )
    data = response.model_dump()
    assert data["deactivated"] is True
    assert data["active_team_roles_id"] == "550e8400-e29b-41d4-a716-446655440000"
    assert data["version"] == 3


def test_resolve_selected_role_name_accepts_legacy_or_canonical_query():
    assert _resolve_selected_role_name(role="Developer", role_name=None) == "developer"
    assert _resolve_selected_role_name(role=None, role_name="Developer") == "developer"


def test_resolve_selected_role_name_rejects_conflicts():
    with pytest.raises(ValueError, match="role and role_name must match"):
        _resolve_selected_role_name(role="developer", role_name="reviewer")


def test_create_team_instructions_request_uses_base_team_instructions_id():
    req = CreateTeamInstructionsRequest(
        document={"body_md": "Use aw", "format": "markdown"},
        base_team_instructions_id="770e8400-e29b-41d4-a716-446655440000",
    )
    assert req.base_team_instructions_id == "770e8400-e29b-41d4-a716-446655440000"


def test_active_team_instructions_response_uses_team_instruction_ids():
    response = ActiveTeamInstructionsResponse(
        team_instructions_id="770e8400-e29b-41d4-a716-446655440000",
        active_team_instructions_id="770e8400-e29b-41d4-a716-446655440000",
        team_address="acme.com/backend",
        version=2,
        updated_at="2026-01-01T00:00:00Z",
        document={"body_md": "Use aw", "format": "markdown"},
    )
    data = response.model_dump()
    assert data["team_instructions_id"] == "770e8400-e29b-41d4-a716-446655440000"
    assert (
        data["active_team_instructions_id"] == "770e8400-e29b-41d4-a716-446655440000"
    )
    assert data["document"]["format"] == "markdown"


def test_team_instructions_history_response_emits_instruction_versions():
    item = TeamInstructionsHistoryItem(
        team_instructions_id="770e8400-e29b-41d4-a716-446655440000",
        version=2,
        created_at="2026-01-01T00:00:00Z",
        created_by_alias="alice",
        is_active=True,
    )
    response = TeamInstructionsHistoryResponse(team_instructions_versions=[item])
    data = response.model_dump()
    assert (
        data["team_instructions_versions"][0]["team_instructions_id"]
        == item.team_instructions_id
    )


class _FakeAwebDB:
    async def fetch_one(self, _query: str, *_args):
        return {"role": "developer"}


class _FakeDBInfra:
    def get_manager(self, name: str):
        assert name == "aweb"
        return _FakeAwebDB()


class _FakeTeamRolesVersion:
    id = "roles-123"
    team_address = "acme.com/backend"
    version = 4
    updated_at = type("FakeTimestamp", (), {"isoformat": lambda self: "2026-01-01T00:00:00Z"})()
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


@pytest.mark.asyncio
async def test_mcp_roles_show_emits_team_roles_ids(monkeypatch):
    async def fake_get_active_team_roles(*_args, **_kwargs):
        return _FakeTeamRolesVersion()

    monkeypatch.setattr(
        team_roles_tools,
        "get_auth",
        lambda: AuthContext(
            team_address="acme.com/backend",
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
    assert data["selected_role"]["role_name"] == "developer"
