import pytest

from aweb.coordination.routes.project_roles import (
    ActiveProjectRolesResponse,
    CreateProjectRolesRequest,
    DeactivateProjectRolesResponse,
    ProjectRolesHistoryItem,
    ProjectRolesHistoryResponse,
    SelectedRoleInfo,
    _resolve_selected_role_name,
)
from aweb.coordination.routes.project_instructions import (
    ActiveProjectInstructionsResponse,
    CreateProjectInstructionsRequest,
    ProjectInstructionsHistoryItem,
    ProjectInstructionsHistoryResponse,
)


def test_create_project_roles_request_uses_base_project_roles_id():
    req = CreateProjectRolesRequest(
        bundle={"roles": {}, "adapters": {}},
        base_project_roles_id="550e8400-e29b-41d4-a716-446655440000",
    )
    assert req.base_project_roles_id == "550e8400-e29b-41d4-a716-446655440000"


def test_selected_role_info_emits_role_name_and_role():
    selected = SelectedRoleInfo(
        role_name="developer",
        title="Developer",
        playbook_md="Ship code",
    )
    data = selected.model_dump()
    assert data["role_name"] == "developer"
    assert data["role"] == "developer"


def test_active_project_roles_response_uses_project_roles_ids():
    response = ActiveProjectRolesResponse(
        project_roles_id="550e8400-e29b-41d4-a716-446655440000",
        active_project_roles_id="550e8400-e29b-41d4-a716-446655440000",
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
    assert data["project_roles_id"] == "550e8400-e29b-41d4-a716-446655440000"
    assert data["active_project_roles_id"] == "550e8400-e29b-41d4-a716-446655440000"
    assert data["selected_role"]["role_name"] == "developer"
    assert data["selected_role"]["role"] == "developer"


def test_project_roles_history_response_emits_project_roles_versions():
    item = ProjectRolesHistoryItem(
        project_roles_id="550e8400-e29b-41d4-a716-446655440000",
        version=2,
        created_at="2026-01-01T00:00:00Z",
        created_by_alias="alice",
        is_active=True,
    )
    response = ProjectRolesHistoryResponse(project_roles_versions=[item])
    data = response.model_dump()
    assert data["project_roles_versions"][0]["project_roles_id"] == item.project_roles_id


def test_deactivate_project_roles_response_emits_active_project_roles_id():
    response = DeactivateProjectRolesResponse(
        deactivated=True,
        active_project_roles_id="550e8400-e29b-41d4-a716-446655440000",
        version=3,
    )
    data = response.model_dump()
    assert data["deactivated"] is True
    assert data["active_project_roles_id"] == "550e8400-e29b-41d4-a716-446655440000"
    assert data["version"] == 3


def test_resolve_selected_role_name_accepts_legacy_or_canonical_query():
    assert _resolve_selected_role_name(role="Developer", role_name=None) == "developer"
    assert _resolve_selected_role_name(role=None, role_name="Developer") == "developer"


def test_resolve_selected_role_name_rejects_conflicts():
    with pytest.raises(ValueError, match="role and role_name must match"):
        _resolve_selected_role_name(role="developer", role_name="reviewer")


def test_create_project_instructions_request_uses_base_project_instructions_id():
    req = CreateProjectInstructionsRequest(
        document={"body_md": "Use aw", "format": "markdown"},
        base_project_instructions_id="770e8400-e29b-41d4-a716-446655440000",
    )
    assert req.base_project_instructions_id == "770e8400-e29b-41d4-a716-446655440000"


def test_active_project_instructions_response_uses_project_instruction_ids():
    response = ActiveProjectInstructionsResponse(
        project_instructions_id="770e8400-e29b-41d4-a716-446655440000",
        active_project_instructions_id="770e8400-e29b-41d4-a716-446655440000",
        team_address="acme.com/backend",
        version=2,
        updated_at="2026-01-01T00:00:00Z",
        document={"body_md": "Use aw", "format": "markdown"},
    )
    data = response.model_dump()
    assert data["project_instructions_id"] == "770e8400-e29b-41d4-a716-446655440000"
    assert (
        data["active_project_instructions_id"] == "770e8400-e29b-41d4-a716-446655440000"
    )
    assert data["document"]["format"] == "markdown"


def test_project_instructions_history_response_emits_instruction_versions():
    item = ProjectInstructionsHistoryItem(
        project_instructions_id="770e8400-e29b-41d4-a716-446655440000",
        version=2,
        created_at="2026-01-01T00:00:00Z",
        created_by_alias="alice",
        is_active=True,
    )
    response = ProjectInstructionsHistoryResponse(project_instructions_versions=[item])
    data = response.model_dump()
    assert (
        data["project_instructions_versions"][0]["project_instructions_id"]
        == item.project_instructions_id
    )
