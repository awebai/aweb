import pytest
from pydantic import ValidationError

from aweb.coordination.routes.policies import (
    ActiveProjectRolesResponse,
    CreateProjectRolesRequest,
    ProjectRolesHistoryItem,
    ProjectRolesHistoryResponse,
    SelectedRoleInfo,
    _resolve_selected_role_name,
)


def test_create_project_roles_request_accepts_legacy_base_policy_id():
    req = CreateProjectRolesRequest(
        bundle={"invariants": [], "roles": {}, "adapters": {}},
        base_policy_id="550e8400-e29b-41d4-a716-446655440000",
    )
    assert req.base_project_roles_id == "550e8400-e29b-41d4-a716-446655440000"
    assert req.base_policy_id == "550e8400-e29b-41d4-a716-446655440000"


def test_create_project_roles_request_rejects_conflicting_base_ids():
    with pytest.raises(ValidationError, match="base_project_roles_id and base_policy_id must match"):
        CreateProjectRolesRequest(
            bundle={"invariants": [], "roles": {}, "adapters": {}},
            base_project_roles_id="550e8400-e29b-41d4-a716-446655440000",
            base_policy_id="660e8400-e29b-41d4-a716-446655440000",
        )


def test_selected_role_info_emits_role_name_and_role():
    selected = SelectedRoleInfo(
        role_name="developer",
        title="Developer",
        playbook_md="Ship code",
    )
    data = selected.model_dump()
    assert data["role_name"] == "developer"
    assert data["role"] == "developer"


def test_active_project_roles_response_emits_legacy_and_canonical_ids():
    response = ActiveProjectRolesResponse(
        project_roles_id="550e8400-e29b-41d4-a716-446655440000",
        policy_id="550e8400-e29b-41d4-a716-446655440000",
        active_project_roles_id="550e8400-e29b-41d4-a716-446655440000",
        active_policy_id="550e8400-e29b-41d4-a716-446655440000",
        project_id="660e8400-e29b-41d4-a716-446655440000",
        version=3,
        updated_at="2026-01-01T00:00:00Z",
        invariants=[],
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
    assert data["policy_id"] == "550e8400-e29b-41d4-a716-446655440000"
    assert data["active_project_roles_id"] == "550e8400-e29b-41d4-a716-446655440000"
    assert data["active_policy_id"] == "550e8400-e29b-41d4-a716-446655440000"
    assert data["selected_role"]["role_name"] == "developer"
    assert data["selected_role"]["role"] == "developer"


def test_project_roles_history_response_emits_legacy_and_canonical_lists():
    item = ProjectRolesHistoryItem(
        project_roles_id="550e8400-e29b-41d4-a716-446655440000",
        policy_id="550e8400-e29b-41d4-a716-446655440000",
        version=2,
        created_at="2026-01-01T00:00:00Z",
        created_by_workspace_id=None,
        is_active=True,
    )
    response = ProjectRolesHistoryResponse(project_roles_versions=[item])
    data = response.model_dump()
    assert data["project_roles_versions"][0]["project_roles_id"] == item.project_roles_id
    assert data["policies"][0]["policy_id"] == item.policy_id


def test_resolve_selected_role_name_accepts_legacy_or_canonical_query():
    assert _resolve_selected_role_name(role="Developer", role_name=None) == "developer"
    assert _resolve_selected_role_name(role=None, role_name="Developer") == "developer"


def test_resolve_selected_role_name_rejects_conflicts():
    with pytest.raises(ValueError, match="role and role_name must match"):
        _resolve_selected_role_name(role="developer", role_name="reviewer")
