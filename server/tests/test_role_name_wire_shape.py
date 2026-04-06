import pytest

pytest.skip("Tests reference removed models (RegisterWorkspaceRequest, RegisterAgentRequest, etc.) — to be deleted in aaez.5", allow_module_level=True)


def test_init_request_accepts_role_name_and_syncs_role():
    req = InitRequest(project_slug="my-project", role_name="Developer")
    assert req.role == "developer"
    assert req.role_name == "developer"


def test_init_request_defaults_to_agent_when_no_role_fields_are_provided():
    req = InitRequest(project_slug="my-project")
    assert req.role == "agent"
    assert req.role_name == "agent"


def test_init_request_empty_role_defaults_to_agent():
    req = InitRequest(project_slug="my-project", role="")
    assert req.role == "agent"
    assert req.role_name == "agent"


def test_register_workspace_request_accepts_role_name_and_syncs_role():
    req = RegisterWorkspaceRequest(
        repo_origin="https://github.com/test/repo.git",
        role_name="Frontend",
    )
    assert req.role == "frontend"
    assert req.role_name == "frontend"


def test_register_workspace_request_rejects_conflicting_role_aliases():
    with pytest.raises(ValidationError, match="role and role_name must match"):
        RegisterWorkspaceRequest(
            repo_origin="https://github.com/test/repo.git",
            role="developer",
            role_name="frontend",
        )


def test_register_agent_request_accepts_role_name_and_syncs_role():
    req = RegisterAgentRequest(
        workspace_id="550e8400-e29b-41d4-a716-446655440000",
        alias="alice",
        role_name="Reviewer",
    )
    assert req.role == "reviewer"
    assert req.role_name == "reviewer"


def test_patch_agent_request_accepts_role_name_and_syncs_role():
    req = PatchAgentRequest(role_name="Coordinator")
    assert req.role == "coordinator"
    assert req.role_name == "coordinator"


def test_response_models_emit_role_and_role_name():
    agent = AgentView(agent_id="agent-1", alias="alice", role="developer")
    workspace = WorkspaceInfo(
        workspace_id="ws-1",
        alias="alice",
        status="active",
        claims=[],
        role="developer",
    )
    scoped = ScopeAgentView(agent_id="agent-1", alias="alice", role="developer")

    assert agent.model_dump()["role_name"] == "developer"
    assert workspace.model_dump()["role_name"] == "developer"
    assert scoped.model_dump()["role_name"] == "developer"


def test_scope_provision_response_emits_role_and_role_name():
    response = ScopeProvisionResponse(
        created_at="2026-01-01T00:00:00Z",
        project_id="550e8400-e29b-41d4-a716-446655440000",
        project_slug="my-project",
        agent_id="660e8400-e29b-41d4-a716-446655440000",
        alias="alice",
        api_key="aw_sk_test",
        created=True,
        role="developer",
        role_name="developer",
    )
    data = response.model_dump()
    assert data["role"] == "developer"
    assert data["role_name"] == "developer"
