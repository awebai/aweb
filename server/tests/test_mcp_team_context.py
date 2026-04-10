import json

import pytest

from aweb.mcp.auth import AuthContext
from aweb.mcp.tools import _common as common_tools
from aweb.mcp.tools import agents as agent_tools
from aweb.mcp.tools import tasks as task_tools
from aweb.mcp.tools import team_instructions as instruction_tools
from aweb.mcp.tools import team_roles as role_tools
from aweb.mcp.tools import work as work_tools
from aweb.mcp.tools import workspace as workspace_tools


class _DBInfra:
    def get_manager(self, name: str):
        raise AssertionError(f"unexpected DB access for {name}")


def _identity_only_auth() -> AuthContext:
    return AuthContext(
        team_id=None,
        agent_id=None,
        alias=None,
        did_key="did:key:z6MkIdentity",
        did_aw="did:aw:alice",
        address="acme.com/alice",
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "call",
    [
        lambda infra: agent_tools.list_agents(infra, None),
        lambda infra: agent_tools.heartbeat(infra, None),
        lambda infra: task_tools.task_list(infra),
        lambda infra: task_tools.task_comment_list(infra, ref="aweb-aagt.3"),
        lambda infra: work_tools.work_ready(infra),
        lambda infra: workspace_tools.workspace_status(infra, None),
        lambda infra: role_tools.roles_show(infra),
        lambda infra: instruction_tools.instructions_show(infra),
    ],
)
async def test_coordination_mcp_tools_require_team_context(monkeypatch, call):
    monkeypatch.setattr(common_tools, "get_auth", _identity_only_auth)
    result = json.loads(await call(_DBInfra()))
    assert result == {"error": "This tool requires team context. Use a team certificate."}
