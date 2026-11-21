"""MCP federation budgets belong to the authenticated sender, not a shared proxy."""

from fastapi import Request
from aweb.mcp.auth import AuthContext
from aweb.mcp.tools.federation import mcp_sender_budget_key


def test_mcp_sender_budget_stays_distinct_without_an_http_request():
    alice = AuthContext(
        agent_id=None,
        team_id="team:example.test",
        did_key="did:key:alice",
        alias="alice",
    )
    bob = AuthContext(
        agent_id=None, team_id="team:example.test", did_key="did:key:bob", alias="bob"
    )
    assert mcp_sender_budget_key(alice) == "mcp:did:key:alice"
    assert mcp_sender_budget_key(bob) == "mcp:did:key:bob"


def test_two_mcp_senders_behind_the_same_proxy_keep_their_own_buckets(monkeypatch):
    request = Request(
        {
            "type": "http",
            "headers": [(b"x-forwarded-for", b"198.51.100.1")],
            "client": ("192.0.2.10", 1234),
            "method": "POST",
            "path": "/mcp",
        }
    )
    monkeypatch.setenv("AWEB_CLIENT_ADDRESS_HEADER", "x-forwarded-for")
    alice = AuthContext(
        agent_id=None,
        team_id="team:example.test",
        did_key="did:key:alice",
        alias="alice",
        request=request,
    )
    bob = AuthContext(
        agent_id=None,
        team_id="team:example.test",
        did_key="did:key:bob",
        alias="bob",
        request=request,
    )
    assert mcp_sender_budget_key(alice) == "mcp:did:key:alice"
    assert mcp_sender_budget_key(bob) == "mcp:did:key:bob"
