"""An inbox page reads its senders' agent rows with the page, not in a query of their own."""

import asyncpg.connection
import pytest

from test_dashboard_privacy import _request, _seed_mail, privacy_app  # noqa: F401


@pytest.mark.asyncio
async def test_an_inbox_page_reads_sender_membership_rows_with_its_messages(privacy_app, monkeypatch):
    env = privacy_app
    await _seed_mail(env)
    statements: list[str] = []
    execute = asyncpg.connection.Connection._execute

    async def observed_execute(connection, query, *args, **kwargs):
        statements.append(" ".join(query.split()))
        return await execute(connection, query, *args, **kwargs)

    monkeypatch.setattr(asyncpg.connection.Connection, "_execute", observed_execute)
    inbox = await _request(env, "bob", "GET", "/v1/messages/inbox?limit=50")

    assert inbox.status_code == 200, inbox.text
    message = inbox.json()["messages"][0]
    assert message["sender_membership"]["team_id"]
    assert not [q for q in statements if "WHERE agent_id = ANY($1::uuid[])" in q]
