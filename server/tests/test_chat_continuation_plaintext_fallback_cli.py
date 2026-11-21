"""A default chat continuation whose encryption aw cannot read is plaintext.

A continuation inherits its conversation's end-to-end encryption, which aw
reads from the conversation's stored rows. When the server will not show
those rows to the sender (a grant scoped to chat.send only), or the widest
page it returns is full of plaintext rows so an older encrypted one may
exist, the default send is sent server-readable, as released aw sends it,
and aw says so on stderr. A headless sender is never refused for a choice
it did not make.

Real aweb, AWID and PostgreSQL: the grant is minted through
POST /v1/identity-grants, every row is posted through the chat routes, the
real aw binary sends, and SQL only observes what was stored.
"""

import asyncio
import os

import pytest
from test_addressless_sender_cli import _registry_http
from test_agent_activity_emitter_e2e import _grant_home
from test_dashboard_privacy import _request, privacy_app  # noqa: F401

__all__ = ["privacy_app"]

# Chat history accepts limit up to 2000 (server/src/aweb/routes/chat.py
# history), the page aw reads (cli/go/awid/conversation_encryption.go).
CHAT_ENCRYPTION_PAGE = 2000


async def _open_plaintext_session(env):
    opened = await _request(
        env,
        "alice",
        "POST",
        "/v1/chat/sessions",
        {
            "to_dids": [env.actors["bob"].did],
            "message": "opening",
        },
    )
    assert opened.status_code == 200, opened.text
    return opened.json()["session_id"]


async def _stored_bodies(env, session_id):
    rows = await env.db.fetch_all(
        "SELECT body FROM {{tables.chat_messages}} WHERE session_id=$1",
        session_id,
    )
    return [row["body"] for row in rows]


async def _aw(env, home, registry_url, *args):
    child_env = {
        k: v for k, v in os.environ.items() if not k.startswith(("AWEB_", "AWID_"))
    }
    child_env.update(
        AWEB_IDENTITY_HOME=str(home),
        AWEB_URL=str(env.client.base_url).rstrip("/"),
        AWID_REGISTRY_URL=registry_url,
        HOME=str(home.parent),
        XDG_CONFIG_HOME=str(home.parent / "config"),
        AW_NO_UPDATE_CHECK="1",
    )
    process = await asyncio.create_subprocess_exec(
        os.environ["AW_TEST_CLI_BINARY"],
        *args,
        cwd=home.parent,
        env=child_env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    output, _ = await asyncio.wait_for(process.communicate(), 60)
    return process.returncode, output.decode()


def _assert_plaintext_with_notice(code, output):
    assert code == 0, output
    assert "cannot tell whether this conversation is end-to-end encrypted" in output, (
        output
    )
    assert "sending server-readable plaintext" in output, output


@pytest.mark.usefixtures("source_cli_binary")
@pytest.mark.asyncio
async def test_a_send_only_grant_continues_by_default_in_plaintext_a_session_it_cannot_read(
    privacy_app, tmp_path
):
    env = privacy_app
    session_id = await _open_plaintext_session(env)
    (tmp_path / "send-only").mkdir()
    (tmp_path / "readable").mkdir()
    send_only, _ = await _grant_home(
        env, tmp_path / "send-only", "alice", ["chat.send"]
    )
    readable, _ = await _grant_home(
        env, tmp_path / "readable", "alice", ["chat.send", "chat.read"]
    )

    async with _registry_http(env.registry_app) as (registry_url, _):
        code, output = await _aw(
            env,
            send_only,
            registry_url,
            "chat",
            "send",
            "--session-id",
            session_id,
            "--body",
            "inherited",
            "--json",
        )
        _assert_plaintext_with_notice(code, output)
        assert "HTTP 403" in output, output
        assert "inherited" in await _stored_bodies(env, session_id)

        # Controls: an explicit choice needs no reading, and a grant that may
        # read the session learns it is plaintext.
        code, output = await _aw(
            env,
            send_only,
            registry_url,
            "chat",
            "send",
            "--session-id",
            session_id,
            "--body",
            "explicit",
            "--plaintext",
            "--json",
        )
        assert code == 0, output
        code, output = await _aw(
            env,
            readable,
            registry_url,
            "chat",
            "send",
            "--session-id",
            session_id,
            "--body",
            "readable",
            "--json",
        )
        assert code == 0, output

    stored = await _stored_bodies(env, session_id)
    assert "explicit" in stored and "readable" in stored, stored


@pytest.mark.usefixtures("source_cli_binary")
@pytest.mark.asyncio
async def test_a_default_continuation_is_plaintext_with_a_notice_once_the_readable_page_is_full(
    privacy_app, tmp_path
):
    env = privacy_app
    session_id = await _open_plaintext_session(env)
    for index in range(CHAT_ENCRYPTION_PAGE - 2):
        sender = "bob" if index % 2 == 0 else "alice"
        posted = await _request(
            env,
            sender,
            "POST",
            f"/v1/chat/sessions/{session_id}/messages",
            {"body": f"plaintext {index}"},
        )
        assert posted.status_code == 200, posted.text
    home, _ = await _grant_home(env, tmp_path, "alice", ["chat.send", "chat.read"])

    async with _registry_http(env.registry_app) as (registry_url, _):
        # 1999 stored rows: the whole history is readable and plaintext.
        assert len(await _stored_bodies(env, session_id)) == CHAT_ENCRYPTION_PAGE - 1
        code, output = await _aw(
            env,
            home,
            registry_url,
            "chat",
            "send",
            "--session-id",
            session_id,
            "--body",
            "last readable",
            "--json",
        )
        assert code == 0, output
        assert "sending server-readable plaintext" not in output, output

        # 2000 rows fill the page: an older row could be encrypted.
        code, output = await _aw(
            env,
            home,
            registry_url,
            "chat",
            "send",
            "--session-id",
            session_id,
            "--body",
            "beyond the page",
            "--json",
        )
        _assert_plaintext_with_notice(code, output)
        assert "the 2000 messages the server returns are plaintext" in output, output

    stored = await _stored_bodies(env, session_id)
    assert "last readable" in stored and "beyond the page" in stored
