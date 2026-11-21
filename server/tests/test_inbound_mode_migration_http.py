"""A real N-1 inbound policy row stays private after it is backfilled."""

import json
from uuid import UUID

import asyncpg
import pytest
from pgdbm.errors import QueryError

from aweb_naapp.hooks.owner_act_nonces import apply_owner_act_migrations
from messaging_actor_support import register_messaging_actors, set_messaging_inbound_mode
from test_dashboard_privacy import privacy_stack
from test_messages_http import _signed_identity_headers
from tests.product_migration_support import stage_aweb_upgrade

MIGRATION = "056_inbound_mode_default.sql"


@pytest.mark.asyncio
@pytest.mark.parametrize("route", ["mail", "chat"])
async def test_migrated_global_recipient_keeps_noncontacts_refused(
    shared_test_pool, tmp_path, monkeypatch, route
):
    async with stage_aweb_upgrade(shared_test_pool, tmp_path / "policies", MIGRATION) as upgrade:
        await apply_owner_act_migrations(upgrade.infra.get_manager())
        async with privacy_stack(shared_test_pool, monkeypatch, database=upgrade.infra) as env:
            senders = await register_messaging_actors(
                env, team_id="ops:acme.com", aliases=("alice",), local=False
            )
            alice = senders["alice"]
            recipients = await register_messaging_actors(
                env,
                team_id="ops:otherco.com",
                aliases=("bob-migration", "bob-restricted"),
                local=False,
            )
            bob, restricted = (recipients[name] for name in ("bob-migration", "bob-restricted"))
            await set_messaging_inbound_mode(env, restricted, mode="team_and_contacts")
            # unreachable-state: pre-056 policy omitted by old admission.
            await env.db.execute(
                "UPDATE {{tables.agents}} SET inbound_mode = NULL WHERE agent_id=$1",
                UUID(bob.agent_id),
            )

            async def send(recipient):
                if route == "mail":
                    path = "/v1/messages"
                    payload = {"to_did": recipient.stable_id, "subject": "migration", "body": "hi"}
                else:
                    path = "/v1/chat/sessions"
                    payload = {"to_dids": [recipient.stable_id], "message": "migration"}
                body = json.dumps(payload).encode()
                return await env.client.post(
                    path,
                    content=body,
                    headers={
                        **_signed_identity_headers(alice.signing_key, alice.did_key, alice.stable_id, body),
                        "Content-Type": "application/json",
                    },
                )

            before = await send(bob)
            assert before.status_code == 403, before.text
            assert "inbound policy is unavailable" in before.text
            assert await env.db.fetch_value(
                """SELECT count(*) FROM {{tables.contacts}}
                   WHERE owner_did = $1 AND contact_address = $2""",
                alice.stable_id,
                bob.address,
            ) == 0

            assert await upgrade.apply() == [MIGRATION]
            assert await upgrade.apply() == []
            with pytest.raises(QueryError) as missing_policy:
                # unreachable-state: a legacy writer attempts to omit the required inbound policy.
                await env.db.execute(
                    """INSERT INTO {{tables.agents}} (team_id, did_key, alias)
                       VALUES ($1, $2, 'missing-inbound-mode')""",
                    bob.team_id,
                    alice.did_key,
                )
            refusal = missing_policy.value.__cause__
            assert isinstance(refusal, asyncpg.NotNullViolationError)
            assert refusal.column_name == "inbound_mode"
            schema = await env.db.fetch_one(
                """SELECT a.attnotnull, pg_get_expr(d.adbin, d.adrelid) AS mode_default
                   FROM pg_attribute a LEFT JOIN pg_attrdef d
                     ON d.adrelid = a.attrelid AND d.adnum = a.attnum
                   WHERE a.attrelid = '{{tables.agents}}'::regclass
                     AND a.attname = 'inbound_mode'"""
            )
            assert dict(schema) == {"attnotnull": True, "mode_default": None}
            modes = await env.db.fetch_all(
                "SELECT alias, inbound_mode FROM {{tables.agents}} WHERE agent_id = ANY($1::UUID[])",
                [UUID(bob.agent_id), UUID(restricted.agent_id)],
            )
            assert {row["alias"]: row["inbound_mode"] for row in modes} == {
                "bob-migration": "contacts_only",
                "bob-restricted": "team_and_contacts",
            }
            after = await send(bob)
            assert after.status_code == 403, after.text
            assert "exact active contacts" in after.text
            await set_messaging_inbound_mode(env, bob, mode="open")
            owner_opened = await send(bob)
            assert owner_opened.status_code == 200, owner_opened.text
            still_restricted = await send(restricted)
            assert still_restricted.status_code == 403, still_restricted.text
            assert "exact active contacts" in still_restricted.text
