"""Team instructions and roles through real HTTP: audit of instruction changes
and the size limit on both documents."""

from __future__ import annotations

import json
from uuid import uuid4

import pytest

from aweb.coordination.team_documents import MAX_TEAM_DOCUMENT_BYTES
from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401
from test_operator_audit_http import _request

__all__ = ["privacy_app"]


async def _instruction_audit_rows(env):
    return await env.db.fetch_all(
        "SELECT * FROM {{tables.audit_log}} WHERE event_type LIKE 'instructions.%' ORDER BY created_at, id"
    )


INSTRUCTION_OPERATIONS = [
    (
        "POST",
        "/v1/instructions",
        {"document": {"body_md": "refused"}},
        "instructions.create",
    ),
    ("POST", "/v1/instructions/{id}/activate", None, "instructions.activate"),
    ("POST", "/v1/instructions/reset", None, "instructions.reset"),
]


@pytest.mark.asyncio
async def test_each_instruction_change_writes_one_attributed_row(privacy_app):
    env = privacy_app
    sentinel = "content-never-in-audit"
    created = await _request(
        env, "POST", "/v1/instructions", {"document": {"body_md": sentinel}}
    )
    assert created.status_code == 200, created.text
    instructions_id = created.json()["team_instructions_id"]
    activated = await _request(
        env, "POST", f"/v1/instructions/{instructions_id}/activate"
    )
    assert activated.status_code == 200, activated.text
    reset = await _request(env, "POST", "/v1/instructions/reset")
    assert reset.status_code == 200, reset.text

    rows = await _instruction_audit_rows(env)
    assert [r["event_type"] for r in rows] == [
        "instructions.create",
        "instructions.activate",
        "instructions.reset",
    ]
    assert [r["resource"] for r in rows] == [
        f"instructions:{TEAM}",
        f"instructions:{instructions_id}",
        f"instructions:{TEAM}",
    ]
    assert len({r["request_id"] for r in rows}) == 3
    for row in rows:
        assert row["team_id"] == TEAM
        assert row["actor_did_key"] == env.actors["alice"].did
        assert row["principal_type"] == "c" and row["outcome"] == "success"
        assert row["details"] is None and sentinel not in str(dict(row))


@pytest.mark.asyncio
@pytest.mark.parametrize("method,path,body,action", INSTRUCTION_OPERATIONS)
async def test_a_refused_instruction_change_writes_one_denied_row(
    privacy_app, method, path, body, action
):
    env = privacy_app
    await env.db.execute(
        "UPDATE {{tables.agents}} SET deleted_at=NOW() WHERE agent_id=$1",
        env.actors["alice"].id,
    )
    response = await _request(env, method, path.format(id=uuid4()), body)
    assert response.status_code == 403, response.text
    rows = await _instruction_audit_rows(env)
    assert [(r["event_type"], r["outcome"]) for r in rows] == [(action, "denied")]
    assert rows[0]["actor_did_key"] == env.actors["alice"].did
    assert (
        await env.db.fetch_value("SELECT count(*) FROM {{tables.team_instructions}}")
        == 0
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("method,path,body,action", INSTRUCTION_OPERATIONS)
async def test_an_instruction_change_that_cannot_be_audited_is_not_made(
    privacy_app, method, path, body, action
):
    env = privacy_app
    created = await _request(
        env, "POST", "/v1/instructions", {"document": {"body_md": "kept"}}
    )
    instructions_id = created.json()["team_instructions_id"]
    assert (
        await _request(env, "POST", f"/v1/instructions/{instructions_id}/activate")
    ).status_code == 200
    spare = await _request(
        env, "POST", "/v1/instructions", {"document": {"body_md": "spare"}}
    )
    before = await env.db.fetch_all(
        "SELECT * FROM {{tables.team_instructions}} ORDER BY id"
    )
    audited = len(await _instruction_audit_rows(env))
    await env.db.execute(
        "ALTER TABLE {{tables.audit_log}} ADD CONSTRAINT audit_test_failure "
        "CHECK (event_type NOT LIKE 'instructions.%') NOT VALID"
    )
    try:
        response = await _request(
            env, method, path.format(id=spare.json()["team_instructions_id"]), body
        )
        assert response.status_code == 500, response.text
        assert (
            await env.db.fetch_all(
                "SELECT * FROM {{tables.team_instructions}} ORDER BY id"
            )
            == before
        )
        assert len(await _instruction_audit_rows(env)) == audited
    finally:
        await env.db.execute(
            "ALTER TABLE {{tables.audit_log}} DROP CONSTRAINT audit_test_failure"
        )


@pytest.mark.asyncio
async def test_a_team_document_over_the_limit_is_refused_and_one_at_the_limit_is_stored(
    privacy_app,
):
    env = privacy_app
    # {"body_md": "...", "format": "markdown"} serialized, less the body itself.
    overhead = len(b'{"body_md": "", "format": "markdown"}')
    at_limit = "a" * (MAX_TEAM_DOCUMENT_BYTES - overhead)

    stored = await _request(
        env, "POST", "/v1/instructions", {"document": {"body_md": at_limit}}
    )
    assert stored.status_code == 200, stored.text
    refused = await _request(
        env, "POST", "/v1/instructions", {"document": {"body_md": at_limit + "a"}}
    )
    assert refused.status_code == 413, refused.text
    assert str(MAX_TEAM_DOCUMENT_BYTES) in refused.text
    assert (
        await env.db.fetch_value("SELECT count(*) FROM {{tables.team_instructions}}")
        == 1
    )

    oversized_roles = {
        "bundle": {
            "roles": {
                "dev": {"title": "dev", "playbook_md": "a" * MAX_TEAM_DOCUMENT_BYTES}
            }
        }
    }
    refused = await _request(env, "POST", "/v1/roles", oversized_roles)
    assert refused.status_code == 413, refused.text
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.team_roles}}") == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["instructions", "roles"])
async def test_concurrent_document_creation_allocates_distinct_versions(
    privacy_app, kind
):  # noqa: F811
    import asyncio

    from aweb.coordination.routes.team_instructions import (
        create_team_instructions_version,
    )
    from aweb.coordination.routes.team_roles import create_team_roles_version

    env = privacy_app
    table = "{{tables.team_" + kind + "}}"
    # Each INSERT has already selected MAX(version) when this trigger pauses
    # it. Without the per-team lock, concurrent writers select the same value.
    await env.db.execute("""
        CREATE FUNCTION {{tables.delay_team_document_insert}}() RETURNS trigger
        LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.15); RETURN NEW; END $$
    """)
    await env.db.execute(
        f"CREATE TRIGGER delay_team_document_insert BEFORE INSERT ON {table} "
        "FOR EACH ROW EXECUTE FUNCTION {{tables.delay_team_document_insert}}()"
    )

    async def create(index):
        args = dict(team_id=TEAM, created_by_alias="alice")
        if kind == "instructions":
            return await create_team_instructions_version(
                env.db,
                base_instructions_id=None,
                document={"body_md": str(index)},
                **args,
            )
        return await create_team_roles_version(
            env.db, base_roles_id=None, bundle={"roles": {}, "adapters": {}}, **args
        )

    outcomes = await asyncio.gather(
        *(create(i) for i in range(3)), return_exceptions=True
    )
    assert not [r for r in outcomes if isinstance(r, BaseException)], outcomes
    assert sorted(r.version for r in outcomes) == [1, 2, 3]
    assert (
        await env.db.fetch_value(f"SELECT count(*) FROM {table} WHERE team_id=$1", TEAM)
        == 3
    )


async def _versions(env, kind):
    table = "{{tables.team_" + kind + "}}"
    return await env.db.fetch_value(
        f"SELECT count(*) FROM {table} WHERE team_id=$1", TEAM
    )


@pytest.mark.asyncio
async def test_a_new_team_reads_an_empty_stored_roles_bundle(privacy_app):
    env = privacy_app
    assert await _versions(env, "roles") == 0

    active = await _request(env, "GET", "/v1/roles/active")

    assert active.status_code == 200, active.text
    assert active.json()["roles"] == {}
    rows = await env.db.fetch_all(
        "SELECT id, is_active, bundle_json FROM {{tables.team_roles}} WHERE team_id=$1",
        TEAM,
    )
    assert len(rows) == 1 and rows[0]["is_active"]
    bundle = rows[0]["bundle_json"]
    bundle = json.loads(bundle) if isinstance(bundle, str) else bundle
    assert bundle == {"roles": {}, "adapters": {}}
    assert active.json()["team_roles_id"] == str(rows[0]["id"])


@pytest.mark.asyncio
async def test_team_roles_routes_carry_the_ids_the_cli_reads(privacy_app):
    env = privacy_app
    first = (await _request(env, "GET", "/v1/roles/active")).json()
    assert first["active_team_roles_id"] == first["team_roles_id"]
    bundle = {
        "roles": {"developer": {"title": "Developer", "playbook_md": "Ship code"}},
        "adapters": {},
    }

    created = await _request(
        env,
        "POST",
        "/v1/roles",
        {"bundle": bundle, "base_team_roles_id": first["team_roles_id"]},
    )
    assert created.status_code == 200, created.text
    new_id = created.json()["team_roles_id"]
    activated = await _request(env, "POST", f"/v1/roles/{new_id}/activate")
    assert activated.status_code == 200, activated.text
    assert activated.json()["active_team_roles_id"] == new_id

    before = await _versions(env, "roles")
    stale = await _request(
        env,
        "POST",
        "/v1/roles",
        {"bundle": bundle, "base_team_roles_id": first["team_roles_id"]},
    )
    assert stale.status_code == 409, stale.text
    assert await _versions(env, "roles") == before

    active = (await _request(env, "GET", "/v1/roles/active?role_name=developer")).json()
    assert active["team_roles_id"] == active["active_team_roles_id"] == new_id
    assert active["selected_role"]["role_name"] == "developer"
    history = (await _request(env, "GET", "/v1/roles/history")).json()
    assert {v["team_roles_id"] for v in history["team_roles_versions"]} == {
        first["team_roles_id"],
        new_id,
    }
    deactivated = await _request(env, "POST", "/v1/roles/deactivate")
    assert deactivated.status_code == 200, deactivated.text
    assert deactivated.json()["deactivated"] is True
    assert deactivated.json()["active_team_roles_id"] != new_id


@pytest.mark.asyncio
async def test_team_instructions_routes_carry_the_ids_the_cli_reads(privacy_app):
    env = privacy_app
    first = await _request(
        env, "POST", "/v1/instructions", {"document": {"body_md": "first"}}
    )
    assert first.status_code == 200, first.text
    first_id = first.json()["team_instructions_id"]
    assert (
        await _request(env, "POST", f"/v1/instructions/{first_id}/activate")
    ).status_code == 200

    created = await _request(
        env,
        "POST",
        "/v1/instructions",
        {"document": {"body_md": "second"}, "base_team_instructions_id": first_id},
    )
    assert created.status_code == 200, created.text
    new_id = created.json()["team_instructions_id"]
    activated = await _request(env, "POST", f"/v1/instructions/{new_id}/activate")
    assert activated.status_code == 200, activated.text
    assert activated.json()["active_team_instructions_id"] == new_id

    before = await _versions(env, "instructions")
    stale = await _request(
        env,
        "POST",
        "/v1/instructions",
        {"document": {"body_md": "stale"}, "base_team_instructions_id": first_id},
    )
    assert stale.status_code == 409, stale.text
    assert await _versions(env, "instructions") == before

    active = (await _request(env, "GET", "/v1/instructions/active")).json()
    assert active["team_instructions_id"] == active["active_team_instructions_id"]
    assert active["team_instructions_id"] == new_id
    assert active["document"]["body_md"] == "second"
    history = (await _request(env, "GET", "/v1/instructions/history")).json()
    assert {
        v["team_instructions_id"] for v in history["team_instructions_versions"]
    } >= {
        first_id,
        new_id,
    }
