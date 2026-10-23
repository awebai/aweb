"""Capability fencing on real PG/HTTP; authority is the explicit fixture source.

The Docker uninstall proof separately exercises real signed G1 and real CAS
uninstall/reinstall. These tests isolate persisted legacy decisions and races.
"""
from datetime import timedelta

import httpx
import pytest
from test_edit_sessions import exchange
from test_present_privacy import mint, present_world

__all__ = ["present_world"]


@pytest.fixture
async def client(present_world):
    app, _, _ = present_world
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://folio.test") as client:
        yield client


async def capabilities(world, client):
    readonly = await mint(world, editable=False)
    editable = await mint(world)
    path, secret = await exchange(client, editable)
    return readonly, editable, path, {"X-Folio-Edit-Session": secret}


async def test_new_rows_bind_and_repin_keeps_links_and_sessions(present_world, client):
    app, db, _ = present_world
    readonly, _, path, headers = await capabilities(present_world, client)
    rows = await db.fetch_all("SELECT installation_id FROM {{tables.presentation_links}} UNION ALL SELECT installation_id FROM {{tables.edit_sessions}}")
    assert len(rows) == 3 and all(row["installation_id"] == "test-installation" for row in rows)
    app.state.test_grants.generation += 1
    assert (await client.get(readonly["url"])).status_code == 200
    assert (await client.get(path + "/state", headers=headers)).status_code == 200


async def test_uninstall_and_replacement_never_revive_capabilities(present_world, client):
    app, _, _ = present_world
    readonly, _, path, headers = await capabilities(present_world, client)
    source = app.state.test_grants
    source.state = "uninstalled"
    source.generation += 1
    for url, auth in [(readonly["url"], {}), (path + "/state", headers)]:
        response = await client.get(url, headers=auth)
        assert response.status_code == 404 and response.json()["detail"]["code"] == "installation_inactive"
    source.state = "active"
    source.installation_id = "replacement"
    source.generation += 1
    for url, auth in [(readonly["url"], {}), (path + "/state", headers)]:
        response = await client.get(url, headers=auth)
        assert response.status_code == 404 and response.json()["detail"]["code"] == "installation_replaced"


async def test_legacy_link_and_session_under_continuous_installation_adopt_once(present_world, client):
    _, db, _ = present_world
    readonly, editable, path, headers = await capabilities(present_world, client)
    await db.execute("UPDATE {{tables.presentation_links}} SET installation_id=NULL")
    await db.execute("UPDATE {{tables.edit_sessions}} SET installation_id=NULL")
    assert (await client.get(readonly["url"])).status_code == 200
    assert (await client.get(path + "/state", headers=headers)).status_code == 200
    rows = await db.fetch_all("SELECT installation_id FROM {{tables.presentation_links}} UNION ALL SELECT installation_id FROM {{tables.edit_sessions}}")
    assert all(row["installation_id"] == "test-installation" for row in rows)
    assert editable["token"] != readonly["token"]


@pytest.mark.parametrize("equal", [False, True])
async def test_legacy_row_older_than_installation_commits_permanent_refusal(present_world, client, equal):
    app, db, _ = present_world
    link = await mint(present_world, editable=False)
    row = await db.fetch_one("SELECT created_at FROM {{tables.presentation_links}} WHERE token=$1", link["token"])
    await db.execute("UPDATE {{tables.presentation_links}} SET installation_id=NULL WHERE token=$1", link["token"])
    source = app.state.test_grants
    source.installed_at = row["created_at"] + timedelta(seconds=0 if equal else 1)
    response = await client.get(link["url"])
    assert response.status_code == 404 and response.json()["detail"]["code"] == "installation_binding_refused"
    stored = await db.fetch_one("SELECT installation_id, installation_refused FROM {{tables.presentation_links}} WHERE token=$1", link["token"])
    assert stored["installation_id"] is None and stored["installation_refused"]
    source.installation_id = "later-installation"
    source.generation += 1
    assert (await client.get(link["url"])).json()["detail"]["code"] == "installation_binding_refused"
    assert (await db.fetch_one("SELECT installation_refused FROM {{tables.presentation_links}} WHERE token=$1", link["token"]))["installation_refused"]


async def test_session_legacy_refusal_does_not_retire_its_valid_parent(present_world, client):
    app, db, _ = present_world
    link = await mint(present_world)
    path, secret = await exchange(client, link)
    await db.execute("UPDATE {{tables.edit_sessions}} SET installation_id=NULL,created_at=$1", app.state.test_grants.installed_at)
    response = await client.get(path + "/state", headers={"X-Folio-Edit-Session": secret})
    assert response.status_code == 404 and response.json()["detail"]["code"] == "installation_binding_refused"
    assert (await db.fetch_one("SELECT installation_refused FROM {{tables.edit_sessions}}"))["installation_refused"]
    assert not (await db.fetch_one("SELECT installation_refused FROM {{tables.presentation_links}}"))["installation_refused"]
