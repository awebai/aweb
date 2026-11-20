"""Capability fencing on real PG/HTTP, with real installation grants.

Folio reads its grants from the team's coordination server; each install,
repin, uninstall and replacement here is the server's own, made through its
public install routes. Legacy rows are modelled by unbinding Folio's own rows.
"""
from datetime import timedelta

import httpx
import pytest
from test_edit_sessions import exchange
from test_present_privacy import grants_refresh, mint, present_world

__all__ = ["present_world"]


@pytest.fixture
async def client(present_world):
    app = present_world.app
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://folio.test") as client:
        yield client


async def capabilities(world, client):
    readonly = await mint(world, editable=False)
    editable = await mint(world)
    path, secret = await exchange(client, editable)
    return readonly, editable, path, {"X-Folio-Edit-Session": secret}


async def test_new_rows_bind_and_repin_keeps_links_and_sessions(present_world, client):
    db = present_world.db
    installed = present_world.installation["installation_id"]
    readonly, _, path, headers = await capabilities(present_world, client)
    rows = await db.fetch_all("SELECT installation_id FROM {{tables.presentation_links}} UNION ALL SELECT installation_id FROM {{tables.edit_sessions}}")
    assert len(rows) == 3 and all(row["installation_id"] == installed for row in rows)
    repinned = await present_world.reinstall()
    assert repinned["installation_id"] == installed
    assert (await client.get(readonly["url"])).status_code == 200
    assert (await client.get(path + "/state", headers=headers)).status_code == 200


async def test_uninstall_and_replacement_never_revive_capabilities(present_world, client):
    readonly, _, path, headers = await capabilities(present_world, client)
    original = present_world.installation["installation_id"]
    await present_world.uninstall()
    for url, auth in [(readonly["url"], {}), (path + "/state", headers)]:
        response = await client.get(url, headers=auth)
        assert response.status_code == 404 and response.json()["detail"]["code"] == "installation_inactive"
    replacement = await present_world.reinstall()
    assert replacement["installation_id"] != original
    for url, auth in [(readonly["url"], {}), (path + "/state", headers)]:
        response = await client.get(url, headers=auth)
        assert response.status_code == 404 and response.json()["detail"]["code"] == "installation_replaced"


async def test_legacy_link_and_session_under_continuous_installation_adopt_once(present_world, client):
    db = present_world.db
    readonly, editable, path, headers = await capabilities(present_world, client)
    await db.execute("UPDATE {{tables.presentation_links}} SET installation_id=NULL")
    await db.execute("UPDATE {{tables.edit_sessions}} SET installation_id=NULL")
    assert (await client.get(readonly["url"])).status_code == 200
    assert (await client.get(path + "/state", headers=headers)).status_code == 200
    rows = await db.fetch_all("SELECT installation_id FROM {{tables.presentation_links}} UNION ALL SELECT installation_id FROM {{tables.edit_sessions}}")
    assert all(row["installation_id"] == present_world.installation["installation_id"] for row in rows)
    assert editable["token"] != readonly["token"]


async def _installed_at(world):
    status = await world.app.state.folio_runtime.installation_grants().status_for(world.member.team_id)
    assert status is not None and status.state == "active"
    return status.installed_at


@pytest.mark.parametrize("equal", [False, True])
async def test_legacy_row_older_than_installation_commits_permanent_refusal(present_world, client, equal):
    db = present_world.db
    link = await mint(present_world, editable=False)
    # A row from before Folio knew installations: unbound, and created at or
    # before the moment this installation was made.
    installed_at = await _installed_at(present_world)
    await db.execute(
        "UPDATE {{tables.presentation_links}} SET installation_id=NULL, created_at=$2 WHERE token=$1",
        link["token"],
        installed_at - timedelta(seconds=0 if equal else 1),
    )
    response = await client.get(link["url"])
    assert response.status_code == 404 and response.json()["detail"]["code"] == "installation_binding_refused"
    stored = await db.fetch_one("SELECT installation_id, installation_refused FROM {{tables.presentation_links}} WHERE token=$1", link["token"])
    assert stored["installation_id"] is None and stored["installation_refused"]
    await present_world.uninstall()
    await present_world.reinstall()
    assert (await client.get(link["url"])).json()["detail"]["code"] == "installation_binding_refused"
    assert (await db.fetch_one("SELECT installation_refused FROM {{tables.presentation_links}} WHERE token=$1", link["token"]))["installation_refused"]


async def test_session_legacy_refusal_does_not_retire_its_valid_parent(present_world, client):
    db = present_world.db
    link = await mint(present_world)
    path, secret = await exchange(client, link)
    await db.execute(
        "UPDATE {{tables.edit_sessions}} SET installation_id=NULL,created_at=$1",
        await _installed_at(present_world),
    )
    response = await client.get(path + "/state", headers={"X-Folio-Edit-Session": secret})
    assert response.status_code == 404 and response.json()["detail"]["code"] == "installation_binding_refused"
    assert (await db.fetch_one("SELECT installation_refused FROM {{tables.edit_sessions}}"))["installation_refused"]
    assert not (await db.fetch_one("SELECT installation_refused FROM {{tables.presentation_links}}"))["installation_refused"]


async def test_unavailable_g1_refuses_without_adopting_or_permanently_refusing_rows(present_world, client):
    db = present_world.db
    readonly, _, path, headers = await capabilities(present_world, client)
    await db.execute("UPDATE {{tables.presentation_links}} SET installation_id=NULL")
    await db.execute("UPDATE {{tables.edit_sessions}} SET installation_id=NULL")
    # The team's coordination server is off the network past Folio's last fresh answer.
    async with present_world.coordination.server_listener.down():
        await grants_refresh()
        for url, auth in [(readonly["url"], {}), (path + "/state", headers)]:
            response = await client.get(url, headers=auth)
            assert response.status_code == 503 and response.json()["detail"]["code"] == "authority_unavailable"
    rows = await db.fetch_all("SELECT installation_id, installation_refused FROM {{tables.presentation_links}} UNION ALL SELECT installation_id, installation_refused FROM {{tables.edit_sessions}}")
    assert all(row["installation_id"] is None and not row["installation_refused"] for row in rows)
