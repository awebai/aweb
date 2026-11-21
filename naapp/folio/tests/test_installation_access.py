"""Capability fencing on real PG/HTTP; authority is the explicit fixture source.

The Docker uninstall proof separately exercises real signed G1 and real CAS
uninstall/reinstall. These tests isolate persisted legacy decisions and races.
"""

import asyncio
import base64
from datetime import timedelta
from enum import StrEnum

import httpx
import pytest
from test_edit_sessions import exchange
from test_present_privacy import OWNER, mint, present_world

from folio import installation_access
from folio.link_secrets import read_only_link_key
from folio.models import ImageAssetUploadRequest
from folio.repository import append_version, upload_image_asset

__all__ = ["present_world"]


@pytest.fixture
async def client(present_world):
    app, _, _ = present_world
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://folio.test"
    ) as client:
        yield client


async def capabilities(world, client):
    readonly = await mint(world, editable=False)
    editable = await mint(world)
    path, secret = await exchange(client, editable)
    return readonly, editable, path, {"X-Folio-Edit-Session": secret}


async def test_new_rows_bind_and_repin_keeps_links_and_sessions(present_world, client):
    app, db, _ = present_world
    readonly, _, path, headers = await capabilities(present_world, client)
    rows = await db.fetch_all(
        "SELECT installation_id FROM {{tables.presentation_links}} UNION ALL SELECT installation_id FROM {{tables.edit_sessions}}"
    )
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
        assert (
            response.status_code == 404
            and response.json()["detail"]["code"] == "installation_inactive"
        )
    source.state = "active"
    source.installation_id = "replacement"
    source.generation += 1
    for url, auth in [(readonly["url"], {}), (path + "/state", headers)]:
        response = await client.get(url, headers=auth)
        assert (
            response.status_code == 404
            and response.json()["detail"]["code"] == "installation_replaced"
        )


async def test_legacy_link_and_session_under_continuous_installation_adopt_once(
    present_world, client
):
    _, db, _ = present_world
    readonly, editable, path, headers = await capabilities(present_world, client)
    await db.execute("UPDATE {{tables.presentation_links}} SET installation_id=NULL")
    await db.execute("UPDATE {{tables.edit_sessions}} SET installation_id=NULL")
    assert (await client.get(readonly["url"])).status_code == 200
    assert (await client.get(path + "/state", headers=headers)).status_code == 200
    rows = await db.fetch_all(
        "SELECT installation_id FROM {{tables.presentation_links}} UNION ALL SELECT installation_id FROM {{tables.edit_sessions}}"
    )
    assert all(row["installation_id"] == "test-installation" for row in rows)
    assert editable["token"] != readonly["token"]


@pytest.mark.parametrize("equal", [False, True])
async def test_legacy_row_older_than_installation_commits_permanent_refusal(
    present_world, client, equal
):
    app, db, _ = present_world
    link = await mint(present_world, editable=False)
    key = read_only_link_key(link["token"])
    row = await db.fetch_one(
        "SELECT created_at FROM {{tables.presentation_links}} WHERE token=$1", key
    )
    await db.execute(
        "UPDATE {{tables.presentation_links}} SET installation_id=NULL WHERE token=$1", key
    )
    source = app.state.test_grants
    source.installed_at = row["created_at"] + timedelta(seconds=0 if equal else 1)
    response = await client.get(link["url"])
    assert (
        response.status_code == 404
        and response.json()["detail"]["code"] == "installation_binding_refused"
    )
    stored = await db.fetch_one(
        "SELECT installation_id, installation_refused FROM {{tables.presentation_links}} WHERE token=$1",
        key,
    )
    assert stored["installation_id"] is None and stored["installation_refused"]
    source.installation_id = "later-installation"
    source.generation += 1
    assert (await client.get(link["url"])).json()["detail"][
        "code"
    ] == "installation_binding_refused"
    assert (
        await db.fetch_one(
            "SELECT installation_refused FROM {{tables.presentation_links}} WHERE token=$1", key
        )
    )["installation_refused"]


async def test_session_legacy_refusal_does_not_retire_its_valid_parent(present_world, client):
    app, db, _ = present_world
    link = await mint(present_world)
    path, secret = await exchange(client, link)
    await db.execute(
        "UPDATE {{tables.edit_sessions}} SET installation_id=NULL,created_at=$1",
        app.state.test_grants.installed_at,
    )
    response = await client.get(path + "/state", headers={"X-Folio-Edit-Session": secret})
    assert (
        response.status_code == 404
        and response.json()["detail"]["code"] == "installation_binding_refused"
    )
    assert (await db.fetch_one("SELECT installation_refused FROM {{tables.edit_sessions}}"))[
        "installation_refused"
    ]
    assert not (
        await db.fetch_one("SELECT installation_refused FROM {{tables.presentation_links}}")
    )["installation_refused"]


async def test_unavailable_g1_refuses_without_adopting_or_permanently_refusing_rows(
    present_world, client
):
    from aweb_naapp.runtime.authorization import GrantUnavailable

    app, db, _ = present_world
    readonly, _, path, headers = await capabilities(present_world, client)
    await db.execute("UPDATE {{tables.presentation_links}} SET installation_id=NULL")
    await db.execute("UPDATE {{tables.edit_sessions}} SET installation_id=NULL")

    async def unavailable(team_id):
        raise GrantUnavailable("authority cannot be reached")

    app.state.test_grants.status_for = unavailable
    for url, auth in [(readonly["url"], {}), (path + "/state", headers)]:
        response = await client.get(url, headers=auth)
        assert (
            response.status_code == 503
            and response.json()["detail"]["code"] == "authority_unavailable"
        )
    rows = await db.fetch_all(
        "SELECT installation_id, installation_refused FROM {{tables.presentation_links}} UNION ALL SELECT installation_id, installation_refused FROM {{tables.edit_sessions}}"
    )
    assert all(row["installation_id"] is None and not row["installation_refused"] for row in rows)


_PNG = b"\x89PNG\r\n\x1a\n" + b"lock-wait"


class Served(StrEnum):
    """What a read-only link serves: its page, or an image the page shows."""

    PAGE = "page"
    IMAGE = "image"


@pytest.mark.parametrize("served", list(Served))
async def test_link_that_expires_during_a_lock_wait_serves_nothing(
    present_world, client, monkeypatch, served
):
    """A read that began before the link's expiry and waited on the link row past it
    is refused: the deadline is checked on live time after every wait."""
    app, db, settings = present_world
    uploaded = await upload_image_asset(
        db,
        principal=OWNER,
        settings=settings,
        image=ImageAssetUploadRequest(
            content_type="image/png", data_base64=base64.b64encode(_PNG).decode()
        ),
    )
    asset_id = uploaded["asset_id"]
    await append_version(
        db,
        principal=OWNER,
        events=app.state.folio_runtime.app_events,
        slug="draft",
        body=f"![shown](/assets/{asset_id})",
    )
    # A three-second link, so it expires while the read below waits on its row.
    link = await mint(present_world, editable=False, ttl_seconds=3)
    key = read_only_link_key(link["token"])
    url = link["url"] if served is Served.PAGE else f"{link['url']}/assets/{asset_id}"
    assert (await client.get(url)).status_code == 200

    locked, release = asyncio.Event(), asyncio.Event()

    async def hold_link_row() -> None:
        async with db.transaction() as tx:
            await tx.execute(
                "SELECT 1 FROM {{tables.presentation_links}} WHERE token=$1 FOR UPDATE", key
            )
            locked.set()
            await release.wait()

    holders: list[asyncio.Task] = []
    admit = installation_access.capability_permit

    async def admit_then_lock(*args, **kwargs):
        # The link row is locked after admission, so the serving transaction
        # starts before the deadline and waits on the row until after it.
        permit = await admit(*args, **kwargs)
        holders.append(asyncio.create_task(hold_link_row()))
        await locked.wait()
        return permit

    monkeypatch.setattr(installation_access, "capability_permit", admit_then_lock)
    request = asyncio.create_task(client.get(url))
    await locked.wait()
    expires_at = await db.fetch_value(
        "SELECT expires_at FROM {{tables.presentation_links}} WHERE token=$1", key
    )
    while await db.fetch_value("SELECT clock_timestamp() <= $1", expires_at):
        await asyncio.sleep(0.1)
    await asyncio.sleep(0.2)
    assert not request.done()
    release.set()
    await asyncio.gather(*holders)
    response = await request
    assert response.status_code == 404
    assert _PNG not in response.content
