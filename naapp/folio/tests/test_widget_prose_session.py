"""The real edit-session text route cannot turn prose input into row authority."""

from urllib.parse import parse_qs, urlsplit

import pytest
from test_record_links import linked, listener
from test_widget_authorization import authors, signed, table_body

__all__ = ["authors", "linked", "listener"]


async def editor(authors):
    world, _, _, _ = authors
    body = table_body("column")
    appended = await signed(
        world, world.member, "POST", "/v1/documents/ordinary/versions", body=body
    )
    assert appended.status_code == 200, appended.text
    minted = await signed(
        world,
        world.member,
        "POST",
        "/v1/present",
        payload={
            "slug": "ordinary",
            "editable": True,
        },
    )
    assert minted.status_code == 200, minted.text
    parts = urlsplit(minted.json()["url"])
    response = await world.client.post(
        parts.path + "/session", json={"opener": parse_qs(parts.fragment)["k"][0]}
    )
    assert response.status_code == 200, response.text
    return (
        world,
        parts.path,
        {"X-Folio-Edit-Session": response.json()["session_secret"]},
        response.json(),
    )


@pytest.mark.parametrize("change", ["add", "remove", "rebind", "rename", "hide"])
async def test_edit_session_refuses_added_removed_or_changed_widget_definitions(authors, change):
    world, path, headers, current = await editor(authors)
    original = current["body"]
    if change == "add":
        proposed = original + "\n" + table_body("allowed").replace('"research"', '"another"')
    elif change == "remove":
        proposed = "Only prose remains."
    elif change == "rebind":
        proposed = original.replace('"discovery"', '"private-collection"')
    elif change == "rename":
        proposed = original.replace('"research"', '"renamed"')
    else:
        proposed = "```\n" + original
    response = await world.client.post(
        path + "/edit",
        headers=headers,
        json={
            "body": proposed,
            "base_version": current["version_number"],
        },
    )
    assert response.status_code in (409, 422), response.text
    assert "private-collection" not in response.text
    saved = await signed(world, world.member, "GET", "/v1/documents/ordinary")
    assert saved.json()["current_version"] == current["version_number"]
    assert saved.json()["body"] == original


async def test_edit_session_prose_only_save_preserves_widget_bytes(authors):
    world, path, headers, current = await editor(authors)
    proposed = current["body"].replace("Before", "Changed café prose before the table")
    response = await world.client.post(
        path + "/edit",
        headers=headers,
        json={
            "body": proposed,
            "base_version": current["version_number"],
        },
    )
    assert response.status_code == 200, response.text
    saved = await signed(world, world.member, "GET", "/v1/documents/ordinary")
    assert saved.json()["body"] == proposed
    assert saved.json()["current_version"] == current["version_number"] + 1
