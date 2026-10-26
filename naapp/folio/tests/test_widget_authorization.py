"""A document author cannot borrow a broader link creator's collection access."""

import json
import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from aweb_naapp.page_store import Access
from aweb_naapp.runtime.clock import seconds_to_ns
from aweb_naapp.runtime.installation import AdmittedInstallation
from aweb_naapp_testing import Member
from test_record_links import TEAM, linked, listener

from folio.collection_documents import collection_scope

__all__ = ["linked", "listener"]


def table_body(reference="column"):
    widget = {
        "id": "research",
        "type": "table",
        "props": {"columns": [{"field": "finding", "label": "Finding", "format": "text"}]},
        "bind": {"collection": "discovery", "limit": 20},
    }
    if reference == "column":
        widget["props"]["columns"].append({"field": "status", "label": "Status", "format": "text"})
    elif reference == "filter":
        widget["bind"]["all"] = [{"field": "status", "op": "eq", "value": "hidden-filter"}]
    elif reference == "sort":
        widget["bind"]["sort"] = [{"field": "status", "direction": "asc"}]
    return "Before\n\n:::widget\n" + json.dumps(widget) + "\n:::\n\nAfter"


async def signed(linked, member, method, path, *, payload=None, body=None):
    raw = (
        json.dumps(payload, separators=(",", ":")).encode()
        if payload is not None
        else (body or "").encode()
    )
    headers = member.headers(
        aud=linked.host.settings.public_origin, method=method, path=path, body=raw
    )
    headers["Content-Type"] = "application/json" if payload is not None else "text/markdown"
    return await linked.client.request(method, path, content=raw, headers=headers)


@pytest.fixture
async def authors(linked):
    # Only the grant authority is the explicit host fixture, as in the baseline.
    # Request signatures, AWID certificate checks, HTTP routes and SQL are real.
    source = linked.host.runtime.installation_grants()
    async def grant_for(team_id, certificate_id=None):
        return await linked.host.grants.grant_for(team_id)

    source.grant_for = grant_for

    async def status_for(team_id):
        grant = await linked.host.grants.grant_for(team_id)
        return SimpleNamespace(
            team_id=team_id,
            app_id=linked.host.runtime.manifest.app_id,
            state="active",
            installation_id=grant.installation_id,
            generation=grant.generation,
            granted_scopes=grant.scopes,
            fresh_until=time.monotonic_ns() + seconds_to_ns(60),
            installed_at=datetime.now(UTC) - timedelta(days=1),
        )

    source.status_for = status_for
    member = Member(
        team_id=TEAM, team_key=linked.member.team_key, certificate_id="cert-author", alias="author"
    )
    await linked.registry.add_certificate(member.certificate())
    grant = linked.authorization.grant
    installation = AdmittedInstallation(
        team_id=TEAM,
        app_id=linked.host.runtime.manifest.app_id,
        installation_id=grant.installation_id,
        generation=grant.generation,
    )
    scope = collection_scope(installation, "discovery")
    # Verify the signed member path works independently of widget authorization.
    created = await signed(
        linked,
        linked.member,
        "POST",
        "/v1/documents",
        payload={
            "slug": "ordinary",
            "title": "Ordinary",
            "body": "Original prose",
        },
    )
    assert created.status_code == 200, created.text
    # Both broader-minter link entry points exist before the attempted version save.
    links = []
    for editable in (False, True):
        minted = await signed(
            linked,
            linked.member,
            "POST",
            "/v1/present",
            payload={
                "slug": "ordinary",
                "editable": editable,
            },
        )
        assert minted.status_code == 200, minted.text
        links.append(minted.json())
    return linked, member, scope, links


@pytest.mark.parametrize("write", ["create", "append"])
@pytest.mark.parametrize("restriction", ["collection", "column", "filter", "sort"])
async def test_saved_widget_requires_the_actual_author_collection_and_referenced_field_acl(
    authors,
    write,
    restriction,
):
    world, author, scope, links = authors
    owner = world.authorization.principal
    access = Access(owner=owner.did_key)
    if restriction != "collection":
        access = Access(
            owner=owner.did_key,
            team_id=TEAM,
            team_read=True,
            team_write=True,
            fields={author.did_key: {"discovery": {"finding"}}},
        )
    store = world.host.storage.require_store()
    await store.change_access(scope, owner, expected_rev=1, key="narrow-author", access=access)
    async with store.db.transaction() as tx:
        broad = await store.collection_access_on(
            tx, scope, creator_id=owner.did_key, collection="discovery", link_mode="live"
        )
    assert broad is not None and "status" in broad["fields"]
    body = table_body("column" if restriction == "collection" else restriction)
    if write == "create":
        response = await signed(
            world,
            author,
            "POST",
            "/v1/documents",
            payload={
                "slug": "forbidden",
                "title": "Forbidden",
                "body": body,
            },
        )
    else:
        response = await signed(world, author, "POST", "/v1/documents/ordinary/versions", body=body)
    assert response.status_code in (403, 404), response.text
    assert "hidden-filter" not in response.text and '"properties"' not in response.text
    current = await signed(world, world.member, "GET", "/v1/documents/ordinary")
    assert current.json()["current_version"] == 1
    assert current.json()["body"] == "Original prose"
    assert (
        await store.db.fetch_value(
            "SELECT count(*) FROM {{tables.documents}} WHERE slug='forbidden'"
        )
        == 0
    )
    assert len(links) == 2  # Neither pre-existing broader link can acquire the refused widget.


async def test_author_can_save_a_widget_using_only_its_authorized_fields(authors):
    world, author, scope, _ = authors
    store = world.host.storage.require_store()
    await store.change_access(
        scope,
        world.authorization.principal,
        expected_rev=1,
        key="narrow-author",
        access=Access(
            owner=world.member.did_key,
            team_id=TEAM,
            team_read=True,
            team_write=True,
            fields={author.did_key: {"discovery": {"finding"}}},
        ),
    )
    response = await signed(
        world,
        author,
        "POST",
        "/v1/documents",
        payload={
            "slug": "allowed",
            "title": "Allowed",
            "body": table_body("allowed"),
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["body"] == table_body("allowed")
