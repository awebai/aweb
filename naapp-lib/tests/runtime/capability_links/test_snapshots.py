"""Pinned projections persist at mint, never reconstructed from current values.

Written during the test hold. The source models the trusted PageStore adapter;
real PageStore projection/redaction integration is tested in the N3/N5 phase.
"""

from __future__ import annotations

import copy
import json
from dataclasses import replace
from datetime import timedelta

import pytest

from aweb_naapp.runtime.capability_links import (
    LinkCaller,
    LinkRefused,
    Readable,
    expire_snapshots,
    mint,
    purge_page_links_on,
    retained_asset_versions_on,
)

from .conftest import CREATOR, DEFAULT_LINK, SCOPE, T0, request_from
from .test_exchange import _exchange, body
from .test_lifecycle import get_projection, revoke_link, selection


class ProjectionSource:
    """A caller-transaction source with already authorized/redacted data."""

    current = {
        "page_format": "aweb.page/1",
        "page_id": SCOPE.page_id,
        "owner": "owner-1",
        "policy_ref": "policy-1",
        "locale": "en",
        "title": "Pinned bookings",
        "rev": 12,
        "layout_version": 1,
        "layout": [
            {
                "id": "heading-1",
                "type": "heading",
                "props": {"text": "Original heading", "level": 1},
            }
        ],
        "widget_state": {"heading-1": {"message": "Original state"}},
        "actions": [
            {
                "id": "mark-cleaned",
                "kind": "edit",
                "label": "Mark cleaned",
                "input_schema": {"type": "object", "additionalProperties": False},
                "policy_ref": "policy-1",
            }
        ],
        "collections": [
            {
                "id": "bookings",
                "mode": "owned",
                "schema_version": 1,
                "schema": {"type": "object", "properties": {"arrival": {"type": "string"}}},
                "records": [{"id": "b-17", "rev": 3, "value": {"arrival": "2026-10-24"}}],
            }
        ],
    }
    fail = False

    async def capture_link_snapshot_on(
        self, tx, *, scope, creator_id, projection, allowed_action_ids, expected_page_rev
    ):
        assert scope == SCOPE and creator_id == CREATOR
        assert projection["collections"] == selection("arrival")["collections"]
        assert allowed_action_ids == ["mark-cleaned"]
        assert expected_page_rev == 12
        # A source-side write proves the link and snapshot share its transaction.
        await tx.execute("INSERT INTO {{tables.test_snapshot_reads}} VALUES (1)")
        if self.fail:
            raise RuntimeError("source failed")
        return copy.deepcopy(self.current)


@pytest.fixture
async def snapshot_source(db):
    await db.execute("CREATE TABLE {{tables.test_snapshot_reads}} (id INTEGER)")
    source = ProjectionSource()
    source.current = copy.deepcopy(source.current)
    return source


async def pinned(db, authority, snapshot_source, *, asset_source=None):
    request = request_from(DEFAULT_LINK)
    request.update(mode="pinned", page_rev=12, projection=selection("arrival"))
    if asset_source is not None:
        request["projection"]["assets"] = list(asset_source.versions)
    async with db.transaction() as tx:
        return await mint(
            tx,
            authority,
            scope=SCOPE,
            creator=CREATOR,
            creator_certificate_id="cert-test",
            request=request,
            now=T0,
            snapshot_source=snapshot_source,
            asset_source=asset_source,
        )


async def pinned_holder(db, authority, snapshot_source, *, asset_source=None):
    link = await pinned(db, authority, snapshot_source, asset_source=asset_source)
    session = await _exchange(db, authority, link.link_id, body(link.secret))
    return LinkCaller(link.link_id, session.session_id)


async def test_pinned_values_do_not_move_after_the_current_page_changes(
    db, authority, snapshot_source
):
    caller = await pinned_holder(db, authority, snapshot_source)
    original = copy.deepcopy(snapshot_source.current)
    snapshot_source.current["rev"] = 13
    snapshot_source.current["collections"][0]["records"][0]["value"]["arrival"] = "2026-11-01"
    snapshot_source.current["layout"][0]["props"]["text"] = "Changed heading"
    snapshot_source.current["widget_state"]["heading-1"]["message"] = "Changed state"
    snapshot_source.current["actions"][0]["label"] = "Changed action"
    checked = await get_projection(db, authority, caller)
    assert checked.mode == "pinned" and checked.page_rev == 12
    assert checked.source_snapshot == original
    assert await db.fetch_value("SELECT count(*) FROM {{tables.test_snapshot_reads}}") == 1


@pytest.mark.parametrize("cause", ["missing", "corrupt", "wrong-revision"])
async def test_a_missing_or_corrupt_snapshot_never_falls_back_to_live(
    db, authority, snapshot_source, cause
):
    caller = await pinned_holder(db, authority, snapshot_source)
    if cause == "missing":
        await db.execute("DELETE FROM {{tables.capability_link_snapshots}}")
    elif cause == "corrupt":
        await db.execute("UPDATE {{tables.capability_link_snapshots}} SET snapshot='{}'::jsonb")
    else:
        await db.execute("UPDATE {{tables.capability_link_snapshots}} SET page_rev=13")
    with pytest.raises(LinkRefused) as refused:
        await get_projection(db, authority, caller)
    assert (refused.value.code, refused.value.status) == ("link_unavailable", 410)
    assert refused.value.reason  # log identifies the broken snapshot, response does not


async def test_a_snapshot_keeps_the_checked_projection_and_current_authority_gate(
    db, authority, snapshot_source
):
    caller = await pinned_holder(db, authority, snapshot_source)
    with pytest.raises(LinkRefused, match="action_denied"):
        await get_projection(db, authority, caller, projection=selection("guest_note"))
    authority.reads[CREATOR]["bookings"] = Readable((), frozenset({"arrival"}))
    with pytest.raises(LinkRefused, match="action_denied"):
        await get_projection(db, authority, caller)


async def test_revocation_applies_to_pinned_data(db, authority, snapshot_source):
    caller = await pinned_holder(db, authority, snapshot_source)
    await revoke_link(db, caller)
    with pytest.raises(LinkRefused) as refused:
        await get_projection(db, authority, caller)
    assert refused.value.status == 410


async def test_snapshot_and_source_work_roll_back_with_the_mint(db, authority, snapshot_source):
    snapshot_source.fail = True
    with pytest.raises(RuntimeError, match="source failed"):
        await pinned(db, authority, snapshot_source)
    for table in ("capability_links", "capability_link_snapshots", "test_snapshot_reads"):
        assert await db.fetch_value("SELECT count(*) FROM {{tables." + table + "}}") == 0


async def test_a_stale_snapshot_source_cannot_mint_a_pinned_link(db, authority, snapshot_source):
    snapshot_source.current["rev"] = 13
    with pytest.raises(LinkRefused) as refused:
        await pinned(db, authority, snapshot_source)
    assert (refused.value.code, refused.value.status) == ("revision_conflict", 409)
    assert await db.fetch_value("SELECT count(*) FROM {{tables.capability_links}}") == 0


async def test_page_purge_removes_snapshots_and_sessions_on_the_callers_transaction(
    db, authority, snapshot_source
):
    caller = await pinned_holder(db, authority, snapshot_source)
    with pytest.raises(RuntimeError):
        async with db.transaction() as tx:
            assert await purge_page_links_on(tx, scope=SCOPE) == 1
            raise RuntimeError("deletion rolled back")
    assert await get_projection(db, authority, caller)
    async with db.transaction() as tx:
        assert await purge_page_links_on(tx, scope=SCOPE) == 1
    assert await db.fetch_value("SELECT count(*) FROM {{tables.capability_link_snapshots}}") == 0
    assert await db.fetch_value("SELECT count(*) FROM {{tables.link_sessions}}") == 0


async def test_snapshot_expiry_reclaims_content_without_a_new_retention_default(
    db, authority, snapshot_source
):
    await pinned(db, authority, snapshot_source)
    assert await expire_snapshots(db, now=T0 + timedelta(days=6)) == 0
    assert await expire_snapshots(db, now=T0 + timedelta(days=7)) == 1
    assert await db.fetch_value("SELECT count(*) FROM {{tables.capability_links}}") == 1


async def test_the_stored_snapshot_has_no_capability_secret(db, authority, snapshot_source):
    link = await pinned(db, authority, snapshot_source)
    row = await db.fetch_one("SELECT * FROM {{tables.capability_link_snapshots}}")
    content = json.loads(row["snapshot"]) if isinstance(row["snapshot"], str) else row["snapshot"]
    assert content == snapshot_source.current
    assert link.secret not in repr(dict(row))


class Assets:
    versions = {"as-image": "version-1"}

    async def versions_on(self, tx, *, scope, asset_ids):
        assert scope == SCOPE
        return {asset_id: self.versions[asset_id] for asset_id in asset_ids}


async def retained(db, asset_id="as-image", now=T0):
    async with db.transaction() as tx:
        return await retained_asset_versions_on(tx, scope=SCOPE, asset_id=asset_id, now=now)


async def test_pinned_asset_versions_survive_ordinary_changes(db, authority, snapshot_source):
    assets = Assets()
    authority.assets[CREATOR] = {"as-image"}
    snapshot_source.current["layout"].append(
        {"id": "photo", "type": "image", "props": {"asset_id": "as-image", "alt": "House"}}
    )
    caller = await pinned_holder(db, authority, snapshot_source, asset_source=assets)
    assets.versions = {"as-image": "version-2"}
    checked = await get_projection(db, authority, caller)
    assert checked.asset_versions == {"as-image": "version-1"}
    assert await retained(db) == frozenset({"version-1"})
    async with db.transaction() as tx:
        # GC for another page must still see this installation's references.
        assert await retained_asset_versions_on(
            tx,
            scope=replace(SCOPE, page_id="other-page"),
            asset_id="as-image",
            now=T0,
        ) == frozenset({"version-1"})
    authority.assets[CREATOR].clear()  # explicit asset loss only removes this media capability
    checked = await get_projection(db, authority, caller)
    assert checked.projection["assets"] == [] and checked.asset_versions == {}
    assert checked.source_snapshot["title"] == "Pinned bookings"


@pytest.mark.parametrize("end", ["revoke", "expire", "purge"])
async def test_asset_references_release_with_the_link(db, authority, snapshot_source, end):
    authority.assets[CREATOR] = {"as-image"}
    caller = await pinned_holder(db, authority, snapshot_source, asset_source=Assets())
    assert await retained(db) == frozenset({"version-1"})
    if end == "revoke":
        await revoke_link(db, caller)
    elif end == "expire":
        assert await retained(db, now=T0 + timedelta(days=7)) == frozenset()
        await expire_snapshots(db, now=T0 + timedelta(days=7))
    else:
        async with db.transaction() as tx:
            await purge_page_links_on(tx, scope=SCOPE)
    assert await db.fetch_value("SELECT count(*) FROM {{tables.capability_link_asset_refs}}") == 0


async def test_current_action_loss_only_narrows_the_pinned_view(db, authority, snapshot_source):
    caller = await pinned_holder(db, authority, snapshot_source)
    assert (await get_projection(db, authority, caller)).allowed_action_ids == ("mark-cleaned",)
    authority.actions[CREATOR].clear()
    checked = await get_projection(db, authority, caller)
    assert checked.allowed_action_ids == ()
    assert checked.source_snapshot["actions"][0]["label"] == "Mark cleaned"
