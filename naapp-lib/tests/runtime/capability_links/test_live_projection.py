"""Checked live query capabilities; concrete SQL/cursor proof belongs to PageStore."""

import copy
import json
from datetime import timedelta

import pytest

from aweb_naapp.runtime.capability_links import LinkCaller, LinkRefused, Readable, mint

from . import test_lifecycle
from .conftest import CAPABILITY, CREATOR, DEFAULT_LINK, SCOPE, T0, request_from
from .test_exchange import _exchange, body
from .test_lifecycle import get_projection, revoke_link, selection, submit
from .test_snapshots import ProjectionSource

action_app = test_lifecycle.action_app


class Source:
    async def capture_link_snapshot_on(self, tx, *, projection, **context):
        page = copy.deepcopy(ProjectionSource.current)
        page["actions"] = []
        ids = projection["collections"][0]["record_ids"]
        assert isinstance(ids, list)  # No dynamic marker may reach capture.
        page["collections"][0]["records"] = [
            {"id": record_id, "rev": 1, "value": {"arrival": "2026-10-24"}} for record_id in ids
        ]
        return page


@pytest.mark.parametrize("case", CAPABILITY["live_projection_cases"], ids=lambda c: c["name"])
async def test_live_projection_vector(db, authority, action_app, case):
    request = request_from(DEFAULT_LINK)
    request.update(
        mode=case["mode"],
        page_rev=12 if case["mode"] == "pinned" else None,
        actions=[],
        intent_sponsor_did=None,
    )
    request["projection"]["collections"][0]["record_ids"] = case["records"]
    authority.reads[CREATOR]["bookings"] = Readable(
        tuple(case["initial_records"]), frozenset({"arrival", "status"})
    )
    async with db.transaction() as tx:
        link = await mint(
            tx,
            authority,
            scope=SCOPE,
            creator=CREATOR,
            creator_certificate_id="cert-test",
            request=request,
            now=T0,
            snapshot_source=Source(),
        )
    session = await _exchange(db, authority, link.link_id, body(link.secret))
    caller = LinkCaller(link.link_id, session.session_id)
    for step in case["steps"]:
        if step.get("collection_lost"):
            authority.reads[CREATOR].clear()
        elif "records" in step:
            authority.reads[CREATOR]["bookings"] = Readable(
                tuple(step["records"]), frozenset(step.get("fields", ["arrival", "status"]))
            )
        if step.get("revoke"):
            await revoke_link(db, caller)
        if "refused" in step:
            with pytest.raises(LinkRefused) as refused:
                if "action_record" in step:
                    await submit(db, authority, action_app, caller, record_id=step["action_record"])
                else:
                    await get_projection(
                        db,
                        authority,
                        caller,
                        now=T0 + timedelta(days=8) if step.get("expire") else T0,
                    )
            assert (refused.value.code, refused.value.status) == (step["refused"], step["status"])
            continue
        checked = await get_projection(db, authority, caller)
        expected = step.get(
            "projection_collections",
            [
                {
                    "collection": "bookings",
                    "record_ids": step.get("projection_records"),
                    "fields": step["fields"],
                }
            ],
        )
        assert checked.projection["collections"] == expected
        assert checked.allowed_action_ids == ()
        # The query marker is a capability ceiling, never an unbounded data page.
        assert (
            checked.source_snapshot is None
            if case["mode"] == "live"
            else checked.source_snapshot is not None
        )


async def test_live_wildcard_exceeds_one_page_but_never_freezes_all_ids(db, authority):
    from .test_lifecycle import holder

    request = request_from(DEFAULT_LINK)
    request.update(actions=[], intent_sponsor_did=None)
    request["projection"]["collections"][0]["record_ids"] = "*"
    authority.reads[CREATOR]["bookings"] = Readable(
        tuple(f"r-{i}" for i in range(501)), frozenset({"arrival", "status"})
    )
    caller = await holder(db, authority, request=request)
    checked = await get_projection(db, authority, caller)
    assert checked.projection["collections"][0]["record_ids"] == "*"
    assert await get_projection(db, authority, caller, projection=selection("arrival", records=()))
    stored = await db.fetch_value("SELECT record FROM {{tables.capability_links}}")
    stored = json.loads(stored) if isinstance(stored, str) else stored
    assert stored["projection"]["collections"][0]["record_ids"] == "*"


async def test_action_wildcards_remain_named_and_cannot_gain_new_targets(db, authority, action_app):
    from .test_lifecycle import holder

    request = request_from(DEFAULT_LINK)
    request["projection"]["collections"][0]["record_ids"] = "*"
    caller = await holder(db, authority, request=request)
    authority.reads[CREATOR]["bookings"] = Readable(
        ("b-17", "b-18", "b-19"), frozenset({"arrival", "status"})
    )
    checked = await get_projection(db, authority, caller)
    assert checked.projection["collections"][0]["record_ids"] == ["b-17", "b-18"]
    with pytest.raises(LinkRefused, match="action_denied"):
        await submit(db, authority, action_app, caller, record_id="b-19")
    # A caller cannot turn the old literal ceiling back into a live wildcard.
    with pytest.raises(LinkRefused, match="action_denied"):
        await get_projection(
            db,
            authority,
            caller,
            projection={
                "collections": [
                    {"collection": "bookings", "record_ids": "*", "fields": ["arrival"]}
                ],
                "assets": [],
            },
        )


async def test_pinned_wildcard_still_refuses_more_than_200_rows(db, authority):
    request = request_from(DEFAULT_LINK)
    request.update(mode="pinned", page_rev=12, actions=[], intent_sponsor_did=None)
    request["projection"]["collections"][0]["record_ids"] = "*"
    authority.reads[CREATOR]["bookings"] = Readable(
        tuple(f"r-{i}" for i in range(201)), frozenset({"arrival", "status"})
    )
    with pytest.raises(LinkRefused, match="action_denied"):
        async with db.transaction() as tx:
            await mint(
                tx,
                authority,
                scope=SCOPE,
                creator=CREATOR,
                creator_certificate_id="cert-test",
                request=request,
                now=T0,
                snapshot_source=Source(),
            )
