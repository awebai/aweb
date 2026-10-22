"""Minting a capability link (docs/page-links.md §1), on real PostgreSQL."""

from __future__ import annotations

import base64
import copy
import hashlib
import json

import pytest
from pgdbm import AsyncDatabaseManager

from aweb_naapp.runtime.capability_links import LinkRefused

from .conftest import (
    CAPABILITY,
    CREATOR,
    DEFAULT_LINK,
    T0,
    authority_from,
    mint_link,
    request_from,
)


@pytest.mark.parametrize("case", CAPABILITY["delegation"], ids=lambda case: case["name"])
async def test_delegation(db: AsyncDatabaseManager, case) -> None:
    authority = authority_from(case["creator"])
    request = request_from(case["link"])
    expect = case["expect"]
    if "refused" in expect:
        with pytest.raises(LinkRefused) as refused:
            await mint_link(db, authority, request)
        assert refused.value.code == expect["refused"]
        assert await db.fetch_value("SELECT count(*) FROM {{tables.capability_links}}") == 0
        return
    minted = await mint_link(db, authority, request)
    record = await db.fetch_one(
        "SELECT record FROM {{tables.capability_links}} WHERE link_id = $1", minted.link_id
    )
    assert record is not None
    if "frozen_records" in expect:
        stored = _json(record["record"])["projection"]["collections"][0]["record_ids"]
        assert stored == expect["frozen_records"]
    if "dynamic_records" in expect:
        stored = _json(record["record"])["projection"]["collections"][0]["record_ids"]
        assert stored == expect["dynamic_records"]


def _json(value):
    return json.loads(value) if isinstance(value, str) else value


async def test_the_secret_is_returned_once_and_only_its_verifier_is_stored(
    db: AsyncDatabaseManager, authority
) -> None:
    minted = await mint_link(db, authority)
    assert len(minted.secret) == 43
    assert len(base64.urlsafe_b64decode(minted.secret + "=")) == 32
    row = await db.fetch_one(
        "SELECT * FROM {{tables.capability_links}} WHERE link_id = $1", minted.link_id
    )
    assert row["verifier_sha256"] == hashlib.sha256(minted.secret.encode()).hexdigest()
    assert minted.secret not in repr(dict(row))
    assert row["created_by"] == CREATOR
    assert (await mint_link(db, authority)).secret != minted.secret


async def test_the_record_keeps_what_the_creator_minted(
    db: AsyncDatabaseManager, authority
) -> None:
    minted = await mint_link(db, authority)
    row = await db.fetch_one(
        "SELECT record, expires_at, one_use FROM {{tables.capability_links}} WHERE link_id = $1",
        minted.link_id,
    )
    record = _json(row["record"])
    assert record["link_id"] == minted.link_id
    assert record["page_id"] == "pg_4hd2"
    assert record["created_by"]["principal_did"] == CREATOR
    assert record["rate_policy"] == "link-default-v1"
    assert "verifier_sha256" not in record
    assert row["expires_at"] == minted.expires_at


def _with(**changes):
    request = request_from(DEFAULT_LINK)
    request.update(changes)
    return request


def _collections(**grant):
    return {"collections": [{"collection": "bookings", **grant}], "assets": []}


SCHEMA_REFUSALS = {
    "unknown-field": {**request_from(DEFAULT_LINK), "team_id": "other:acme.com"},
    "pinned-without-rev": _with(mode="pinned", page_rev=None),
    "live-with-rev": _with(mode="live", page_rev=12),
    "unknown-mode": _with(mode="draft"),
    "no-collections": _with(projection={"collections": [], "assets": []}),
    "too-many-collections": _with(
        projection={
            "collections": [
                {"collection": f"c{n}", "record_ids": ["b-17"], "fields": ["status"]}
                for n in range(17)
            ],
            "assets": [],
        }
    ),
    "duplicate-collection": _with(
        projection={
            "collections": [
                {"collection": "bookings", "record_ids": ["b-17"], "fields": ["status"]},
                {"collection": "bookings", "record_ids": ["b-18"], "fields": ["status"]},
            ],
            "assets": [],
        }
    ),
    "duplicate-records": _with(
        projection=_collections(record_ids=["b-17", "b-17"], fields=["status"])
    ),
    "too-many-records": _with(
        projection=_collections(record_ids=[f"b-{n}" for n in range(201)], fields=["status"])
    ),
    "no-fields": _with(projection=_collections(record_ids=["b-17"], fields=[])),
    "too-many-fields": _with(
        projection=_collections(record_ids=["b-17"], fields=[f"f{n}" for n in range(65)])
    ),
    "too-many-assets": _with(
        projection={
            "collections": [
                {"collection": "bookings", "record_ids": ["b-17"], "fields": ["status"]}
            ],
            "assets": [f"as_{n}" for n in range(65)],
        }
    ),
    "too-many-actions": _with(
        actions=[{"action_id": f"a{n}", "constraints": {}} for n in range(17)]
    ),
    "duplicate-action": _with(
        actions=[
            {"action_id": "mark-cleaned", "constraints": {}},
            {"action_id": "mark-cleaned", "constraints": {"record_id": "b-17"}},
        ]
    ),
    "constraints-not-object": _with(actions=[{"action_id": "mark-cleaned", "constraints": []}]),
    "sponsor-without-intent": _with(intent_sponsor_did="did:aw:2bvkNehXHxb9NusXh7MbiUwn2vva"),
    "one-use-not-bool": _with(one_use=1),
    "expired-at-mint": _with(expires_at="2026-10-20T12:00:00Z"),
    "expiry-not-timestamp": _with(expires_at="2026-10-27"),
    "expiry-over-30-days": _with(expires_at="2026-11-19T12:00:01Z"),
}


@pytest.mark.parametrize("name", sorted(SCHEMA_REFUSALS))
async def test_a_malformed_request_is_schema_invalid(
    db: AsyncDatabaseManager, authority, name
) -> None:
    with pytest.raises(LinkRefused) as refused:
        await mint_link(db, authority, copy.deepcopy(SCHEMA_REFUSALS[name]))
    assert (refused.value.code, refused.value.status) == ("schema_invalid", 422)


async def test_a_link_may_last_exactly_30_days(db: AsyncDatabaseManager, authority) -> None:
    minted = await mint_link(db, authority, _with(expires_at="2026-11-19T12:00:00Z"))
    assert (minted.expires_at - T0).days == 30


async def test_a_sponsor_must_be_a_team_agent(db: AsyncDatabaseManager, authority) -> None:
    request = _with(
        actions=[{"action_id": "request-cleaner", "constraints": {}}],
        intent_sponsor_did="did:aw:notanagent",
    )
    with pytest.raises(LinkRefused) as refused:
        await mint_link(db, authority, request)
    assert (refused.value.code, refused.value.status) == ("action_denied", 403)


async def test_an_asset_the_creator_cannot_read_is_refused(
    db: AsyncDatabaseManager, authority
) -> None:
    request = _with(
        projection={
            "collections": [
                {"collection": "bookings", "record_ids": ["b-17"], "fields": ["status"]}
            ],
            "assets": ["as_1"],
        }
    )
    with pytest.raises(LinkRefused) as refused:
        await mint_link(db, authority, request)
    assert refused.value.code == "action_denied"
    authority.assets[CREATOR] = {"as_1"}
    await mint_link(db, authority, request)
