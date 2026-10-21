"""Exchanging a link secret for a session (docs/page-links.md §2, §6)."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import timedelta

import pytest
from pgdbm import AsyncDatabaseManager

from aweb_naapp.runtime.capability_links import LinkRefused, exchange

from .conftest import CAPABILITY, CREATOR, REQUESTS, T0, mint_link, request_from

SESSION_KEY = REQUESTS["keys"]["session"]["did_key"]


def body(secret: str, did_key: str = SESSION_KEY) -> bytes:
    return json.dumps({"secret": secret, "session_did_key": did_key}).encode()


async def _exchange(db, authority, link_id, payload: bytes, *, client="203.0.113.7", now=T0):
    return await exchange(db, authority, link_id=link_id, body=payload, client=client, now=now)


async def test_the_right_secret_opens_a_key_bound_session(
    db: AsyncDatabaseManager, authority
) -> None:
    minted = await mint_link(db, authority)
    session = await _exchange(db, authority, minted.link_id, body(minted.secret))
    assert session.session_id.startswith("lks_")
    assert len(session.csrf_token) == 22
    assert len(base64.urlsafe_b64decode(session.csrf_token + "==")) == 16
    assert session.expires_at == T0 + timedelta(minutes=15)
    assert session.link == {"page_id": "pg_4hd2", "mode": "live", "actions": ["mark-cleaned"]}
    row = await db.fetch_one(
        "SELECT * FROM {{tables.link_sessions}} WHERE session_id = $1", session.session_id
    )
    assert row["session_did_key"] == SESSION_KEY
    assert bytes(row["csrf_sha256"]) == hashlib.sha256(session.csrf_token.encode()).digest()
    assert session.csrf_token not in repr(dict(row))


async def test_a_session_never_outlives_its_link(db: AsyncDatabaseManager, authority) -> None:
    request = request_from(CAPABILITY["delegation"][0]["link"])
    request["expires_at"] = "2026-10-20T12:05:00Z"
    minted = await mint_link(db, authority, request)
    session = await _exchange(db, authority, minted.link_id, body(minted.secret))
    assert session.expires_at == minted.expires_at


async def test_a_link_may_hold_several_sessions(db: AsyncDatabaseManager, authority) -> None:
    minted = await mint_link(db, authority)
    first = await _exchange(db, authority, minted.link_id, body(minted.secret))
    second = await _exchange(db, authority, minted.link_id, body(minted.secret))
    assert first.session_id != second.session_id


@pytest.mark.parametrize("secret", ["wrong", None])
async def test_a_wrong_secret_or_unknown_link_is_link_unavailable(
    db: AsyncDatabaseManager, authority, secret
) -> None:
    minted = await mint_link(db, authority)
    link_id = minted.link_id if secret else "lnk_unknown"
    with pytest.raises(LinkRefused) as refused:
        await _exchange(db, authority, link_id, body(secret or minted.secret))
    assert (refused.value.code, refused.value.status) == ("link_unavailable", 404)
    assert await db.fetch_value("SELECT count(*) FROM {{tables.link_sessions}}") == 0


@pytest.mark.parametrize(
    "lifecycle",
    [
        "revoked_at = $2",
        "used_at = $2, used_by_operation = 'op-1', one_use = true",
    ],
    ids=["revoked", "one-use-used-up"],
)
async def test_an_unusable_link_is_link_unavailable(
    db: AsyncDatabaseManager, authority, lifecycle
) -> None:
    minted = await mint_link(db, authority)
    await db.execute(
        f"UPDATE {{{{tables.capability_links}}}} SET {lifecycle} WHERE link_id = $1",
        minted.link_id,
        T0,
    )
    with pytest.raises(LinkRefused) as refused:
        await _exchange(db, authority, minted.link_id, body(minted.secret))
    assert refused.value.code == "link_unavailable"


async def test_an_expired_link_is_link_unavailable(db: AsyncDatabaseManager, authority) -> None:
    minted = await mint_link(db, authority)
    with pytest.raises(LinkRefused) as refused:
        await _exchange(db, authority, minted.link_id, body(minted.secret), now=minted.expires_at)
    assert refused.value.code == "link_unavailable"


async def test_a_creator_who_lost_the_read_projection_closes_the_link(
    db: AsyncDatabaseManager, authority
) -> None:
    minted = await mint_link(db, authority)
    authority.reads[CREATOR].pop("bookings")
    with pytest.raises(LinkRefused) as refused:
        await _exchange(db, authority, minted.link_id, body(minted.secret))
    assert refused.value.code == "link_unavailable"


@pytest.mark.parametrize(
    "case", [k for k in REQUESTS["session_keys"] if not k["valid"]], ids=lambda k: k["name"]
)
async def test_a_non_canonical_session_key_is_refused_before_any_lookup(
    db: AsyncDatabaseManager, authority, case
) -> None:
    with pytest.raises(LinkRefused) as refused:
        await _exchange(db, authority, "lnk_unknown", body("x" * 43, case["did_key"]))
    assert (refused.value.code, refused.value.status) == ("schema_invalid", 422)


@pytest.mark.parametrize(
    "payload",
    [
        b'{"secret": "a", "secret": "b", "session_did_key": "x"}',
        b'{"secret": "a"}',
        b'{"secret": "a", "session_did_key": "%s", "extra": 1}' % SESSION_KEY.encode(),
        b'{"secret": 1, "session_did_key": "%s"}' % SESSION_KEY.encode(),
        b"not json",
    ],
)
async def test_a_malformed_body_is_schema_invalid(
    db: AsyncDatabaseManager, authority, payload
) -> None:
    minted = await mint_link(db, authority)
    with pytest.raises(LinkRefused) as refused:
        await _exchange(db, authority, minted.link_id, payload)
    assert refused.value.code == "schema_invalid"


async def test_wrong_secrets_do_not_lock_out_the_holder(
    db: AsyncDatabaseManager, authority
) -> None:
    case = CAPABILITY["lockout"][0]
    minted = await mint_link(db, authority)
    last = None
    for _ in range(case["steps"][0]["times"]):
        with pytest.raises(LinkRefused) as refused:
            await _exchange(db, authority, minted.link_id, body("wrong"), client="attacker")
        last = refused.value
    expected = case["result"]["attacker"]["last"]
    assert (last.status, last.code) == (expected["status"], expected["code"])
    assert last.retry_after_s >= 1
    session = await _exchange(db, authority, minted.link_id, body(minted.secret), client="holder")
    assert session.session_id


async def test_successful_exchanges_are_limited_per_link(
    db: AsyncDatabaseManager, authority
) -> None:
    minted = await mint_link(db, authority)
    for n in range(10):
        await _exchange(db, authority, minted.link_id, body(minted.secret), client=f"c{n}")
    with pytest.raises(LinkRefused) as refused:
        await _exchange(db, authority, minted.link_id, body(minted.secret), client="c10")
    assert (refused.value.code, refused.value.status) == ("safety_rate_limited", 429)
    assert await db.fetch_value("SELECT count(*) FROM {{tables.link_sessions}}") == 10
