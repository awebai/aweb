"""Authenticating a link holder's signed request (docs/page-links.md §3 steps 1-5)."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from datetime import datetime, timedelta

import pytest
from awid.signing import canonical_json_bytes
from nacl.signing import SigningKey
from pgdbm import AsyncDatabaseManager

from aweb_naapp.runtime.capability_links import LinkRefused, authenticate, expire_sessions
from aweb_naapp.runtime.link_requests import sign_link_request

from .conftest import REQUESTS, mint_link

APP_ORIGIN = "https://pages.example.com"
NOW = datetime.fromisoformat(REQUESTS["now"].replace("Z", "+00:00"))
VALID = {case["name"]: case for case in REQUESTS["valid"]}
CSRF = "AAECAwQFBgcICQoLDA0ODw"


@pytest.fixture
async def session(db: AsyncDatabaseManager, authority) -> str:
    """The vectors' link and session, bound to the vectors' session key."""
    minted = await mint_link(db, authority)
    await db.execute(
        "UPDATE {{tables.capability_links}} SET link_id = 'lnk_01JC7Q' WHERE link_id = $1",
        minted.link_id,
    )
    await db.execute(
        """
        INSERT INTO {{tables.link_sessions}}
            (session_id, link_id, session_did_key, csrf_sha256, created_at, expires_at)
        VALUES ('lks_01JC7R', 'lnk_01JC7Q', $1, $2, $3, $4)
        """,
        REQUESTS["keys"]["session"]["did_key"],
        hashlib.sha256(CSRF.encode()).digest(),
        NOW - timedelta(minutes=1),
        NOW + timedelta(minutes=14),
    )
    return "lks_01JC7R"


def _request(case, **changes):
    request = {
        "authorization": case["authorization"],
        "signed_payload": case["signed_payload_header"],
        "method": case["payload"]["method"],
        "target": case["payload"]["path"],
        "body": case["body"].encode(),
        "origin": APP_ORIGIN,
        "csrf": CSRF,
        "app_origin": APP_ORIGIN,
        "now": NOW,
    }
    request.update(changes)
    return request


async def _authenticate(db, **request):
    return await authenticate(db, **request)


def _signed(payload: dict) -> tuple[str, str]:
    key = SigningKey(bytes.fromhex(REQUESTS["keys"]["session"]["seed_hex"]))
    signature = sign_link_request(payload, key)
    header = base64.urlsafe_b64encode(canonical_json_bytes(payload)).rstrip(b"=").decode()
    return f"AWEB-Link-Request {payload['session_id']} {signature}", header


def _fresh(case, nonce: str) -> dict:
    payload = {**case["payload"], "nonce": nonce}
    authorization, header = _signed(payload)
    return _request(case, authorization=authorization, signed_payload=header)


@pytest.mark.parametrize("name", sorted(VALID))
async def test_a_valid_signed_request_authenticates(
    db: AsyncDatabaseManager, session, name
) -> None:
    caller = await _authenticate(db, **_request(VALID[name]))
    assert (caller.link_id, caller.session_id) == ("lnk_01JC7Q", session)


async def test_a_read_needs_no_origin_or_csrf(db: AsyncDatabaseManager, session) -> None:
    await _authenticate(db, **_request(VALID["projection-read"], origin=None, csrf=None))


@pytest.mark.parametrize(
    "changes",
    [
        {"target": "/v1/pages/pg_4hd2/actions?x=1"},
        {"method": "PUT"},
        {"body": b"{}"},
        {"authorization": "Bearer abc"},
        {"authorization": None},
        {"signed_payload": None},
    ],
    ids=["path", "method", "body", "scheme", "no-authorization", "no-payload"],
)
async def test_a_request_that_does_not_match_its_signature_is_refused(
    db: AsyncDatabaseManager, session, changes
) -> None:
    with pytest.raises(LinkRefused) as refused:
        await _authenticate(db, **_request(VALID["action-post"], **changes))
    assert (refused.value.code, refused.value.status) == ("signature_invalid", 401)


async def test_an_expired_session_is_unavailable_after_signature_verification(
    db: AsyncDatabaseManager, session
) -> None:
    await db.execute(
        "UPDATE {{tables.link_sessions}} SET expires_at = $1 WHERE session_id = $2", NOW, session
    )
    with pytest.raises(LinkRefused) as refused:
        await _authenticate(db, **_request(VALID["action-post"]))
    assert (refused.value.code, refused.value.status) == ("link_unavailable", 410)
    with pytest.raises(LinkRefused) as unsigned:
        await _authenticate(db, **_request(VALID["action-post"], authorization=None))
    assert (unsigned.value.code, unsigned.value.status) == ("signature_invalid", 401)


async def test_a_stale_request_is_authorization_expired(db: AsyncDatabaseManager, session) -> None:
    with pytest.raises(LinkRefused) as refused:
        await _authenticate(db, **_request(VALID["action-post"], now=NOW + timedelta(seconds=61)))
    assert (refused.value.code, refused.value.status) == ("authorization_expired", 401)


async def test_a_replayed_nonce_is_refused(db: AsyncDatabaseManager, session) -> None:
    await _authenticate(db, **_request(VALID["action-post"]))
    with pytest.raises(LinkRefused) as refused:
        await _authenticate(db, **_request(VALID["action-post"]))
    assert (refused.value.code, refused.value.status) == ("idempotency_conflict", 409)
    await _authenticate(db, **_fresh(VALID["action-post"], "0" * 31 + "1"))


@pytest.mark.parametrize(
    "changes",
    [{"origin": None}, {"origin": "https://evil.example"}, {"csrf": None}, {"csrf": "x" * 22}],
    ids=["no-origin", "wrong-origin", "no-csrf", "wrong-csrf"],
)
async def test_a_write_needs_the_app_origin_and_the_session_csrf(
    db: AsyncDatabaseManager, session, changes
) -> None:
    with pytest.raises(LinkRefused) as refused:
        await _authenticate(db, **_request(VALID["action-post"], **changes))
    assert (refused.value.code, refused.value.status) == ("action_denied", 403)
    # The nonce was recorded before the Origin and CSRF checks.
    with pytest.raises(LinkRefused) as replayed:
        await _authenticate(db, **_request(VALID["action-post"]))
    assert replayed.value.code == "idempotency_conflict"


async def test_the_nonce_is_kept_past_the_session_for_the_clock_window(
    db: AsyncDatabaseManager, session
) -> None:
    await _authenticate(db, **_request(VALID["action-post"]))
    keep = await db.fetch_value("SELECT keep_until FROM {{tables.link_nonces}}")
    assert keep == NOW + timedelta(minutes=14)
    await db.execute(
        "UPDATE {{tables.link_sessions}} SET expires_at = $1 WHERE session_id = $2",
        NOW + timedelta(seconds=10),
        session,
    )
    await _authenticate(db, **_fresh(VALID["action-post"], "0" * 31 + "2"))
    keeps = [
        row["keep_until"]
        for row in await db.fetch_all(
            "SELECT keep_until FROM {{tables.link_nonces}} ORDER BY keep_until"
        )
    ]
    assert keeps[0] == NOW + timedelta(seconds=60)


async def test_two_concurrent_requests_with_one_nonce_admit_exactly_one(
    db: AsyncDatabaseManager, session
) -> None:
    async def attempt() -> bool:
        try:
            await _authenticate(db, **_request(VALID["action-post"]))
            return True
        except LinkRefused as refused:
            assert refused.code == "idempotency_conflict"
            return False

    results = await asyncio.gather(*(attempt() for _ in range(8)))
    assert sum(results) == 1
    assert await db.fetch_value("SELECT count(*) FROM {{tables.link_nonces}}") == 1


def test_the_vectors_bodies_match_their_digests() -> None:
    for case in REQUESTS["valid"]:
        assert hashlib.sha256(case["body"].encode()).hexdigest() == case["payload"]["body_sha256"]
        assert json.loads(base64.urlsafe_b64decode(case["signed_payload_header"] + "=="))


async def test_expired_sessions_and_spent_nonces_are_deleted(
    db: AsyncDatabaseManager, session
) -> None:
    await _authenticate(db, **_request(VALID["action-post"]))
    assert await expire_sessions(db, now=NOW + timedelta(minutes=13)) == 0
    assert await expire_sessions(db, now=NOW + timedelta(minutes=14)) == 2
    assert await db.fetch_value("SELECT count(*) FROM {{tables.link_sessions}}") == 0
    assert await db.fetch_value("SELECT count(*) FROM {{tables.link_nonces}}") == 0


@pytest.mark.parametrize("failure", ["origin", "csrf", "action"])
async def test_signed_attempts_commit_their_budget_even_when_the_operation_fails(
    db, session, failure
):
    capacity = 240  # link-default-v1 signed attempts, per session per minute
    for index in range(capacity):
        request = _fresh(VALID["action-post"], f"{index:032x}")
        if failure == "origin":
            request["origin"] = "https://evil.example"
        elif failure == "csrf":
            request["csrf"] = "wrong"
        if failure == "action":
            await _authenticate(db, **request)
            with pytest.raises(RuntimeError):
                async with db.transaction():
                    raise RuntimeError("later action rolled back")
        else:
            with pytest.raises(LinkRefused, match="action_denied"):
                await _authenticate(db, **request)
    request = _fresh(VALID["action-post"], f"{capacity:032x}")
    with pytest.raises(LinkRefused) as refused:
        await _authenticate(db, **request)
    assert (refused.value.code, refused.value.status) == ("safety_rate_limited", 429)
    assert refused.value.retry_after_s == 1
    assert await db.fetch_value("SELECT count(*) FROM {{tables.link_nonces}}") == capacity
    # A later valid request can use the refilled token; refusal stored no nonce.
    await _authenticate(db, **{**request, "now": NOW + timedelta(seconds=1)})


async def test_invalid_signatures_never_consume_a_session_attempt(db, session):
    with pytest.raises(LinkRefused, match="signature_invalid"):
        await _authenticate(db, **_request(VALID["action-post"], body=b"tampered"))
    assert (
        await db.fetch_value(
            "SELECT count(*) FROM {{tables.rate_buckets}} WHERE bucket='link.attempt'"
        )
        == 0
    )


async def test_duplicate_nonces_also_consume_the_committed_attempt_budget(db, session):
    request = _request(VALID["action-post"])
    await _authenticate(db, **request)
    for _ in range(239):
        with pytest.raises(LinkRefused, match="idempotency_conflict"):
            await _authenticate(db, **request)
    with pytest.raises(LinkRefused, match="safety_rate_limited"):
        await _authenticate(db, **request)
    assert await db.fetch_value("SELECT count(*) FROM {{tables.link_nonces}}") == 1
