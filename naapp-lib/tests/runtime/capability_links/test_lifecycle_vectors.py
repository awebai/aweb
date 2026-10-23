"""Frozen C4 sequences through the real signature verifier and database stores.

Stream steps belong to phase 4. Everything else in use_sequence, and every
receipt/nonce replay sequence, runs here.
"""

from __future__ import annotations

import base64
import hashlib
from datetime import datetime

import pytest
from awid.signing import canonical_json_bytes
from nacl.signing import SigningKey

from aweb_naapp.runtime.capability_links import (
    LinkRefused,
    Readable,
    authenticate,
)
from aweb_naapp.runtime.link_requests import sign_link_request

from . import test_lifecycle
from .conftest import CAPABILITY, CREATOR, REQUESTS, SCOPE, T0
from .test_lifecycle import (
    get_projection,
    holder,
    revoke_link,
    selection,
    submit,
)

ORIGIN = "https://pages.example.com"
action_app = test_lifecycle.action_app


async def signed_action(
    db,
    authority,
    action_app,
    caller,
    *,
    key="k1",
    nonce="n1",
    now=T0,
    origin=ORIGIN,
    csrf=None,
    record_id="b-17",
    issued_at=None,
):
    request = {
        "action_id": "mark-cleaned",
        "input": {"record_id": record_id},
        "expected_page_rev": 1,
        "expected_record_revs": {"bookings/b-17": 1},
        "idempotency_key": key,
    }
    raw = canonical_json_bytes(request)
    payload = {
        "v": 1,
        "type": "aweb.link-request",
        "link_id": caller.link_id,
        "session_id": caller.session_id,
        "method": "POST",
        "path": f"/v1/pages/{SCOPE.page_id}/actions",
        "body_sha256": hashlib.sha256(raw).hexdigest(),
        "nonce": hashlib.sha256(nonce.encode()).hexdigest()[:32],
        "issued_at": (issued_at or now).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    signing_key = SigningKey(bytes.fromhex(REQUESTS["keys"]["session"]["seed_hex"]))
    signature = sign_link_request(payload, signing_key)
    header = base64.urlsafe_b64encode(canonical_json_bytes(payload)).rstrip(b"=").decode()
    verified = await authenticate(
        db,
        authorization=f"AWEB-Link-Request {caller.session_id} {signature}",
        signed_payload=header,
        method="POST",
        target=payload["path"],
        body=raw,
        origin=origin,
        csrf=csrf,
        app_origin=ORIGIN,
        now=now,
    )
    assert verified == caller
    return await submit(db, authority, action_app, verified, key=key, now=now, record_id=record_id)


@pytest.fixture
async def signed_holder(db, authority):
    caller = await holder(db, authority)
    # The secret is deliberately never read back from the database. Exchange
    # generated the CSRF, so give this test session a known test-only token.
    await db.execute(
        "UPDATE {{tables.link_sessions}} SET csrf_sha256=$1 WHERE session_id=$2",
        hashlib.sha256(b"test-csrf").digest(),
        caller.session_id,
    )
    return caller


async def test_use_sequence(db, authority, action_app, signed_holder):
    caller = signed_holder
    receipts = {}
    for index, step in enumerate(CAPABILITY["use_sequence"]):
        kind = step["step"]
        if kind in {"exchange", "stream_open", "stream_check"}:
            # Exchange cases run in test_exchange; streams are phase 4.
            continue
        if kind == "creator_loses_field":
            old = authority.reads[CREATOR]["bookings"]
            authority.reads[CREATOR]["bookings"] = Readable(
                old.records, old.fields - {step["field"]}
            )
            continue
        if kind == "creator_loses_record":
            old = authority.reads[CREATOR]["bookings"]
            authority.reads[CREATOR]["bookings"] = Readable(
                tuple(r for r in old.records if r != step["record_id"]), old.fields
            )
            continue
        try:
            if kind == "read":
                await get_projection(db, authority, caller, projection=selection(*step["fields"]))
            elif kind == "revoke":
                await revoke_link(db, caller)
            elif kind == "action":
                receipt = await signed_action(
                    db,
                    authority,
                    action_app,
                    caller,
                    key=step["idempotency_key"],
                    nonce=step["nonce"],
                    record_id=step["input"]["record_id"],
                    origin=step.get("origin", ORIGIN),
                    csrf="test-csrf"
                    if "csrf" not in step
                    else None
                    if step["csrf"] == "missing"
                    else "wrong",
                )
                receipts[index] = receipt
                if "same_receipt_as" in step["result"]:
                    assert receipt == receipts[step["result"]["same_receipt_as"]]
            else:
                raise AssertionError(kind)
        except LinkRefused as refused:
            assert {"status": refused.status, "code": refused.code} == step["result"], (index, step)
        else:
            assert step["result"]["status"] == 200, (index, step)


@pytest.mark.parametrize("case", CAPABILITY["replay_cases"], ids=lambda c: c["name"])
async def test_replay_sequences(db, authority, action_app, case):
    caller = await holder(db, authority, one_use=case.get("one_use", False))
    await db.execute(
        "UPDATE {{tables.link_sessions}} SET csrf_sha256=$1 WHERE session_id=$2",
        hashlib.sha256(b"test-csrf").digest(),
        caller.session_id,
    )
    receipts = {}
    prior = None
    for step in case["steps"]:
        now = datetime.fromisoformat(step["at"].replace("Z", "+00:00"))
        if step.get("revoke"):
            await revoke_link(db, caller, now=now)
            continue
        if step.get("session_expires"):
            continue  # the session's original 15-minute expiry needs no mutation
        if "concurrent" in step:
            import asyncio

            async def attempt(now=now):
                try:
                    await signed_action(
                        db, authority, action_app, caller, now=now, csrf="test-csrf"
                    )
                    return 200
                except LinkRefused as refused:
                    assert refused.code == "idempotency_conflict"
                    return refused.status

            assert sorted(await asyncio.gather(attempt(), attempt())) == [200, 409]
            continue
        args = dict(
            key=step.get("action", "k1"),
            nonce=step.get("nonce", "n1"),
            now=now,
            record_id="b-18"
            if step.get("violates_constraint") or step.get("same_body") is False
            else "b-17",
            csrf="test-csrf",
        )
        if step.get("same_signed_request_again"):
            args = {**prior, "now": now, "issued_at": prior["now"]}
        else:
            prior = args
        try:
            receipt = await signed_action(db, authority, action_app, caller, **args)
        except LinkRefused as refused:
            assert {"status": refused.status, "code": refused.code} == step["result"]
        else:
            assert step["result"]["status"] == 200
            receipt_name = step["result"]["receipt"]
            if receipt_name in receipts:
                assert receipt == receipts[receipt_name]
            receipts[receipt_name] = receipt


async def test_a_failed_app_write_keeps_the_authenticated_nonce(
    db, authority, action_app, signed_holder
):
    action_app.fail = True
    with pytest.raises(RuntimeError, match="app failed"):
        await signed_action(db, authority, action_app, signed_holder, csrf="test-csrf")
    assert await db.fetch_value("SELECT count(*) FROM {{tables.link_nonces}}") == 1
    assert await db.fetch_value("SELECT count(*) FROM {{tables.test_link_actions}}") == 0
    action_app.fail = False
    with pytest.raises(LinkRefused, match="idempotency_conflict"):
        await signed_action(db, authority, action_app, signed_holder, csrf="test-csrf")
    await signed_action(db, authority, action_app, signed_holder, csrf="test-csrf", nonce="new")
