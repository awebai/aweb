"""aweb-adbb D2f: the page asks which of its saved selections are final.

A tab keeps the removal it started until that operation is final. The owner
page shows one bounded page of History, so the page asks, by exact id, which
of the operations it holds are final in its own authorized scope: only a
stored commit or refusal counts, never a signed-but-unconfirmed row, a row of
another scope, or an id the signer does not hold."""

import json
import uuid
from datetime import timedelta

import pytest

from tests.test_protected_admission_native import admissions as admissions  # noqa: F401
from tests.test_protected_owner_initiation_native import owner_http, selection
from tests.test_protected_owner_removal_native import legacy_member

pytest_plugins = ("tests.test_independent_protected_signer",)

FINAL = "/governance/operations/final"


@pytest.mark.asyncio
async def test_only_a_stored_final_outcome_in_this_scope_is_reported_final(admissions, tmp_path, monkeypatch):
    a = admissions
    _, certificate = await legacy_member(a, "unknown")
    body = selection(certificate)
    async with owner_http(a, tmp_path) as (client, headers, _):
        signer = a.w.app.signer
        signer.mailed_approval_wait = timedelta(seconds=30)
        assert (await client.post("/governance/operations", json=body, headers=headers)).status_code == 200
        held, unknown = body["operation_id"], str(uuid.uuid4())

        # Waiting for a decision, and past its expiry by the clock only: not final.
        answer = await client.post(FINAL, json={"operation_ids": [held, unknown]}, headers=headers)
        assert answer.status_code == 200 and answer.json() == {"final": []}, answer.text

        # The signer stores the unsigned expiry as its final refusal.
        row = await a.w.db.fetch_one(
            "SELECT expires_at FROM {{tables.protected_signer_operations}} WHERE operation_id=$1", held)
        expired = row["expires_at"] + timedelta(seconds=1)
        monkeypatch.setattr(signer, "clock", lambda: expired)
        assert (await client.post("/governance/operations", json=body, headers=headers)).status_code == 410
        answer = await client.post(FINAL, json={"operation_ids": [held, unknown]}, headers=headers)
        assert answer.json() == {"final": [held]}, answer.text

        # The same row in another scope is not this owner's to retire.
        scope = json.loads(await a.w.db.fetch_value(
            "SELECT scope::text FROM {{tables.protected_signer_operations}} WHERE operation_id=$1", held))
        await a.w.db.execute("UPDATE {{tables.protected_signer_operations}} SET scope=$2::jsonb WHERE operation_id=$1",
                             held, json.dumps({**scope, "service_id": "another-service"}))
        answer = await client.post(FINAL, json={"operation_ids": [held]}, headers=headers)
        assert answer.json() == {"final": []}, answer.text


@pytest.mark.asyncio
@pytest.mark.parametrize("ids", [["not-an-id"], [str(uuid.uuid4()).upper()], "one", [],
                                 [str(uuid.uuid4()) for _ in range(51)]])
async def test_a_malformed_lookup_is_refused(admissions, tmp_path, ids):
    async with owner_http(admissions, tmp_path) as (client, headers, _):
        answer = await client.post(FINAL, json={"operation_ids": ids}, headers=headers)
        assert (answer.status_code, answer.json()) == (400, {"detail": "request_invalid"}), answer.text


@pytest.mark.asyncio
async def test_the_lookup_needs_the_signed_in_owner(admissions, tmp_path):
    async with owner_http(admissions, tmp_path) as (client, headers, _):
        client.cookies.clear()  # no console session
        answer = await client.post(FINAL, json={"operation_ids": [str(uuid.uuid4())]}, headers=headers)
        assert answer.status_code == 401, answer.text
