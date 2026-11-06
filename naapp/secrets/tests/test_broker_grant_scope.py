"""Named pin discovery does not reveal definitions outside the caller's grant."""

import json
import re
from dataclasses import replace

import pytest

from aweb_secrets import records
from tests.harness import running_upstream
from tests.test_admission import BOB, SECRET, TEAM
from tests.test_broker_audit import INSTALLATION, envelopes
from tests.test_broker_audit import db as db
from tests.test_broker_audit import fence as fence
from tests.test_broker_operation import _template
from tests.test_broker_service import setup, submission


@pytest.mark.parametrize(
    "secret,operation",
    [(SECRET["ref"], "refund"), (SECRET["ref"], "unknown"), ("unknown-secret", "refund")],
)
async def test_ungranted_named_definition_is_indistinguishable_from_missing(
    db, fence, tmp_path, secret, operation
):
    async with running_upstream(tmp_path) as upstream:
        service = await setup(db, fence, tmp_path, upstream)
        async with db.transaction() as tx:
            await records.create_operation(tx, INSTALLATION, TEAM, _template(upstream))
        original = submission(upstream)
        caller = replace(
            original,
            authorization=replace(original.authorization, principal=BOB),
            inbound=replace(
                original.inbound,
                body=json.dumps(
                    {"request_id": "scope-probe", "operation": operation, "params": {}}
                ).encode(),
            ),
        )
        refs = []
        for _ in range(2):
            reply = await service.submit(secret=secret, submission=caller)
            # All three cases have exactly the same response fields and opaque
            # random reference shape; even identical probes are fresh attempts.
            ref = reply.body["use_ref"]
            assert re.fullmatch(r"use_[A-Za-z0-9_-]{22}", ref)
            assert reply.status == 403 and reply.body == {
                "state": "refused",
                "request_id": "scope-probe",
                "code": "grant_missing",
                "use_ref": ref,
            }, (reply.status, reply.body.get("code"))
            refs.append(ref)
        assert refs[0] != refs[1]

        events = [e for e in await envelopes(db) if e["hook"] == "post-secret-use-hook"]
        assert [e["payload"]["use_ref"] for e in events] == refs
        assert all(e["payload"]["action"] == "refused" for e in events)
        assert all(e["payload"]["refusal_code"] == "grant_missing" for e in events)
        rows = await db.fetch_all("SELECT correlation FROM {{tables.broker_use_events}}")
        assert sorted(json.loads(row["correlation"])["request_ref"] for row in rows) == sorted(refs)
        assert upstream.paths == []
        for table in ("intents", "dispatches", "idempotency_keys", "rate_buckets"):
            assert await db.fetch_value("SELECT count(*) FROM {{tables." + table + "}}") == 0
