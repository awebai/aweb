"""Named pin discovery does not reveal definitions outside the caller's grant."""

import json
from dataclasses import replace

import pytest

from aweb_secrets import records
from tests.harness import running_upstream
from tests.test_admission import BOB, SECRET, TEAM
from tests.test_broker_audit import INSTALLATION
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
        reply = await service.submit(secret=secret, submission=caller)
        assert reply.status == 403 and reply.body == {
            "state": "refused",
            "request_id": "scope-probe",
            "code": "grant_missing",
        }, (reply.status, reply.body.get("code"))
        assert upstream.paths == []
        assert await db.fetch_value("SELECT count(*) FROM {{tables.intents}}") == 0
