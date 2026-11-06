"""Named submissions keep their original effect binding across definition edits."""

import copy
import hashlib
import json
from dataclasses import replace

from aweb_naapp.roles import principal_key

from aweb_secrets import records
from aweb_secrets.grant import GrantRecord
from aweb_secrets.operation import OperationTemplate
from aweb_secrets.policy import Policy
from tests.harness import running_upstream
from tests.test_admission import ALICE, POLICY_BODY, SECRET, TEAM
from tests.test_broker_audit import INSTALLATION
from tests.test_broker_audit import db as db
from tests.test_broker_audit import fence as fence
from tests.test_broker_service import setup, submission
from tests.test_operation_record import REFUND


def named(upstream, *, request_id="named-use", amount=10):
    original = submission(upstream)
    return replace(
        original,
        inbound=replace(
            original.inbound,
            body=json.dumps(
                {
                    "request_id": request_id,
                    "operation": "echo",
                    "params": {"label": "original", "amount": amount},
                }
            ).encode(),
        ),
    )


async def test_named_effects_are_pinned_but_terminal_replay_never_renders_an_edited_template(
    db, fence, tmp_path
):
    async with running_upstream(tmp_path) as upstream:
        service = await setup(db, fence, tmp_path, upstream)
        after = copy.deepcopy(REFUND)
        after.update(
            operation_id="echo",
            secret_id=SECRET["secret_id"],
            url={
                "host": "upstream.secrets.test",
                "port": upstream.port,
                "path": "/bearer/echo/{label}",
            },
            params={
                "label": {
                    "schema": {"type": "string", "minLength": 1, "maxLength": 20},
                    "charset": "base64url",
                    "placement": "path",
                },
                "amount": {
                    "schema": {"type": "integer", "minimum": 1, "maximum": 50},
                    "charset": None,
                    "placement": "body",
                },
            },
            body={"template": {"amount": {"$param": "amount"}}},
            headers={"fixed": {}, "allowed": []},
            response={
                "projection": ["/scheme", "/path", "/body_sha256", "/idempotency_key"],
                "max_bytes": 65536,
                "content_types": ["application/json"],
            },
        )
        operation = OperationTemplate.from_after(after)
        pin = {"operation_id": operation.operation_id, "digest": operation.digest}
        policy = Policy.from_body({**POLICY_BODY, "operations": [pin], "open_request": False})
        async with db.transaction() as tx:
            await records.create_operation(tx, INSTALLATION, TEAM, operation)
            await records.create_policy(tx, INSTALLATION, policy)
            await records.create_grant(
                tx,
                INSTALLATION,
                TEAM,
                GrantRecord.from_after(
                    {
                        "v": 1,
                        "grant_id": "grt_named001",
                        "secret_id": SECRET["secret_id"],
                        "subject": {"principal": principal_key(ALICE).principal_did},
                        "capability": "use",
                        "operations": [pin],
                        "open_request": False,
                        "jobs": [],
                        "policy_digest": policy.digest,
                    }
                ),
            )
        original = named(upstream)
        first = await service.submit(secret=SECRET["ref"], submission=original)
        assert first.status == 200 and first.body["state"] == "completed", (
            first.status,
            first.body.get("state"),
            first.body.get("code"),
        )
        result = json.loads(first.body["result"]["body"])
        assert result["/scheme"] == "bearer" and result["/path"] == "/bearer/echo/original"
        assert result["/body_sha256"] == hashlib.sha256(b'{"amount":10}').hexdigest()
        dispatch_id = await db.fetch_value("SELECT dispatch_id FROM {{tables.dispatches}}")
        assert result["/idempotency_key"] == f"secrets-{dispatch_id}"

        async with db.transaction() as tx:
            await records.create_operation(
                tx, INSTALLATION, TEAM, OperationTemplate.from_after({**after, "timeout_s": 19})
            )
        assert await service.submit(secret=SECRET["ref"], submission=original) == first
        changed = await service.submit(secret=SECRET["ref"], submission=named(upstream, amount=11))
        assert changed.status == 409 and changed.body["code"] == "idempotency_conflict"
        fresh = await service.submit(
            secret=SECRET["ref"], submission=named(upstream, request_id="new-use")
        )
        assert fresh.body["state"] == "refused" and fresh.body["code"] == "operation_not_allowed"
        assert upstream.paths == ["/bearer/echo/original"]
        assert await db.fetch_value("SELECT count(*) FROM {{tables.intents}}") == 1
