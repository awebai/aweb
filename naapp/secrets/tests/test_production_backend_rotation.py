"""Version changes cross the real broker and runner production boundaries."""

import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from uuid import uuid4

import pytest
from aweb_naapp.egress import InternalDestinations
from aweb_naapp.hooks.strictjson import encode_base64url
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from nacl.signing import SigningKey

from aweb_secrets import jobs, records, runners
from aweb_secrets.destination import DestinationRecord
from aweb_secrets.grant import GrantRecord
from aweb_secrets.policy import Policy
from aweb_secrets.revisions import config_revision
from tests.custody.test_onepassword import field, sdk_item
from tests.production_backend import backend_secret as backend_secret
from tests.test_jobs import after as job_after
from tests.test_production_bootstrap import envelopes
from tests.test_production_bootstrap import root as root
from tests.test_production_reconciliation import member_request
from tests.test_production_reconciliation import production_settings as production_settings
from tests.test_production_reconciliation import upstream as upstream
from tests.test_production_runner_dispatch import runner_headers
from tests.test_use_approvals import POLICY_BODY


class Execution(StrEnum):
    BROKER = "broker"
    RUNNER = "runner"


@dataclass(kw_only=True, repr=False)
class RegisteredRunner:
    runner_id: str
    runner_signing_key: SigningKey


async def register_runner(root, *, record):
    service, _, _, member, installed, *_ = root
    definition = job_after()
    definition["credentials"][0]["secret_ref"] = record.ref
    definition["env"] = {"DB_ADMIN": {"$credential": record.ref, "field": "value"}}
    job = jobs.JobDefinition.from_after(definition)
    runner_id = job.after["runner_ids"][0]
    signing = SigningKey.generate()
    encryption = X25519PrivateKey.generate()
    async with service.runtime.db().transaction() as tx:
        await jobs.create_job(tx, installed["installation_id"], member.team_id, job)
        code = await runners.create_runner(
            tx,
            installed["installation_id"],
            member.team_id,
            runners.RunnerRecord.from_after(
                {
                    "v": 1,
                    "runner_id": runner_id,
                    "label": "Version test",
                    "allowed_jobs": [job.job_id],
                }
            ),
            now=datetime.now(UTC),
        )
        from awid.did import did_from_public_key

        await runners.register_runner(
            tx,
            code=code,
            signing_key=did_from_public_key(bytes(signing.verify_key)),
            encryption_key=encode_base64url(encryption.public_key().public_bytes_raw()),
        )
    return job, RegisteredRunner(runner_id=runner_id, runner_signing_key=signing)


async def configure_execution(root, *, record, upstream, execution: Execution):
    service, _, _, member, installed, *_ = root
    server, state = upstream
    state["drop"] = False
    policy = Policy.from_body({**POLICY_BODY, "approval": "none", "approvers": []})
    runner = None
    allowed_jobs = []
    path = "/v1/secrets/" + record.ref + "/requests"
    body = {"method": "POST", "url": f"https://{server.host}:{server.port}/effect", "data": "probe"}
    if execution is Execution.RUNNER:
        job, runner = await register_runner(root, record=record)
        allowed_jobs = [{"job_id": job.job_id, "digest": job.digest}]
        path = "/v1/jobs/" + job.job_id + "/runs"
        body = {"runner": runner.runner_id, "params": {"database": "orders"}}
    async with service.runtime.db().transaction() as tx:
        await records.create_policy(
            tx, installed["installation_id"], policy, team_id=member.team_id
        )
        await records.create_grant(
            tx,
            installed["installation_id"],
            member.team_id,
            GrantRecord.from_after(
                {
                    "v": 1,
                    "grant_id": "grt_backend_rotation",
                    "secret_id": record.secret_id,
                    "subject": {"principal": member.extra_cert_fields["member_did_aw"]},
                    "capability": "use" if execution is Execution.BROKER else "run",
                    "operations": [],
                    "open_request": execution is Execution.BROKER,
                    "jobs": allowed_jobs,
                    "policy_digest": policy.digest,
                }
            ),
        )
        if execution is Execution.BROKER:
            await records.create_destination(
                tx,
                installed["installation_id"],
                member.team_id,
                DestinationRecord.from_after(
                    {
                        "v": 1,
                        "destination_id": "dst_backend_rotation",
                        "secret_id": record.secret_id,
                        "scheme": "https",
                        "host": server.host,
                        "port": server.port,
                        "path": "/**",
                        "methods": ["POST"],
                        "query_rules": {},
                        "header_allow": [],
                        "network": "internal",
                        "cidr": server.host + "/32",
                    },
                    internal_destinations=InternalDestinations.ALLOWED,
                ),
            )
    return path, body, runner


@pytest.mark.parametrize("execution", list(Execution))
async def test_changed_sdk_item_refuses_the_observing_attempt_and_only_a_fresh_request_uses_it(
    root, backend_secret, upstream, execution
):
    service, client, configured, member, installed, *_ = root
    item, record = backend_secret
    path, body, runner = await configure_execution(
        root, record=record, upstream=upstream, execution=execution
    )
    db = service.runtime.db()
    revision = await config_revision(db, installed["installation_id"], team_id=member.team_id)
    original_id = uuid4().hex
    if execution is Execution.RUNNER:
        admitted = await member_request(root, path, {**body, "request_id": original_id})
        assert admitted.status_code == 202 and admitted.json()["state"] == "admitted"
    item.current = sdk_item(
        [field("credential", secrets.token_urlsafe(32))],
        id=item.current.id,
        vault_id=item.current.vault_id,
        version=8,
    )
    if execution is Execution.BROKER:
        first = await member_request(root, path, {**body, "request_id": original_id})
    else:
        claim = await client.post(
            configured.public_origin + "/runner/v1/claim",
            content=b"{}",
            headers=runner_headers(runner, configured.public_origin, "/runner/v1/claim"),
        )
        assert claim.status_code == 503
        assert claim.json() == {"detail": {"code": "runner_unavailable"}}
        status_path = "/v1/status/" + admitted.json()["request_ref"]
        first = await client.get(
            configured.public_origin + status_path,
            headers=member.headers(aud=configured.public_origin, method="GET", path=status_path),
        )
    assert first.json()["state"] == "refused" and first.json()["code"] == "secret_version_changed"
    assert first.json()["next_step"] == {"action": "start_new_request"}
    assert (
        await db.fetch_value(
            "SELECT active_version FROM secrets WHERE secret_id=$1", record.secret_id
        )
        == 2
    )
    assert (
        await config_revision(db, installed["installation_id"], team_id=member.team_id)
        == revision + 1
    )
    observed = [
        event
        for event in await envelopes(db, member.team_id)
        if event["payload"].get("act") == "resource.version_observed"
    ]
    assert len(observed) == 1
    replay = await member_request(root, path, {**body, "request_id": original_id})
    assert replay.json()["state"] == "refused", (
        "the original admission must not acquire the new version"
    )
    assert len(upstream[0].seen) == 0
    fresh = await member_request(root, path, {**body, "request_id": uuid4().hex})
    if execution is Execution.BROKER:
        assert fresh.status_code == 200 and fresh.json()["state"] == "completed"
        assert len(upstream[0].seen) == 1
    else:
        assert fresh.status_code == 202 and fresh.json()["state"] == "admitted"
        claimed = await client.post(
            configured.public_origin + "/runner/v1/claim",
            content=b"{}",
            headers=runner_headers(runner, configured.public_origin, "/runner/v1/claim"),
        )
        assert claimed.status_code == 200
        assert (
            await db.fetch_value("SELECT count(*) FROM run_deliveries WHERE assignment IS NOT NULL")
            == 1
        )
