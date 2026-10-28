"""Real PG, custody, registered runner and passkey world for S13 run tests."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta

from aweb_naapp.dispatch import apply_dispatch_migrations
from aweb_naapp.egress import InternalDestinations
from aweb_naapp.hooks.commitment import CommitmentKey, Purpose, RequestBytes
from aweb_naapp.hooks.producer import HookProducer, ServerProducer
from aweb_naapp.hooks.strictjson import encode_base64url
from aweb_naapp.nonces import apply_nonce_migrations
from aweb_naapp.runtime.approvals import Approvals, PgApprovalStore
from aweb_naapp.runtime.authorization import Authorization, DeclaredTool
from aweb_naapp.runtime.installation import InstallationFence
from awid.did import did_from_public_key
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from nacl.signing import SigningKey

from aweb_secrets import jobs, records, runners
from aweb_secrets.custody import apply_custody_migrations, encode_value
from aweb_secrets.custody.opening import UseSecretOpener
from aweb_secrets.grant import GrantRecord
from aweb_secrets.member_types import MemberSubmission
from aweb_secrets.policy import Policy
from aweb_secrets.response_audit import ResponseKey
from aweb_secrets.run_context import apply_run_dispatch_migrations
from aweb_secrets.runner_protocol import canonical
from aweb_secrets.runner_types import RunnerSubmission
from aweb_secrets.secret import SecretRecord
from aweb_secrets.use_approvals import UseApprovers, UsePolicies
from aweb_secrets.use_audit import UseApprovalAudit
from aweb_secrets.use_context import UseCommitter, apply_use_context_migrations
from tests.test_change_sets import Installations
from tests.test_jobs import after
from tests.test_use_approvals import POLICY_BODY, REQUESTER, SECRET, TEAM, designate
from tests.test_use_approvals import uses as uses
from tests.test_use_approvals import world as world
from tests.test_use_audit import targets

ORIGIN = "https://secrets.example.com"
RUN = DeclaredTool(
    "run", "POST", "/v1/jobs/{job}/runs", frozenset({"secrets:run"}), frozenset({"agent"})
)


@dataclass(repr=False)
class RunWorld:
    uses: object
    job: jobs.JobDefinition
    runner: runners.RunnerRecord
    signing_key: SigningKey
    encryption_key: X25519PrivateKey
    credential: str
    arguments: dict
    submission: MemberSubmission
    available: list[bool]
    origin: str = ORIGIN

    def signed(self, target, body=b"{}", *, key=None):
        key = key or self.signing_key
        payload = canonical(
            {
                "v": 1,
                "type": "aweb.secrets.runner-request",
                "origin": self.origin,
                "runner_id": self.runner.runner_id,
                "kid": did_from_public_key(bytes(key.verify_key)),
                "method": "POST",
                "path": target,
                "body_sha256": hashlib.sha256(body).hexdigest(),
                "timestamp": self.uses.clock().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "nonce": secrets.token_urlsafe(16),
            }
        )
        signature = key.sign(b"aweb.secrets.runner-request/1\n" + payload).signature
        return RunnerSubmission(
            encode_base64url(payload) + "." + encode_base64url(signature),
            "POST",
            target,
            body,
        )


class RunInstallations(Installations):
    @property
    def grant(self):
        return replace(
            super().grant, scopes=frozenset({"secrets:use", "secrets:run", "secrets:read"})
        )


async def setup(uses, *, approval_required=False, producer_clock=None):
    db, scope = uses.world.db, uses.world.admitted
    for migration in (
        apply_dispatch_migrations,
        apply_nonce_migrations,
        apply_custody_migrations,
        jobs.apply_job_migrations,
        runners.apply_runner_migrations,
        apply_use_context_migrations,
        apply_run_dispatch_migrations,
    ):
        await migration(db)
    if approval_required:
        await designate(uses, "finance", "finance@acme.com")
    body = after()
    body["credentials"][0]["secret_ref"] = SECRET["ref"]
    body["env"] = {"DB_ADMIN": {"$credential": SECRET["ref"], "field": "value"}}
    body["output"]["projection"] = ["/exit_code", "/stderr", "/stdout"]
    job = jobs.JobDefinition.from_after(body)
    policy = Policy.from_body(
        {
            **POLICY_BODY,
            "approval": "per_use" if approval_required else "none",
            "approvers": ["finance"] if approval_required else [],
        }
    )
    credential = secrets.token_urlsafe(32)
    signing_key, encryption_key = SigningKey.generate(), X25519PrivateKey.generate()
    runner = runners.RunnerRecord.from_after(
        {
            "v": 1,
            "runner_id": job.after["runner_ids"][0],
            "label": "Durable acceptance",
            "allowed_jobs": [job.job_id],
        }
    )
    async with db.transaction() as tx:
        await records.create_policy(tx, scope.installation_id, policy)
        await records.create_secret(
            tx, scope.installation_id, TEAM, SecretRecord.from_after(SECRET)
        )
        version = await uses.world.custody.sealer.ingest(
            tx,
            installation_id=scope.installation_id,
            team_id=TEAM,
            secret_id=SECRET["secret_id"],
            value=encode_value("bearer", {"value": credential}),
        )
        await records.set_active_version(
            tx, scope.installation_id, TEAM, SECRET["secret_id"], version
        )
        await records.create_grant(
            tx,
            scope.installation_id,
            TEAM,
            GrantRecord.from_after(
                {
                    "v": 1,
                    "grant_id": "grt_durable001",
                    "secret_id": SECRET["secret_id"],
                    "subject": {"principal": REQUESTER.did_aw},
                    "capability": "run",
                    "operations": [],
                    "open_request": False,
                    "jobs": [{"job_id": job.job_id, "digest": job.digest}],
                    "policy_digest": policy.digest,
                }
            ),
        )
        await jobs.create_job(tx, scope.installation_id, TEAM, job)
        code = await runners.create_runner(
            tx, scope.installation_id, TEAM, runner, now=uses.clock()
        )
        await runners.register_runner(
            tx,
            code=code,
            signing_key=did_from_public_key(bytes(signing_key.verify_key)),
            encryption_key=encode_base64url(encryption_key.public_key().public_bytes_raw()),
            clock=uses.clock,
        )
    seed = secrets.token_bytes(32)
    # S3 transition timestamps come from PostgreSQL's live clock. The frozen
    # policy/runner clock cannot measure their age on a loaded test host.
    producer_clock = producer_clock or (lambda: datetime.now(UTC))

    def producer(*, installation_id, generation):
        return HookProducer(
            ServerProducer.app(
                origin=ORIGIN,
                app_id="secrets",
                installation_id=installation_id,
                generation=generation,
                kid="run-dispatch-acceptance",
                seed=seed,
            ),
            clock=producer_clock,
        )

    store = PgApprovalStore(db)

    async def approval(tx, approval_id):
        return await store.get_in(approval_id, tx)

    audit = UseApprovalAudit(
        producer=producer,
        passkeys=lambda: uses.world.passkeys,
        approval=approval,
        max_backlog_age=timedelta(minutes=5),
        clock=uses.clock,
        enable_runs=True,
    )
    approvals = Approvals(
        store=store,
        policies=UsePolicies(db),
        approvers=UseApprovers(db, uses.world.passkeys, uses.world.directory),
        delivery=uses.world.inbox,
        authenticators=[uses.world.passkeys.authenticator()],
        audit=audit,
        clock=uses.clock,
    )

    available = [True]

    async def registration_view(team_id):
        assert team_id == TEAM
        return targets(uses.clock()) if available[0] else None

    arguments = dict(
        fence=InstallationFence(db, app_id="secrets", grants=RunInstallations()),
        opener=UseSecretOpener(
            db,
            native=uses.world.custody.opener,
            credential_opener=uses.world.custody.backend_credential_opener,
        ),
        committer=UseCommitter(
            CommitmentKey(Purpose.SECRET_REQUEST, secrets.token_bytes(32)),
            CommitmentKey(Purpose.SECRET_PARAMS, secrets.token_bytes(32)),
        ),
        response_key=ResponseKey(secrets.token_bytes(32)),
        service_key=SigningKey.generate(),
        origin=ORIGIN,
        producer=producer,
        registration_view=registration_view,
        approvals=approvals,
        use_audit=audit,
        passkeys=uses.world.passkeys,
        max_backlog_age=timedelta(minutes=5),
        assignment_ttl=timedelta(seconds=30),
        sweep_margin=timedelta(seconds=5),
        claim_wait=timedelta(0),
        derived_max_ttl_s=3600,
        internal_destinations=InternalDestinations.DISABLED,
        clock=uses.clock,
    )
    submission = MemberSubmission(
        Authorization(REQUESTER, RUN, replace(uses.grant, scopes=frozenset({"secrets:run"}))),
        RequestBytes(
            "POST",
            f"/v1/jobs/{job.job_id}/runs".encode(),
            (b"application/json",),
            canonical(
                {
                    "request_id": "durable-1",
                    "runner": runner.runner_id,
                    "params": {"database": "orders"},
                }
            ),
        ),
    )
    return RunWorld(
        uses,
        job,
        runner,
        signing_key,
        encryption_key,
        credential,
        arguments,
        submission,
        available,
    )
