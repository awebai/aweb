#!/usr/bin/env python3
"""Disposable topology-harness consumer of the strict federation authority core.

This is copied into test-only aweb containers by the federation conformance
harness. It never exposes an ingress route and never contains key material.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import ssl
from dataclasses import asdict
from uuid import uuid4

from aweb.federation.authority import AuthorityClaim, FederationAuthorityCore
from aweb.federation.authority_state import (
    AddressAuthorityCandidate,
    AuthorityRepository,
    CheckpointCandidate,
)
from aweb.federation.authority_work import AuthorityWorkRepository
from awid.db_config import build_database_config
from awid.did import did_from_public_key, generate_keypair, stable_id_from_did_key
from awid.external_authority import DNSLookup, OriginContext, compare_claim_to_evidence
from awid.external_registry import StrictExternalRegistry, SystemHostResolver
from awid.federation_errors import FederationAuthorityError
from awid.log import identity_state_hash, log_entry_payload
from awid.signing import sign_message
from pgdbm import AsyncDatabaseManager
from redis.asyncio import Redis


class RecordedDNS:
    def __init__(self, domain: str, controller_did: str, registry_origin: str) -> None:
        self.domain = domain
        self.controller_did = controller_did
        self.registry_origin = registry_origin
        self.queries: list[str] = []

    async def lookup_txt(self, name: str) -> DNSLookup:
        self.queries.append(name)
        if name != "_awid." + self.domain:
            return DNSLookup("nxdomain")
        record = (
            f"awid=v1; controller={self.controller_did}; "
            f"registry={self.registry_origin};"
        )
        return DNSLookup("record", (record,))


class RecordedHosts:
    def __init__(self) -> None:
        self.delegate = SystemHostResolver()
        self.queries: list[str] = []
        self.answers: list[tuple[str, ...]] = []

    async def resolve_all(self, hostname: str) -> tuple[str, ...]:
        self.queries.append(hostname)
        answers = await self.delegate.resolve_all(hostname)
        self.answers.append(answers)
        return answers


async def process_barrier(name: str, role: str, participants: int) -> None:
    """Release test processes together; Redis is only a disposable barrier."""
    redis = Redis.from_url(os.environ["AWEB_REDIS_URL"], decode_responses=True)
    ready = f"federation-harness:{name}:ready"
    release = f"federation-harness:{name}:release"
    try:
        await redis.sadd(ready, role)
        for _ in range(200):
            if await redis.scard(ready) >= participants:
                await redis.set(release, "1", ex=30)
            if await redis.exists(release):
                return
            await asyncio.sleep(0.025)
        raise RuntimeError("process barrier timed out")
    finally:
        await redis.aclose()


def strict_resolver() -> tuple[StrictExternalRegistry, RecordedDNS, RecordedHosts]:
    dns = RecordedDNS(
        os.environ["HARNESS_DOMAIN"],
        os.environ["HARNESS_CONTROLLER_DID"],
        os.environ["HARNESS_REGISTRY_ORIGIN"],
    )
    hosts = RecordedHosts()
    tls = ssl.create_default_context(cafile=os.environ["HARNESS_CA_FILE"])
    resolver = StrictExternalRegistry(
        txt_resolver=dns,
        host_resolver=hosts,
        origin_context=OriginContext(
            app_env="development",
            federation_test_enabled=True,
            listener_origin=os.environ["AWEB_PUBLIC_ORIGIN"],
        ),
        ssl_context=tls,
    )
    return resolver, dns, hosts


def checkpoint(
    did_aw: str,
    *,
    seq: int,
    variant: str,
    expected_revision: int | None,
) -> CheckpointCandidate:
    previous = (
        hashlib.sha256(f"{did_aw}:{seq - 1}:winner:entry".encode()).hexdigest()
        if expected_revision is not None
        else None
    )
    return CheckpointCandidate(
        did_aw=did_aw,
        seq=seq,
        entry_hash=hashlib.sha256(
            f"{did_aw}:{seq}:{variant}:entry".encode()
        ).hexdigest(),
        state_hash=hashlib.sha256(
            f"{did_aw}:{seq}:{variant}:state".encode()
        ).hexdigest(),
        current_did_key=os.environ["HARNESS_DID_KEY"],
        contains_snapshot=seq > 1,
        expected_revision=expected_revision,
        expected_entry_hash=previous,
    )


def cohort(
    candidate: CheckpointCandidate,
    *,
    checkpoint_revision: int,
    publishing_fence: int,
) -> AddressAuthorityCandidate:
    return AddressAuthorityCandidate(
        canonical_address=os.environ["HARNESS_ADDRESS"],
        authority_selection="dns",
        authority_name="_awid." + os.environ["HARNESS_DOMAIN"],
        controller_did=os.environ["HARNESS_CONTROLLER_DID"],
        authority_statement_version="aweb.federation-authority.dns.v1",
        authority_statement_digest="sha256:" + "a" * 64,
        inherited=False,
        registry_explicit=True,
        registry_origin=os.environ["HARNESS_REGISTRY_ORIGIN"],
        address_id="disposable-harness-address",
        bound_did_aw=candidate.did_aw,
        bound_current_did_key=candidate.current_did_key,
        checkpoint_seq=candidate.seq,
        checkpoint_entry_hash=candidate.entry_hash,
        checkpoint_revision=checkpoint_revision,
        authoritative_delivery_origin=os.environ["HARNESS_DELIVERY_ORIGIN"],
        publishing_fence=publishing_fence,
        reuse_seconds=60,
    )


def generate_identity() -> dict[str, object]:
    """Build one valid runtime-only identity-log fixture without exporting its key."""
    signing_key, public_key = generate_keypair()
    _, rotated_public_key = generate_keypair()
    did_key = did_from_public_key(public_key)
    rotated_did_key = did_from_public_key(rotated_public_key)
    did_aw = stable_id_from_did_key(did_key)
    first_entry = {
        "did_aw": did_aw,
        "seq": 1,
        "operation": "register_did",
        "previous_did_key": None,
        "new_did_key": did_key,
        "prev_entry_hash": None,
        "state_hash": identity_state_hash(did_aw=did_aw, current_did_key=did_key),
        "authorized_by": did_key,
        "timestamp": "2026-08-01T00:00:00Z",
    }
    first_payload = log_entry_payload(**first_entry)
    first_hash = hashlib.sha256(first_payload).hexdigest()
    second_entry = {
        "did_aw": did_aw,
        "seq": 2,
        "operation": "rotate_key",
        "previous_did_key": did_key,
        "new_did_key": rotated_did_key,
        "prev_entry_hash": first_hash,
        "state_hash": identity_state_hash(
            did_aw=did_aw, current_did_key=rotated_did_key
        ),
        "authorized_by": did_key,
        "timestamp": "2026-08-01T00:05:00Z",
    }
    second_payload = log_entry_payload(**second_entry)
    return {
        "mapping": {
            "did_aw": did_aw,
            "initial_did_key": did_key,
            "rotated_did_key": rotated_did_key,
        },
        "entries": [
            {
                "entry_payload": first_entry,
                "entry_hash": first_hash,
                "signature_b64": sign_message(signing_key, first_payload),
            },
            {
                "entry_payload": second_entry,
                "entry_hash": hashlib.sha256(second_payload).hexdigest(),
                "signature_b64": sign_message(signing_key, second_payload),
            },
        ],
    }


async def run(args: argparse.Namespace) -> dict[str, object]:
    config = build_database_config(
        connection_string=os.environ["AWEB_DATABASE_URL"],
        min_connections=1,
        max_connections=2,
    )
    pool = await AsyncDatabaseManager.create_shared_pool(config)
    db = AsyncDatabaseManager(pool=pool, schema="aweb")
    repository = AuthorityRepository(db)
    core = FederationAuthorityCore(repository)
    try:
        if args.action == "resolve":
            resolver, dns, hosts = strict_resolver()
            claim = AuthorityClaim(
                canonical_address=os.environ["HARNESS_ADDRESS"],
                did_aw=os.environ["HARNESS_DID_AW"],
                current_did_key=os.environ["HARNESS_DID_KEY"],
                delivery_origin=os.environ["HARNESS_DELIVERY_ORIGIN"],
            )
            try:
                token = await core.resolve_and_commit(
                    claim,
                    resolver,
                    authority_generation=args.generation,
                    publishing_fence=args.generation,
                )
            finally:
                await resolver.aclose()
            return {
                "status": "resolved",
                "token": asdict(token),
                "dns_queries": dns.queries,
                "host_queries": hosts.queries,
                "approved_answers": hosts.answers,
            }
        if args.action == "singleflight":
            await process_barrier(args.barrier, args.role, 2)
            work = AuthorityWorkRepository(db)
            lease = await work.acquire_lease(
                args.scope, owner_id=uuid4(), ttl_seconds=30
            )
            chain_count = 0
            if lease.acquired:
                resolver, dns, _hosts = strict_resolver()
                try:
                    evidence = await resolver.fetch_evidence(
                        os.environ["HARNESS_ADDRESS"],
                        authority_generation=args.generation,
                    )
                finally:
                    await resolver.aclose()
                chain_count = len(dns.queries)
                await work.publish_result(
                    lease,
                    status="verified_evidence",
                    evidence=evidence.claim_evidence(),
                    ttl_seconds=30,
                )
            shared = await work.wait_for_result(args.scope, deadline_seconds=5)
            if shared is None:
                raise RuntimeError("singleflight result was not published")
            claim_did = (
                os.environ["HARNESS_DID_AW"]
                if args.claim == "correct"
                else "did:aw:wrong-claim"
            )
            try:
                compare_claim_to_evidence(
                    shared.evidence,
                    did_aw=claim_did,
                    current_did_key=os.environ["HARNESS_DID_KEY"],
                    delivery_origin=os.environ["HARNESS_DELIVERY_ORIGIN"],
                )
            except FederationAuthorityError as exc:
                return {
                    "status": "claim_rejected",
                    "claim": args.claim,
                    "reason": exc.reason,
                    "lease_leader": lease.acquired,
                    "authority_chain_count": chain_count,
                }
            return {
                "status": "claim_authorized",
                "claim": args.claim,
                "lease_leader": lease.acquired,
                "authority_chain_count": chain_count,
            }
        if args.action == "verify":
            token = await core.authorize_from_shared_cohort(
                AuthorityClaim(
                    canonical_address=os.environ["HARNESS_ADDRESS"],
                    did_aw=os.environ["HARNESS_DID_AW"],
                    current_did_key=os.environ["HARNESS_DID_KEY"],
                    delivery_origin=os.environ["HARNESS_DELIVERY_ORIGIN"],
                )
            )
            if token is None:
                raise RuntimeError("shared cohort did not authorize")
            return {"status": "authorized", "token": asdict(token)}
        if args.action == "seed":
            candidate = checkpoint(
                os.environ["HARNESS_DID_AW"],
                seq=1,
                variant="winner",
                expected_revision=None,
            )
            token = await repository.commit_phase_a(
                candidate,
                cohort(candidate, checkpoint_revision=1, publishing_fence=1),
            )
            return {"status": "seeded", "token": asdict(token)}
        if args.action == "fork":
            candidate = checkpoint(
                os.environ["HARNESS_DID_AW"],
                seq=2,
                variant=args.variant,
                expected_revision=1,
            )
            token = await repository.commit_phase_a(
                candidate,
                cohort(candidate, checkpoint_revision=2, publishing_fence=2),
            )
            return {
                "status": "fork_winner",
                "variant": args.variant,
                "token": asdict(token),
            }
        if args.action == "permit-fill":
            work = AuthorityWorkRepository(db)
            for _ in range(args.count):
                await work.acquire_permits(
                    owner_id=uuid4(),
                    scopes=((args.kind, args.key, args.limit),),
                    ttl_seconds=60,
                )
            return {"status": "permits_filled", "count": args.count}
        if args.action == "permit-race":
            await process_barrier(args.barrier, args.role, 2)
            reason = None
            try:
                await AuthorityWorkRepository(db).acquire_permits(
                    owner_id=uuid4(),
                    scopes=((args.kind, args.key, args.limit),),
                    ttl_seconds=60,
                )
                status = "permit_admitted"
            except FederationAuthorityError as exc:
                status = "permit_rejected"
                reason = exc.reason
            active_count = await db.fetch_value(
                "SELECT COUNT(*) FROM {{tables.federation_authority_permits}} "
                "WHERE scope_kind = $1 AND scope_key = $2 "
                "AND expires_at > clock_timestamp()",
                args.kind,
                args.key,
            )
            return {
                "status": status,
                "reason": reason,
                "kind": args.kind,
                "limit": args.limit,
                "active_count": active_count,
            }
        if args.action == "permit-atomic":
            work = AuthorityWorkRepository(db)
            try:
                await work.acquire_permits(
                    owner_id=uuid4(),
                    scopes=(
                        ("global", args.key, 32),
                        ("domain", "atomic-unused.test", 2),
                        ("origin", "https://atomic-unused.test", 4),
                    ),
                    ttl_seconds=60,
                )
            except FederationAuthorityError as exc:
                inserted = await db.fetch_value(
                    "SELECT COUNT(*) FROM {{tables.federation_authority_permits}} "
                    "WHERE scope_key IN ($1, $2)",
                    "atomic-unused.test",
                    "https://atomic-unused.test",
                )
                return {
                    "status": "atomic_permit_rejected",
                    "reason": exc.reason,
                    "partial_permits": inserted,
                }
            raise RuntimeError("atomic over-limit permit unexpectedly admitted")
        if args.action == "token":
            remaining = await AuthorityWorkRepository(db).consume_token(
                bucket_kind="domain",
                bucket_key=os.environ["HARNESS_DOMAIN"],
                burst=args.burst,
                refill_per_minute=1,
            )
            return {"status": "token_consumed", "remaining": remaining}
        if args.action == "lock-timeout":
            scope = args.scope
            work = AuthorityWorkRepository(db)
            async with db.transaction() as blocker:
                await blocker.fetch_value(
                    "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                    "federation-authority:lease:" + scope,
                )
                try:
                    await work.acquire_lease(scope, owner_id=uuid4(), ttl_seconds=5)
                except FederationAuthorityError as exc:
                    failure = exc
                else:
                    raise RuntimeError("blocked lock unexpectedly acquired")
            unpublished = {
                "leases": await db.fetch_value(
                    "SELECT COUNT(*) FROM {{tables.federation_authority_leases}} WHERE scope_key = $1",
                    scope,
                ),
                "results": await db.fetch_value(
                    "SELECT COUNT(*) FROM {{tables.federation_authority_results}} WHERE scope_key = $1",
                    scope,
                ),
            }
            absent_claim = AuthorityClaim(
                canonical_address="lock-timeout.test/Alice",
                did_aw="did:aw:2CiZ88hVF4JuQim8nnSuyeiV2Lock",
                current_did_key=os.environ["HARNESS_DID_KEY"],
                delivery_origin="https://lock-timeout.test",
            )
            authorized = await core.authorize_from_shared_cohort(absent_claim)
            return {
                "status": "federation_error",
                "reason": failure.reason,
                "http_status": failure.http_status,
                "retryable": failure.retryable,
                "authorized": authorized is not None,
                "published": unpublished,
            }
        if args.action == "outage":
            # The shell starts this process while PostgreSQL is healthy, then
            # stops the database during the barrier delay. The already-running
            # worker therefore exercises the repository's stable fail-closed
            # mapping rather than container bootstrap failure.
            await db.fetch_value("SELECT 1")
            await asyncio.sleep(args.delay)
            try:
                await repository.get_checkpoint(os.environ["HARNESS_DID_AW"])
            except FederationAuthorityError as exc:
                return {
                    "status": "federation_error",
                    "reason": exc.reason,
                    "http_status": exc.http_status,
                    "retryable": exc.retryable,
                }
            raise RuntimeError("coordination outage unexpectedly authorized a read")
        if args.action == "state":
            counts = {}
            for table in (
                "federation_did_checkpoints",
                "federation_address_authority_cohorts",
                "federation_authority_leases",
                "federation_authority_results",
                "federation_authority_permits",
                "federation_authority_token_buckets",
            ):
                counts[table] = await db.fetch_value(
                    f'SELECT COUNT(*) FROM "aweb"."{table}"'
                )
            return {"status": "state", "counts": counts}
        raise ValueError(f"unsupported action: {args.action}")
    finally:
        await pool.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "action",
        choices=(
            "identity",
            "resolve",
            "singleflight",
            "verify",
            "seed",
            "fork",
            "permit-fill",
            "permit-race",
            "permit-atomic",
            "token",
            "lock-timeout",
            "outage",
            "state",
        ),
    )
    parser.add_argument("--generation", type=int, default=1)
    parser.add_argument("--variant", default="winner")
    parser.add_argument("--burst", type=int, default=5)
    parser.add_argument("--delay", type=float, default=3.0)
    parser.add_argument("--barrier", default="default")
    parser.add_argument("--role", default="worker")
    parser.add_argument("--claim", choices=("correct", "wrong"), default="correct")
    parser.add_argument("--scope", default="harness-scope")
    parser.add_argument(
        "--kind", choices=("global", "domain", "origin"), default="global"
    )
    parser.add_argument("--key", default="harness-key")
    parser.add_argument("--limit", type=int, default=1)
    parser.add_argument("--count", type=int, default=0)
    args = parser.parse_args()
    try:
        result = (
            generate_identity() if args.action == "identity" else asyncio.run(run(args))
        )
    except FederationAuthorityError as exc:
        result = {
            "status": "federation_error",
            "reason": exc.reason,
            "http_status": exc.spec.http_status,
            "retryable": exc.spec.retryable,
        }
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 2
    except Exception as exc:  # noqa: BLE001 - harness boundary emits a sanitized artifact
        result = {"status": "error", "type": type(exc).__name__, "detail": str(exc)}
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 3
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
