"""PostgreSQL-only leases, fences, permits, results, and token buckets."""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Sequence
from uuid import UUID

from awid.federation_errors import FederationAuthorityError

_MAX_BIGINT = 2**63 - 1


@dataclass(frozen=True)
class AuthorityLease:
    scope_key: str
    owner_id: UUID
    fence: int
    expires_at: datetime
    acquired: bool = True


@dataclass(frozen=True)
class AuthorityEvidenceScope:
    authority_statement_digest: str
    authority_generation: int
    registry_origin: str
    canonical_address: str
    did_aw: str | None = None

    def payload(self) -> dict[str, Any]:
        return {
            "authority_statement_digest": self.authority_statement_digest,
            "authority_generation": self.authority_generation,
            "registry_origin": self.registry_origin,
            "canonical_address": self.canonical_address,
            "did_aw_where_applicable": self.did_aw,
        }

    def key(self, *, response_digest: str | None = None) -> str:
        payload = authority_result_scope_payload(self, response_digest=response_digest)
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return "evidence:" + hashlib.sha256(encoded).hexdigest()


def authority_result_scope_payload(
    scope: AuthorityEvidenceScope, *, response_digest: str | None = None
) -> dict[str, Any]:
    if scope.authority_generation < 1 or not scope.registry_origin or not scope.canonical_address:
        raise ValueError("invalid authority evidence scope")
    complete = scope.payload()
    if response_digest is None:
        return complete
    if not response_digest.startswith("sha256:") or len(response_digest) != 71:
        raise ValueError("invalid authority response digest")
    return {
        "complete_source_scope": complete,
        "response_digest": response_digest,
    }


def authority_result_ttl_seconds(result_kind: str, requested_seconds: int) -> int:
    if requested_seconds < 1:
        raise ValueError("invalid authority result ttl")
    maximum = {
        "dns_transport_failure": 5,
        "authoritative_not_found": 15,
    }.get(result_kind, 60)
    return min(requested_seconds, maximum)


@dataclass(frozen=True)
class AuthorityWorkResult:
    scope_key: str
    fence: int
    status: str
    evidence: dict[str, Any]
    expires_at: datetime


class AuthorityWorkRepository:
    def __init__(self, db) -> None:
        self.db = db

    async def _lock(self, tx, key: str) -> None:
        await tx.fetch_value(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
            "federation-authority:" + key,
            timeout=1.0,
        )

    async def acquire_lease(
        self,
        scope_key: str,
        *,
        owner_id: UUID,
        ttl_seconds: int,
    ) -> AuthorityLease:
        if not scope_key or scope_key != scope_key.strip() or not 1 <= ttl_seconds <= 60:
            raise ValueError("invalid authority lease")
        try:
            async with self.db.transaction() as tx:
                await self._lock(tx, "lease:" + scope_key)
                lease = await tx.fetch_one(
                    """
                    SELECT owner_id, fence, expires_at,
                           expires_at > clock_timestamp() AS live
                    FROM {{tables.federation_authority_leases}}
                    WHERE scope_key = $1
                    FOR UPDATE
                    """,
                    scope_key,
                )
                if lease and lease["live"]:
                    if lease["owner_id"] == owner_id:
                        row = await tx.fetch_one(
                            """
                            UPDATE {{tables.federation_authority_leases}}
                            SET expires_at = clock_timestamp() + $3::integer * INTERVAL '1 second'
                            WHERE scope_key = $1 AND owner_id = $2
                            RETURNING fence, expires_at
                            """,
                            scope_key,
                            owner_id,
                            ttl_seconds,
                        )
                        return AuthorityLease(scope_key, owner_id, row["fence"], row["expires_at"])
                    return AuthorityLease(
                        scope_key,
                        lease["owner_id"],
                        lease["fence"],
                        lease["expires_at"],
                        acquired=False,
                    )

                counter = await tx.fetch_one(
                    "SELECT last_fence FROM {{tables.federation_authority_fences}} WHERE scope_key = $1 FOR UPDATE",
                    scope_key,
                )
                if counter is None:
                    fence = 1
                    await tx.execute(
                        "INSERT INTO {{tables.federation_authority_fences}} (scope_key, last_fence) VALUES ($1, $2)",
                        scope_key,
                        fence,
                    )
                else:
                    if counter["last_fence"] >= _MAX_BIGINT:
                        raise FederationAuthorityError(
                            "federation_authority_coordination_unavailable"
                        )
                    fence = counter["last_fence"] + 1
                    await tx.execute(
                        """
                        UPDATE {{tables.federation_authority_fences}}
                        SET last_fence = $2, updated_at = clock_timestamp()
                        WHERE scope_key = $1
                        """,
                        scope_key,
                        fence,
                    )
                row = await tx.fetch_one(
                    """
                    INSERT INTO {{tables.federation_authority_leases}} (
                        scope_key, owner_id, fence, acquired_at, expires_at
                    ) VALUES (
                        $1, $2, $3, clock_timestamp(),
                        clock_timestamp() + $4::integer * INTERVAL '1 second'
                    )
                    ON CONFLICT (scope_key) DO UPDATE SET
                        owner_id = EXCLUDED.owner_id,
                        fence = EXCLUDED.fence,
                        acquired_at = EXCLUDED.acquired_at,
                        expires_at = EXCLUDED.expires_at
                    RETURNING expires_at
                    """,
                    scope_key,
                    owner_id,
                    fence,
                    ttl_seconds,
                )
                return AuthorityLease(scope_key, owner_id, fence, row["expires_at"])
        except FederationAuthorityError:
            raise
        except Exception as exc:
            raise FederationAuthorityError(
                "federation_authority_coordination_unavailable"
            ) from exc

    async def publish_result(
        self,
        lease: AuthorityLease,
        *,
        status: str,
        evidence: dict[str, Any],
        ttl_seconds: int,
        source_digest: str | None = None,
    ) -> AuthorityWorkResult:
        if not lease.acquired or not status or not 1 <= ttl_seconds <= 60:
            raise ValueError("invalid authority result")
        try:
            async with self.db.transaction() as tx:
                await self._lock(tx, "lease:" + lease.scope_key)
                live = await tx.fetch_one(
                    """
                    SELECT 1
                    FROM {{tables.federation_authority_leases}}
                    WHERE scope_key = $1 AND owner_id = $2 AND fence = $3
                      AND expires_at > clock_timestamp()
                    FOR UPDATE
                    """,
                    lease.scope_key,
                    lease.owner_id,
                    lease.fence,
                )
                if live is None:
                    raise FederationAuthorityError("federation_authority_cas_conflict")
                row = await tx.fetch_one(
                    """
                    INSERT INTO {{tables.federation_authority_results}} (
                        scope_key, fence, status, evidence, source_digest,
                        created_at, expires_at
                    ) VALUES (
                        $1, $2, $3, $4::jsonb, $5, clock_timestamp(),
                        clock_timestamp() + $6::integer * INTERVAL '1 second'
                    )
                    ON CONFLICT (scope_key) DO UPDATE SET
                        fence = EXCLUDED.fence,
                        status = EXCLUDED.status,
                        evidence = EXCLUDED.evidence,
                        source_digest = EXCLUDED.source_digest,
                        created_at = EXCLUDED.created_at,
                        expires_at = EXCLUDED.expires_at
                    WHERE {{tables.federation_authority_results}}.fence <= EXCLUDED.fence
                    RETURNING expires_at
                    """,
                    lease.scope_key,
                    lease.fence,
                    status,
                    json.dumps(evidence, sort_keys=True, separators=(",", ":")),
                    source_digest,
                    ttl_seconds,
                )
                if row is None:
                    raise FederationAuthorityError("federation_authority_cas_conflict")
                return AuthorityWorkResult(
                    lease.scope_key,
                    lease.fence,
                    status,
                    evidence,
                    row["expires_at"],
                )
        except FederationAuthorityError:
            raise
        except Exception as exc:
            raise FederationAuthorityError(
                "federation_authority_coordination_unavailable"
            ) from exc

    async def get_result(self, scope_key: str) -> AuthorityWorkResult | None:
        try:
            row = await self.db.fetch_one(
                """
                SELECT scope_key, fence, status, evidence, expires_at
                FROM {{tables.federation_authority_results}}
                WHERE scope_key = $1 AND expires_at > clock_timestamp()
                """,
                scope_key,
            )
        except Exception as exc:
            raise FederationAuthorityError(
                "federation_authority_coordination_unavailable"
            ) from exc
        if row is None:
            return None
        evidence = row["evidence"]
        if isinstance(evidence, str):
            evidence = json.loads(evidence)
        return AuthorityWorkResult(
            row["scope_key"], row["fence"], row["status"], evidence, row["expires_at"]
        )

    async def wait_for_result(
        self,
        scope_key: str,
        *,
        deadline_seconds: float = 5.0,
        poll_seconds: float = 0.05,
    ) -> AuthorityWorkResult | None:
        if deadline_seconds <= 0 or poll_seconds <= 0:
            raise ValueError("invalid authority result wait")
        deadline = time.monotonic() + min(deadline_seconds, 5.0)
        while True:
            result = await self.get_result(scope_key)
            if result is not None:
                return result
            try:
                live = await self.db.fetch_value(
                    """
                    SELECT EXISTS (
                        SELECT 1 FROM {{tables.federation_authority_leases}}
                        WHERE scope_key = $1 AND expires_at > clock_timestamp()
                    )
                    """,
                    scope_key,
                )
            except Exception as exc:
                raise FederationAuthorityError(
                    "federation_authority_coordination_unavailable"
                ) from exc
            if not live or time.monotonic() >= deadline:
                return None
            await asyncio.sleep(min(poll_seconds, max(0.0, deadline - time.monotonic())))

    async def acquire_permits(
        self,
        *,
        owner_id: UUID,
        scopes: Sequence[tuple[str, str, int]],
        ttl_seconds: int,
    ) -> tuple[UUID, ...]:
        ordered = sorted(scopes, key=lambda item: (item[0], item[1]))
        if not ordered or not 1 <= ttl_seconds <= 60:
            raise ValueError("invalid authority permits")
        try:
            async with self.db.transaction() as tx:
                for kind, key, limit in ordered:
                    if kind not in {"global", "domain", "origin"} or not key or limit < 1:
                        raise ValueError("invalid authority permit scope")
                    await self._lock(tx, f"permit:{kind}:{key}")
                for kind, key, limit in ordered:
                    active = await tx.fetch_value(
                        """
                        SELECT COUNT(*)
                        FROM {{tables.federation_authority_permits}}
                        WHERE scope_kind = $1 AND scope_key = $2
                          AND expires_at > clock_timestamp()
                        """,
                        kind,
                        key,
                    )
                    if active >= limit:
                        raise FederationAuthorityError("federation_resolver_busy")
                permit_ids: list[UUID] = []
                for kind, key, _limit in ordered:
                    row = await tx.fetch_one(
                        """
                        INSERT INTO {{tables.federation_authority_permits}} (
                            scope_kind, scope_key, owner_id, acquired_at, expires_at
                        ) VALUES (
                            $1, $2, $3, clock_timestamp(),
                            clock_timestamp() + $4::integer * INTERVAL '1 second'
                        )
                        RETURNING permit_id
                        """,
                        kind,
                        key,
                        owner_id,
                        ttl_seconds,
                    )
                    permit_ids.append(row["permit_id"])
                return tuple(permit_ids)
        except (FederationAuthorityError, ValueError):
            raise
        except Exception as exc:
            raise FederationAuthorityError(
                "federation_authority_coordination_unavailable"
            ) from exc

    async def release_permits(self, *, owner_id: UUID) -> None:
        try:
            await self.db.execute(
                "DELETE FROM {{tables.federation_authority_permits}} WHERE owner_id = $1",
                owner_id,
            )
        except Exception as exc:
            raise FederationAuthorityError(
                "federation_authority_coordination_unavailable"
            ) from exc

    async def consume_token(
        self,
        *,
        bucket_kind: str,
        bucket_key: str,
        burst: int,
        refill_per_minute: int,
    ) -> float:
        if (
            bucket_kind not in {"source_ip", "domain", "origin"}
            or not bucket_key
            or burst < 1
            or refill_per_minute < 1
        ):
            raise ValueError("invalid authority token bucket")
        try:
            async with self.db.transaction() as tx:
                await self._lock(tx, f"bucket:{bucket_kind}:{bucket_key}")
                row = await tx.fetch_one(
                    """
                    INSERT INTO {{tables.federation_authority_token_buckets}} (
                        bucket_kind, bucket_key, tokens, refilled_at, updated_at
                    ) VALUES (
                        $1, $2, ($3::double precision - 1),
                        clock_timestamp(), clock_timestamp()
                    )
                    ON CONFLICT (bucket_kind, bucket_key) DO UPDATE SET
                        tokens = LEAST(
                            $3::double precision,
                            {{tables.federation_authority_token_buckets}}.tokens
                              + EXTRACT(EPOCH FROM (
                                  clock_timestamp()
                                  - {{tables.federation_authority_token_buckets}}.refilled_at
                                )) * ($4::double precision / 60.0)
                        ) - 1,
                        refilled_at = clock_timestamp(),
                        updated_at = clock_timestamp()
                    WHERE LEAST(
                        $3::double precision,
                        {{tables.federation_authority_token_buckets}}.tokens
                          + EXTRACT(EPOCH FROM (
                              clock_timestamp()
                              - {{tables.federation_authority_token_buckets}}.refilled_at
                            )) * ($4::double precision / 60.0)
                    ) >= 1
                    RETURNING tokens
                    """,
                    bucket_kind,
                    bucket_key,
                    burst,
                    refill_per_minute,
                )
                if row is None:
                    raise FederationAuthorityError("federation_rate_limited")
                return float(row["tokens"])
        except FederationAuthorityError:
            raise
        except Exception as exc:
            raise FederationAuthorityError(
                "federation_authority_coordination_unavailable"
            ) from exc
