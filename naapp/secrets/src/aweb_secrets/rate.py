"""Rate buckets of a policy, charged inside the admission transaction (§4.4).

A bucket holds up to ``capacity`` tokens and refills continuously at
``capacity`` per ``window_s``. A request takes one token from each of its
policy's buckets, or from none: if any bucket is empty the request is refused
and nothing is charged. Buckets are locked in one fixed order, so concurrent
admissions serialize on them and never take more tokens than there are.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any

from pgdbm.core import TransactionManager


class RateLimited(Exception):
    """A rate bucket of the policy is empty: a security refusal, never metered."""

    code = "policy_rate_limited"
    status = 429


def _key(bucket: Mapping[str, Any], principal_did: str) -> tuple[str, str]:
    return bucket["per"], principal_did if bucket["per"] == "principal_secret" else ""


async def charge(
    tx: TransactionManager,
    installation_id: str,
    secret_id: str,
    principal_did: str,
    buckets: Sequence[Mapping[str, Any]],
    *,
    now: datetime,
) -> None:
    """Take one token from each of ``buckets`` for this request, or raise :class:`RateLimited`."""
    held: list[tuple[str, str, float]] = []
    for bucket in sorted(buckets, key=lambda b: _key(b, principal_did)):
        scope, principal = _key(bucket, principal_did)
        capacity = float(bucket["capacity"])
        await tx.execute(
            """
            INSERT INTO {{tables.rate_buckets}}
                (installation_id, secret_id, scope, principal_did, tokens, refilled_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT DO NOTHING
            """,
            installation_id,
            secret_id,
            scope,
            principal,
            capacity,
            now,
        )
        row = await tx.fetch_one(
            """
            SELECT tokens, refilled_at FROM {{tables.rate_buckets}}
            WHERE installation_id = $1 AND secret_id = $2 AND scope = $3 AND principal_did = $4
            FOR UPDATE
            """,
            installation_id,
            secret_id,
            scope,
            principal,
        )
        if row is None:
            raise RuntimeError("a rate bucket was inserted but cannot be read")
        elapsed = max((now - row["refilled_at"]).total_seconds(), 0.0)
        tokens = min(capacity, row["tokens"] + elapsed * capacity / bucket["window_s"])
        if tokens < 1:
            raise RateLimited("the policy's rate limit is reached")
        held.append((scope, principal, tokens))
    for scope, principal, tokens in held:
        await tx.execute(
            """
            UPDATE {{tables.rate_buckets}} SET tokens = $5, refilled_at = $6
            WHERE installation_id = $1 AND secret_id = $2 AND scope = $3 AND principal_did = $4
            """,
            installation_id,
            secret_id,
            scope,
            principal,
            tokens - 1,
            now,
        )
