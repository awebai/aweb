"""Rate buckets of a policy, charged inside the admission transaction (§4.4).

Each policy has its own buckets for a secret, so a request admitted under one
policy never refills another's.

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


async def _locked_row(
    tx: TransactionManager,
    installation_id: str,
    secret_id: str,
    policy_digest: str,
    scope: str,
    principal: str,
    capacity: float,
    now: datetime,
) -> Mapping[str, Any]:
    """The bucket's row, created full if absent and locked until the transaction ends."""
    await tx.execute(
        """
        INSERT INTO {{tables.rate_buckets}}
            (installation_id, policy_digest, secret_id, scope, principal_did, tokens, refilled_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT DO NOTHING
        """,
        installation_id,
        policy_digest,
        secret_id,
        scope,
        principal,
        capacity,
        now,
    )
    row = await tx.fetch_one(
        """
        SELECT tokens, refilled_at FROM {{tables.rate_buckets}}
        WHERE installation_id = $1 AND policy_digest = $2 AND secret_id = $3
          AND scope = $4 AND principal_did = $5
        FOR UPDATE
        """,
        installation_id,
        policy_digest,
        secret_id,
        scope,
        principal,
    )
    if row is None:
        raise RuntimeError("a rate bucket was inserted but cannot be read")
    return row


async def lock_buckets(
    tx: TransactionManager,
    installation_id: str,
    secret_id: str,
    principal_did: str,
    policies: Sequence[tuple[str, Sequence[Mapping[str, Any]]]],
    *,
    now: datetime,
) -> None:
    """Create and lock every bucket that any of ``policies`` may charge, in one fixed order.

    An admission that may charge any of several candidate policies locks all of
    their buckets first, so admissions trying the same policies in different
    orders never lock their buckets in different orders.
    """
    keys = {
        (digest, *_key(bucket, principal_did)): float(bucket["capacity"])
        for digest, buckets in policies
        for bucket in buckets
    }
    for (digest, scope, principal), capacity in sorted(keys.items()):
        await _locked_row(tx, installation_id, secret_id, digest, scope, principal, capacity, now)


async def charge(
    tx: TransactionManager,
    installation_id: str,
    secret_id: str,
    principal_did: str,
    policy_digest: str,
    buckets: Sequence[Mapping[str, Any]],
    *,
    now: datetime,
) -> None:
    """Take one token from each of the policy's ``buckets`` for this request, or raise
    :class:`RateLimited`."""
    held: list[tuple[str, str, float]] = []
    for bucket in sorted(buckets, key=lambda b: _key(b, principal_did)):
        scope, principal = _key(bucket, principal_did)
        capacity = float(bucket["capacity"])
        row = await _locked_row(
            tx, installation_id, secret_id, policy_digest, scope, principal, capacity, now
        )
        elapsed = max((now - row["refilled_at"]).total_seconds(), 0.0)
        tokens = min(capacity, row["tokens"] + elapsed * capacity / bucket["window_s"])
        if tokens < 1:
            raise RateLimited("the policy's rate limit is reached")
        held.append((scope, principal, tokens))
    for scope, principal, tokens in held:
        await tx.execute(
            """
            UPDATE {{tables.rate_buckets}} SET tokens = $6, refilled_at = $7
            WHERE installation_id = $1 AND policy_digest = $2 AND secret_id = $3
              AND scope = $4 AND principal_did = $5
            """,
            installation_id,
            policy_digest,
            secret_id,
            scope,
            principal,
            tokens - 1,
            now,
        )
