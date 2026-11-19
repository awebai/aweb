"""Classify unique-key collisions without hiding unrelated database failures."""

import asyncpg
from pgdbm.errors import QueryError


def is_unique_write_conflict(error: BaseException) -> bool:
    """Recognize raw transaction errors and pgdbm 0.5.0's chained wrapper.

    Exact-retry race recovery (docs/identity-messaging-contract.md:354-365)
    rereads only after a committed winner's unique-key collision.
    """
    cause = error.__cause__ if isinstance(error, QueryError) else error
    return isinstance(cause, asyncpg.exceptions.UniqueViolationError)
