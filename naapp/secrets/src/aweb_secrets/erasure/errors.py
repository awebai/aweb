"""One fixed, actionable vocabulary for startup and trigger failures."""

from enum import StrEnum

import asyncpg

from aweb_secrets.custody.sealing import CustodyUnavailable


class ErasureFailure(StrEnum):
    UNINITIALISED = "erasure_uninitialised"
    RESTORE_WITHOUT_LEDGER = "erasure_ledger_missing"
    IDENTITY_MISMATCH = "erasure_identity_mismatch"
    SCHEMA_MISMATCH = "erasure_schema_mismatch"
    INCOMPLETE = "erasure_incomplete"
    ALLOCATION_REGRESSED = "erasure_allocation_regressed"
    ROLE_UNSAFE = "erasure_role_unsafe"
    UNAVAILABLE = "erasure_unavailable"


_EXPLANATIONS = {
    ErasureFailure.UNINITIALISED: (
        "Secrets has not been initialised. On a new installation run the operator "
        "init-erasure command before starting Secrets."
    ),
    ErasureFailure.RESTORE_WITHOUT_LEDGER: (
        "Secrets content exists without its retained erasure ledger. Do not initialise "
        "a replacement. Keep Secrets stopped and follow the recovery restrictions in "
        "deploy/team/OPERATIONS.md."
    ),
    ErasureFailure.IDENTITY_MISMATCH: (
        "Secrets content and erasure ledger identities do not match. Keep Secrets "
        "stopped; recover the matching retained ledger using deploy/team/OPERATIONS.md."
    ),
    ErasureFailure.SCHEMA_MISMATCH: (
        "Secrets schema preparation does not match this service image. Keep Secrets "
        "stopped and follow the operator schema-preparation restrictions in "
        "deploy/team/OPERATIONS.md; do not replace the erasure ledger."
    ),
    ErasureFailure.INCOMPLETE: (
        "Secrets contains a key or reference already recorded as destroyed. Keep "
        "Secrets stopped; content restore is not supported by this release."
    ),
    ErasureFailure.ALLOCATION_REGRESSED: (
        "Secrets version history is older than its retained allocation floor. Keep "
        "Secrets stopped; content restore is not supported by this release."
    ),
    ErasureFailure.ROLE_UNSAFE: (
        "Secrets runtime database privileges do not match the protected erasure policy. Stop "
        "Secrets and have the database administrator restore the documented grants and ownership; "
        "init-erasure never repairs an existing ledger."
    ),
    ErasureFailure.UNAVAILABLE: (
        "Secrets cannot verify its retained erasure store. Keep Secrets stopped "
        "and restore database access; do not initialise a replacement ledger."
    ),
}


class ErasureUnavailable(CustodyUnavailable):
    """A refusal that never includes database parameters or stored material."""

    def __init__(self, reason: ErasureFailure) -> None:
        self.reason = reason
        self.code = reason.value
        super().__init__(_EXPLANATIONS[reason])


_TRIGGER_FAILURES = {
    "SE001": ErasureFailure.UNAVAILABLE,
    "SE002": ErasureFailure.ALLOCATION_REGRESSED,
    "SE003": ErasureFailure.INCOMPLETE,
}


def map_erasure_failure(error: BaseException) -> ErasureUnavailable | None:
    """Map raw asyncpg and pgdbm-wrapped failures at API and console boundaries.

    An unrelated database error remains unrelated. Inspect the actual cause,
    never SQL text or a message that could contain a caller's parameters.
    """
    cause: BaseException | None = error
    while cause is not None:
        if isinstance(cause, ErasureUnavailable):
            return cause
        if isinstance(cause, asyncpg.PostgresError) and cause.sqlstate in _TRIGGER_FAILURES:
            return ErasureUnavailable(_TRIGGER_FAILURES[cause.sqlstate])
        cause = cause.__cause__
    return None
