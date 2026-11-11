"""One entry gate for transactions that can retire a B3 designation."""

import hashlib

import asyncpg
from pgdbm.core import TransactionManager

from aweb_naapp.hooks.strictjson import canonical
from aweb_naapp.runtime.installation import AdmittedInstallation

_NAMESPACE = 0x42335231  # ASCII B3R1, signed int32.
_PREFIX = b"aweb.naapp.passkeys.retirement/1\n"


async def prepare_retirement(tx: TransactionManager, *, installation: AdmittedInstallation) -> None:
    """Serialize retirement on the original live effect transaction.

    Every designation-retiring entry takes F6 first, then this gate BEFORE
    actor/target role, B3 or S4 holds. All entry interfaces use this one helper;
    acquiring it inside a retirement method after caller authority is too late.
    The caller owns F6, authorization and the original evidence deadline, and
    checks them after waits and at its effect fence. This grants no authority,
    fetches no evidence and refreshes nothing. Commit/rollback releases the
    lock; rollback to a savepoint releases locks first acquired after it.

    Frozen v1 key: PostgreSQL's two-int form (namespace 0x42335231, scope).
    Scope is the first four SHA-256 bytes, big-endian signed int32, of the
    literal ASCII prefix ``aweb.naapp.passkeys.retirement/1\\n`` followed by
    strictjson.canonical([app_id, team_id, installation_id]). Generation is
    deliberately excluded. This key space is separate from bigint locks.
    Hash collisions only serialize otherwise unrelated retirements.
    """
    try:
        live = tx.connection.is_in_transaction()
    except asyncpg.InterfaceError:
        live = False
    if not live:
        raise ValueError("retirement preparation needs a live transaction")
    identity = canonical([installation.app_id, installation.team_id, installation.installation_id])
    scope = int.from_bytes(hashlib.sha256(_PREFIX + identity).digest()[:4], "big", signed=True)
    await tx.execute("SELECT pg_advisory_xact_lock($1::int, $2::int)", _NAMESPACE, scope)
