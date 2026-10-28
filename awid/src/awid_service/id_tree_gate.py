"""What every identity-tree writer of a domain shares (docs/id-certificates.md §3).

Registration and revocation each run in one transaction that takes the same
locks in the same order, so they serialize with each other and with namespace
and did:aw rotation:
  1. pg_advisory_xact_lock on the exact canonical domain;
  2. the domain's dns_namespaces row (rotation, reverify and delete hold it
     FOR UPDATE, so the open epoch read after it is current);
  3. the subject's and parent's did_aw_mappings rows, sorted by did_aw
     (did:aw rotation holds its row FOR UPDATE);
  4. the subject's id_identities row FOR UPDATE and its parent's FOR SHARE,
     in id order.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from awid.id_certificates import IDCertificateError



class IdentityTreeRefusal(Exception):
    """A contract refusal; ``code`` is the stable reason, ``status`` its HTTP status."""

    def __init__(self, code: str, status: int = 422):
        super().__init__(code)
        self.code = code
        self.status = status


def wire_time(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def strict_json_object(raw: bytes, *, max_bytes: int = 16384) -> dict[str, Any]:
    """Parse a request body as one JSON object: no duplicate keys, floats or constants."""
    if len(raw) > max_bytes:
        raise IDCertificateError("invalid_shape")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise IDCertificateError("invalid_json")
            result[key] = value
        return result

    def reject(_: str) -> Any:
        raise IDCertificateError("invalid_shape")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_float=reject, parse_constant=reject)
    except (UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, IDCertificateError):
            raise
        raise IDCertificateError("invalid_json") from exc
    if type(value) is not dict:
        raise IDCertificateError("invalid_shape")
    return value


async def lock_domain(tx, domain: str):
    """Take locks 1 and 2; return the live namespace row, or None."""
    await tx.execute("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", f"aweb.id-tree/{domain}")
    return await tx.fetch_one(
        """
        SELECT namespace_id, controller_did
        FROM {{tables.dns_namespaces}}
        WHERE domain = $1 AND deleted_at IS NULL
        FOR SHARE
        """,
        domain,
    )


async def lock_keys_and_subject(
    tx, *, dids: set[str | None], subject_id: str, parent_id: str | None = None,
) -> tuple[dict[str, str], Any]:
    """Take locks 3 and 4; return the current key of each mapped did:aw and the subject row.

    The parent's id_identities row is held FOR SHARE beside the subject's, so
    a registration and a revocation of its parent serialize on the row itself
    as well as on the domain lock. Rows are taken in id order.
    """
    mapped = await tx.fetch_all(
        """
        SELECT did_aw, current_did_key
        FROM {{tables.did_aw_mappings}}
        WHERE did_aw = ANY($1::text[])
        ORDER BY did_aw
        FOR SHARE
        """,
        sorted(did for did in dids if did is not None),
    )
    subject = None
    for id_ in sorted({subject_id, parent_id} - {None}):
        row = await tx.fetch_one(
            f"""
            SELECT id, domain, kind, revoked_at, effective_from
            FROM {{{{tables.id_identities}}}}
            WHERE id = $1
            FOR {"UPDATE" if id_ == subject_id else "SHARE"}
            """,
            id_,
        )
        if id_ == subject_id:
            subject = row
    return {row["did_aw"]: row["current_did_key"] for row in mapped}, subject


async def current_root(tx, domain: str, namespace, dns_key: str | None):
    """The domain's open epoch when it has current root authority, else None.

    Authority needs the stored controller, the open epoch's key and the exact
    DNS key this request observed (before its transaction) to agree; any
    disagreement makes it unavailable rather than proof of another root.
    """
    if namespace is None:
        return None
    epoch = await tx.fetch_one(
        """
        SELECT seq, did_key, continuity, registered_at
        FROM {{tables.id_namespace_epochs}}
        WHERE domain = $1 AND retired_at IS NULL
        """,
        domain,
    )
    if epoch is None or not epoch["did_key"] == namespace["controller_did"] == dns_key:
        return None
    return epoch


def identity_parent_did(parent_kind: str, parent_id: str) -> str | None:
    """The did:aw of an identity parent, which is the only parent with a mapping."""
    return parent_id if parent_kind == "identity" and parent_id.startswith("did:aw:") else None
