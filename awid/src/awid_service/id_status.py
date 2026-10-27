"""Identity-tree status snapshots (docs/id-certificates.md §4).

One read-only REPEATABLE READ transaction returns a coherent view of the
domain's complete namespace epoch history and of the exact requested
registered IDs with their proof closure: every same-domain identity named as
a parent by any revision of an included identity. A visited set ends the
traversal; cycle and depth rules apply to the revisions a verifier selects,
not to the union of historical parent links. Nothing else about the domain
is listed, and invitation IDs never leave private storage.
"""

from __future__ import annotations

import json

from awid_service.id_tree_clock import Clock, serialization_time
from awid_service.id_tree_gate import IdentityTreeRefusal, canonical_json, current_root, wire_time
from awid_service.namespace_epochs import latest_domain_event

MAX_RESPONSE_BYTES = 131072


async def status_snapshot(db, *, domain: str, ids: list[str], dns_key: str | None, clock: Clock) -> dict:
    async with db.transaction() as tx:
        await tx.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        namespace = await tx.fetch_one(
            """
            SELECT namespace_id, controller_did
            FROM {{tables.dns_namespaces}}
            WHERE domain = $1 AND deleted_at IS NULL
            """,
            domain,
        )
        # No new current status is issued while the stored controller, the
        # open epoch and exact DNS disagree.
        if await current_root(tx, domain, namespace, dns_key) is None:
            raise IdentityTreeRefusal("evidence_unavailable", 503)

        epochs = await tx.fetch_all(
            """
            SELECT seq, did_key, registered_at, retired_at, continuity
            FROM {{tables.id_namespace_epochs}}
            WHERE domain = $1
            ORDER BY seq
            """,
            domain,
        )
        registered = {
            row["id"]
            for row in await tx.fetch_all(
                "SELECT id FROM {{tables.id_identities}} WHERE domain = $1 AND id = ANY($2::text[])", domain, ids,
            )
        }
        included = [id_ for id_ in ids if id_ in registered]
        frontier = list(included)
        while frontier:
            parents = await tx.fetch_all(
                """
                SELECT DISTINCT c.parent_id
                FROM {{tables.id_certificates}} c
                JOIN {{tables.id_identities}} i ON i.id = c.parent_id AND i.domain = $1
                WHERE c.id = ANY($2::text[]) AND c.parent_kind = 'identity'
                ORDER BY c.parent_id
                """,
                domain, frontier,
            )
            frontier = [row["parent_id"] for row in parents if row["parent_id"] not in included]
            included.extend(frontier)

        snapshot = {
            "v": 1,
            "domain": domain,
            "observed_at": wire_time(serialization_time(clock, await latest_domain_event(tx, domain))),
            "namespace": {"epochs": [_epoch(row) for row in epochs]},
            "identities": [await _identity(tx, id_) for id_ in included],
            "missing": [id_ for id_ in ids if id_ not in registered],
        }
    if len(canonical_json(snapshot).encode()) > MAX_RESPONSE_BYTES:
        raise IdentityTreeRefusal("evidence_unavailable", 503)
    return snapshot


def _epoch(row) -> dict:
    return {
        "seq": row["seq"],
        "did_key": row["did_key"],
        "registered_at": wire_time(row["registered_at"]),
        "retired_at": None if row["retired_at"] is None else wire_time(row["retired_at"]),
        "continuity": row["continuity"],
    }


async def _identity(tx, id_: str) -> dict:
    identity = await tx.fetch_one(
        "SELECT revoked_at, effective_from FROM {{tables.id_identities}} WHERE id = $1", id_,
    )
    revisions = await tx.fetch_all(
        """
        SELECT certificate_id, signed_json, registered_at, superseded_at, issuer_key_seq
        FROM {{tables.id_certificates}}
        WHERE id = $1
        ORDER BY registered_at
        """,
        id_,
    )
    log = await tx.fetch_all(
        """
        SELECT seq, operation, previous_did_key, new_did_key, prev_entry_hash, entry_hash, state_hash,
               authorized_by, signature, timestamp, created_at
        FROM {{tables.did_aw_log}}
        WHERE did_aw = $1
        ORDER BY seq
        """,
        id_,
    )
    return {
        "id": id_,
        "current_certificate_id": next(row["certificate_id"] for row in revisions if row["superseded_at"] is None),
        "current_key_seq": log[-1]["seq"],
        "key_history": [
            {
                "entry": {field: row[field] for field in (
                    "seq", "operation", "previous_did_key", "new_did_key", "prev_entry_hash", "entry_hash",
                    "state_hash", "authorized_by", "signature", "timestamp",
                )},
                "registered_at": wire_time(row["created_at"]),
            }
            for row in log
        ],
        "certificates": [
            {
                "signed": json.loads(row["signed_json"]),
                "registered_at": wire_time(row["registered_at"]),
                "superseded_at": None if row["superseded_at"] is None else wire_time(row["superseded_at"]),
                "issuer_key_seq": row["issuer_key_seq"],
            }
            for row in revisions
        ],
        "revocation": None if identity["revoked_at"] is None else {
            "revoked_at": wire_time(identity["revoked_at"]),
            "effective_from": wire_time(identity["effective_from"]),
        },
    }
