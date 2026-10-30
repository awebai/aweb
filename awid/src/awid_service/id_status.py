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

from awid.dns_verify import DomainAuthority
from awid.id_certificates import IDChainEvidence, verify_id_chain

from awid_service.id_tree_clock import Clock, serialization_time
from awid_service.id_tree_gate import IdentityTreeRefusal, canonical_json, current_root, wire_time
from awid_service.namespace_epochs import latest_domain_event, delegation_of, authority_evidence

MAX_RESPONSE_BYTES = 131072


async def status_snapshot(db, *, domain: str, ids: list[str], dns_authority: DomainAuthority | None, clock: Clock) -> dict:
    """The POST /status answer, read in its own read-only REPEATABLE READ transaction."""
    async with db.transaction() as tx:
        await tx.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        namespace = await tx.fetch_one(
            """
            SELECT namespace_id, controller_did, parent_domain, parent_controller_key
            FROM {{tables.dns_namespaces}}
            WHERE domain = $1 AND deleted_at IS NULL
            """,
            domain,
        )
        # No new current status is issued while the stored controller, the
        # open epoch and discovered authority disagree.
        if await current_root(tx, domain, namespace, dns_authority) is None:
            raise IdentityTreeRefusal("evidence_unavailable", 503)
        return await read_snapshot(tx, domain=domain, ids=ids, clock=clock)


async def read_snapshot(tx, *, domain: str, ids: list[str], clock: Clock) -> dict:
    """The status snapshot as ``tx`` sees it; callers supply the transaction's isolation and locks.

    Every identity row (with its revocation) is read before any revision or
    key history, in one query per kind.
    """
    epochs = await tx.fetch_all(
        """
        SELECT seq, did_key, registered_at, retired_at, continuity
        FROM {{tables.id_namespace_epochs}}
        WHERE domain = $1
        ORDER BY seq
        """,
        domain,
    )
    namespace = await tx.fetch_one(
        "SELECT controller_did, parent_domain, parent_controller_key FROM {{tables.dns_namespaces}} WHERE domain = $1 AND deleted_at IS NULL", domain,
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

    identities = {
        row["id"]: row
        for row in await tx.fetch_all(
            "SELECT id, revoked_at, effective_from FROM {{tables.id_identities}} WHERE id = ANY($1::text[])", included,
        )
    }
    revisions = await tx.fetch_all(
        """
        SELECT id, certificate_id, signed_json, registered_at, superseded_at, issuer_key_seq
        FROM {{tables.id_certificates}}
        WHERE id = ANY($1::text[])
        ORDER BY id, registered_at
        """,
        included,
    )
    logs = await tx.fetch_all(
        """
        SELECT did_aw, seq, operation, previous_did_key, new_did_key, prev_entry_hash, entry_hash, state_hash,
               authorized_by, signature, timestamp, created_at
        FROM {{tables.did_aw_log}}
        WHERE did_aw = ANY($1::text[])
        ORDER BY did_aw, seq
        """,
        included,
    )
    # An identity whose key history is gone (its key mapping was deleted)
    # cannot be proven; the snapshot is incomplete, never partial.
    if {row["did_aw"] for row in logs} != set(included):
        raise IdentityTreeRefusal("evidence_unavailable", 503)
    snapshot = {
        "v": 1,
        "domain": domain,
        "observed_at": wire_time(serialization_time(clock, await latest_domain_event(tx, domain))),
        "namespace": {"epochs": [_epoch(row) for row in epochs]},
        "identities": [],
        "missing": [id_ for id_ in ids if id_ not in registered],
    }
    # The response's exact compact size, kept as identities are added, so an
    # oversized proof stops being assembled as soon as it is too big.
    delegation = delegation_of(namespace)
    if delegation is not None:
        snapshot["namespace"]["delegation"] = delegation
    size = _size(snapshot)
    for id_ in included:
        identity = _identity(
            id_, identities[id_],
            [row for row in revisions if row["id"] == id_],
            [row for row in logs if row["did_aw"] == id_],
        )
        size += _size(identity) + (1 if snapshot["identities"] else 0)
        if size > MAX_RESPONSE_BYTES:
            raise IdentityTreeRefusal("evidence_unavailable", 503)
        snapshot["identities"].append(identity)
    return snapshot


async def verify_parent_chain(tx, *, domain: str, parent: str, parent_key: str, dns_authority: DomainAuthority | None, clock: Clock) -> dict:
    """S1's verdict on ``parent``'s whole current chain, from the state ``tx`` holds.

    The evidence is this transaction's own snapshot, fresh by construction,
    with the DNS authority the request observed before its transaction. A
    proof too large to snapshot refuses evidence_unavailable before any
    verdict.
    """
    evidence = IDChainEvidence(
        status=await read_snapshot(tx, domain=domain, ids=[parent], clock=clock),
        namespace_authority=authority_evidence(domain, dns_authority),
        age_seconds=0,
    )
    return verify_id_chain(None, subject={"id": parent, "did_key": parent_key}, evidence=evidence, domain=domain)


def _size(value) -> int:
    return len(canonical_json(value).encode())


def _epoch(row) -> dict:
    return {
        "seq": row["seq"],
        "did_key": row["did_key"],
        "registered_at": wire_time(row["registered_at"]),
        "retired_at": None if row["retired_at"] is None else wire_time(row["retired_at"]),
        "continuity": row["continuity"],
    }


def _identity(id_: str, identity, revisions, log) -> dict:
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
