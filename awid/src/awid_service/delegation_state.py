"""Transactional persistence for portable namespace delegation."""

from __future__ import annotations

import json
from dataclasses import dataclass

from awid.delegation import (
    DelegationAssertion,
    canonical_delegation_payload,
    parse_delegation_assertion,
)


@dataclass
class DelegationStateError(Exception):
    code: str
    message: str
    status_code: int = 409
    retryable: bool = False

    def __str__(self) -> str:
        return self.message


async def _lock_child(tx, child_domain: str) -> None:
    await tx.fetch_value(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
        "namespace-delegation:" + child_domain,
    )


async def delegation_head(tx, child_domain: str, *, for_update: bool = False):
    query = """
        SELECT child_domain, parent_domain, head_sequence, head_hash,
               head_operation, head_controller_did,state_source_registry_id,
               state_cutover_id,state_generation
        FROM {{tables.namespace_delegation_heads}}
        WHERE child_domain = $1
    """
    if for_update:
        query += " FOR UPDATE"
    return await tx.fetch_one(query, child_domain)


async def stored_assertion(tx, child_domain: str, sequence: int) -> dict:
    entry = await tx.fetch_one(
        """
        SELECT canonical_payload, entry_hash
        FROM {{tables.namespace_delegation_entries}}
        WHERE child_domain = $1 AND sequence = $2
        """,
        child_domain,
        sequence,
    )
    if entry is None:
        raise DelegationStateError("delegation_chain_inconsistent", "delegation entry is missing")
    signatures = await tx.fetch_all(
        """
        SELECT controller_did, signature
        FROM {{tables.namespace_delegation_signatures}}
        WHERE child_domain = $1 AND sequence = $2
        ORDER BY controller_did COLLATE "C"
        """,
        child_domain,
        sequence,
    )
    return {
        "payload": json.loads(bytes(entry["canonical_payload"]).decode("utf-8")),
        "entry_hash": entry["entry_hash"],
        "signatures": [
            {"controller_did": row["controller_did"], "signature": row["signature"]}
            for row in signatures
        ],
    }


async def append_transition(
    tx,
    assertion_value: object,
    *,
    authority_did: str,
    expected_child_domain: str,
    expected_child_controller_did: str,
    expected_operation: str,
) -> dict:
    """Validate and append one transition, or return an exact stored retry."""
    try:
        assertion = parse_delegation_assertion(assertion_value)
    except Exception as exc:
        raise DelegationStateError(
            "delegation_assertion_invalid", str(exc), status_code=422
        ) from exc
    payload = assertion.payload
    if (
        payload.child_domain != expected_child_domain
        or payload.child_controller_did != expected_child_controller_did
        or payload.operation != expected_operation
    ):
        raise DelegationStateError(
            "namespace_delegation_transition_invalid",
            "delegation assertion does not match the namespace mutation",
        )

    await _lock_child(tx, payload.child_domain)
    head = await delegation_head(tx, payload.child_domain, for_update=True)
    canonical = canonical_delegation_payload(payload)

    existing = await tx.fetch_one(
        """
        SELECT canonical_payload, entry_hash
        FROM {{tables.namespace_delegation_entries}}
        WHERE child_domain = $1 AND sequence = $2
        """,
        payload.child_domain,
        payload.sequence,
    )
    if existing is not None:
        if bytes(existing["canonical_payload"]) != canonical or existing["entry_hash"] != assertion.entry_hash:
            raise DelegationStateError(
                "namespace_delegation_conflict",
                "delegation sequence already has different canonical bytes",
            )
        stored_signatures = {
            row["controller_did"]: row["signature"]
            for row in await tx.fetch_all(
                """
                SELECT controller_did, signature
                FROM {{tables.namespace_delegation_signatures}}
                WHERE child_domain = $1 AND sequence = $2
                """,
                payload.child_domain,
                payload.sequence,
            )
        }
        for attachment in assertion.signatures:
            if stored_signatures.get(attachment.controller_did) != attachment.signature:
                raise DelegationStateError(
                    "namespace_delegation_conflict",
                    "ordinary retry cannot add or replace a signature attachment",
                )
        return await stored_assertion(tx, payload.child_domain, payload.sequence)

    if len(assertion.signatures) != 1 or assertion.signatures[0].controller_did != authority_did:
        raise DelegationStateError(
            "delegation_signer_not_authority",
            "delegation transition is not signed by its current authority",
            status_code=403,
        )

    if head is None:
        valid = payload.operation == "delegate" and payload.sequence == 1
    else:
        valid = (
            payload.parent_domain == head["parent_domain"]
            and payload.sequence == head["head_sequence"] + 1
            and payload.previous_delegation_hash == head["head_hash"]
            and (
                (head["head_operation"] == "revoke" and payload.operation == "delegate")
                or (head["head_operation"] != "revoke" and payload.operation in {"rotate", "revoke"})
            )
        )
        if payload.operation == "revoke":
            valid = valid and payload.child_controller_did == head["head_controller_did"]
        if payload.operation == "rotate":
            valid = valid and payload.child_controller_did != head["head_controller_did"]
    if not valid:
        raise DelegationStateError(
            "namespace_delegation_transition_invalid",
            "delegation transition does not extend the current head",
        )

    if head is None:
        await tx.execute(
            """
            INSERT INTO {{tables.namespace_delegation_heads}}
                (child_domain, parent_domain, head_sequence, head_hash,
                 head_operation, head_controller_did)
            VALUES ($1, $2, $3, $4, $5, $6)
            """,
            payload.child_domain,
            payload.parent_domain,
            payload.sequence,
            assertion.entry_hash,
            payload.operation,
            payload.child_controller_did,
        )
    await tx.execute(
        """
        INSERT INTO {{tables.namespace_delegation_entries}}
            (child_domain, parent_domain, sequence, operation,
             child_controller_did, previous_delegation_hash,
             canonical_payload, entry_hash)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        """,
        payload.child_domain,
        payload.parent_domain,
        payload.sequence,
        payload.operation,
        payload.child_controller_did,
        payload.previous_delegation_hash,
        canonical,
        assertion.entry_hash,
    )
    attachment = assertion.signatures[0]
    await tx.execute(
        """
        INSERT INTO {{tables.namespace_delegation_signatures}}
            (child_domain, sequence, controller_did, signature)
        VALUES ($1, $2, $3, $4)
        """,
        payload.child_domain,
        payload.sequence,
        attachment.controller_did,
        attachment.signature,
    )
    if head is not None:
        await tx.execute(
            """
            UPDATE {{tables.namespace_delegation_heads}}
            SET head_sequence = $2, head_hash = $3, head_operation = $4,
                head_controller_did = $5, updated_at = NOW()
            WHERE child_domain = $1
            """,
            payload.child_domain,
            payload.sequence,
            assertion.entry_hash,
            payload.operation,
            payload.child_controller_did,
        )
    return await stored_assertion(tx, payload.child_domain, payload.sequence)


async def stored_delegation_chain(tx, child_domain: str, *, max_depth: int = 128) -> list[dict]:
    """Return the persisted reachable suffix without consulting DNS."""
    head = await delegation_head(tx, child_domain)
    if head is None:
        return []
    chain = [await stored_assertion(tx, child_domain, head["head_sequence"])]
    visited = {child_domain}
    parent_domain = head["parent_domain"]
    for _ in range(max_depth):
        if parent_domain in visited:
            raise DelegationStateError("delegation_chain_inconsistent", "delegation chain cycle")
        visited.add(parent_domain)
        parent_head = await delegation_head(tx, parent_domain)
        parent_row = await tx.fetch_one(
            """
            SELECT controller_did, active_delegation_hash
            FROM {{tables.dns_namespaces}}
            WHERE domain = $1 AND deleted_at IS NULL
            """,
            parent_domain,
        )
        if parent_head is None:
            if parent_row is not None and parent_row["active_delegation_hash"] is not None:
                raise DelegationStateError(
                    "delegation_chain_inconsistent", "inherited marker has no delegation head"
                )
            break
        if parent_row is None:
            same_cohort = await tx.fetch_value(
                """
                SELECT EXISTS(
                    SELECT 1
                    FROM {{tables.registry_migration_cutovers}} c
                    JOIN {{tables.registry_migration_items}} starting
                      ON starting.cutover_id=c.cutover_id
                     AND starting.role=c.role
                     AND starting.kind='namespace'
                    JOIN {{tables.dns_namespaces}} starting_namespace
                      ON starting_namespace.namespace_id::text=starting.item_key
                     AND starting_namespace.domain=$1
                    JOIN {{tables.registry_migration_items}} ancestor
                      ON ancestor.cutover_id=c.cutover_id
                     AND ancestor.role=c.role
                     AND ancestor.kind='delegation_head'
                     AND ancestor.item_key=$2
                    WHERE c.role='destination'
                      AND c.state IN ('verified','dns_authorized','overlap','completed')
                )
                """,
                child_domain,
                parent_domain,
            )
            if not same_cohort or parent_head["head_operation"] == "revoke":
                raise DelegationStateError(
                    "delegation_chain_inconsistent",
                    "rowless ancestor is not part of the imported delegation cohort",
                )
            chain.insert(
                0,
                await stored_assertion(
                    tx, parent_domain, parent_head["head_sequence"]
                ),
            )
            parent_domain = parent_head["parent_domain"]
            continue
        marker = parent_row["active_delegation_hash"]
        if marker is None:
            break
        if (
            parent_row is None
            or parent_head["head_operation"] == "revoke"
            or marker != parent_head["head_hash"]
            or parent_row["controller_did"] != parent_head["head_controller_did"]
        ):
            raise DelegationStateError(
                "delegation_chain_inconsistent", "inherited ancestor state is inconsistent"
            )
        chain.insert(0, await stored_assertion(tx, parent_domain, parent_head["head_sequence"]))
        parent_domain = parent_head["parent_domain"]
    else:
        raise DelegationStateError("delegation_chain_inconsistent", "delegation chain too deep")
    return chain
