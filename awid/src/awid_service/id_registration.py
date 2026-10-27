"""The atomic identity-tree registration gate (docs/id-certificates.md §3).

One transaction serializes registration with namespace and parent rotation,
revocation and re-parenting, checks the current state after its last lock
wait, and records the witnessed registration with the exact issuer key
version. Shape, signature and R1-R3 checks on the presented chain run before
the transaction (awid_service.id_chains).

Lock order, shared by every identity-tree writer of a domain:
  1. pg_advisory_xact_lock on the exact canonical domain;
  2. the domain's dns_namespaces row (rotation, reverify and delete hold it
     FOR UPDATE, so the open epoch read after it is current);
  3. the subject's and parent's did_aw_mappings rows, sorted by did_aw
     (did:aw rotation holds its row FOR UPDATE);
  4. the subject's id_identities row.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from awid.id_certificates import id_certificate_id

from awid_service.id_tree_clock import Clock, serialization_time
from awid_service.namespace_epochs import DNS_EXACT, latest_domain_event


class RegistrationRefused(Exception):
    """A contract refusal; ``code`` is the stable reason, ``status`` its HTTP status."""

    def __init__(self, code: str, status: int = 422):
        super().__init__(code)
        self.code = code
        self.status = status


def wire_time(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


async def lock_domain(tx, domain: str) -> None:
    await tx.execute("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", f"aweb.id-tree/{domain}")


async def register_certificate(
    db, *, chain: list[dict], expected_head: str | None, invitation_id: str | None,
    signer: str, clock: Clock,
) -> dict:
    """Register the leaf of a structurally verified ``chain``; return the receipt."""
    signed = chain[-1]
    cert = signed["certificate"]
    digest = id_certificate_id(cert)
    domain = cert["domain"]
    parent = cert["parent"]
    parent_did = parent["id"] if parent["kind"] == "identity" and parent["id"].startswith("did:aw:") else None

    async with db.transaction() as tx:
        await lock_domain(tx, domain)
        namespace = await tx.fetch_one(
            """
            SELECT namespace_id
            FROM {{tables.dns_namespaces}}
            WHERE domain = $1 AND deleted_at IS NULL
            FOR SHARE
            """,
            domain,
        )
        mapped = await tx.fetch_all(
            """
            SELECT did_aw, current_did_key
            FROM {{tables.did_aw_mappings}}
            WHERE did_aw = ANY($1::text[])
            ORDER BY did_aw
            FOR SHARE
            """,
            sorted({cert["id"], parent_did} - {None}),
        )
        keys = {row["did_aw"]: row["current_did_key"] for row in mapped}
        subject = await tx.fetch_one(
            """
            SELECT id, domain, kind, revoked_at
            FROM {{tables.id_identities}}
            WHERE id = $1
            FOR UPDATE
            """,
            cert["id"],
        )
        # The last lock wait is behind us: everything below reads the state
        # those locks hold still, and the witness time is sampled from here.

        if keys.get(cert["id"]) != signer:
            raise RegistrationRefused("subject_mismatch", 403)

        receipt = await tx.fetch_one(
            """
            SELECT registered_at, invitation_id
            FROM {{tables.id_certificates}}
            WHERE certificate_id = $1
            """,
            digest,
        )
        if receipt is not None:
            if _invitation(receipt["invitation_id"]) != invitation_id:
                raise RegistrationRefused("invitation_conflict", 409)
            return {"certificate_id": digest, "registered_at": wire_time(receipt["registered_at"])}

        if invitation_id is not None:
            used = await tx.fetch_one(
                "SELECT 1 FROM {{tables.id_certificates}} WHERE invitation_id = $1::uuid", invitation_id,
            )
            if used is not None:
                raise RegistrationRefused("invitation_conflict", 409)

        head = None
        if subject is not None:
            if subject["kind"] != cert["kind"]:
                raise RegistrationRefused("identity_kind_immutable")
            if subject["domain"] != domain:
                raise RegistrationRefused("domain_mismatch")
            if subject["revoked_at"] is not None:
                raise RegistrationRefused("subject_revoked")
            head = await tx.fetch_value(
                """
                SELECT certificate_id
                FROM {{tables.id_certificates}}
                WHERE id = $1 AND superseded_at IS NULL
                """,
                cert["id"],
            )
        if expected_head != head:
            raise RegistrationRefused("head_conflict", 409)

        if parent["kind"] == "namespace":
            issuer_key_seq, issuer_epoch_at = await _namespace_issuer(tx, cert, namespace)
        else:
            issuer_key_seq, issuer_epoch_at = await _identity_issuer(tx, cert, keys)

        await _require_registered_ancestry(tx, chain)

        subject_epoch_at = await tx.fetch_value(
            "SELECT MAX(created_at) FROM {{tables.did_aw_log}} WHERE did_aw = $1", cert["id"],
        )
        registered_at = serialization_time(
            clock, await latest_domain_event(tx, domain), issuer_epoch_at, subject_epoch_at,
        )

        if subject is None:
            inserted = await tx.fetch_one(
                """
                INSERT INTO {{tables.id_identities}} (id, domain, kind, first_registered_at)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (id) DO NOTHING
                RETURNING id
                """,
                cert["id"], domain, cert["kind"], registered_at,
            )
            if inserted is None:
                raise RegistrationRefused("head_conflict", 409)
        else:
            await tx.execute(
                """
                UPDATE {{tables.id_certificates}}
                SET superseded_at = $2
                WHERE id = $1 AND superseded_at IS NULL
                """,
                cert["id"], registered_at,
            )
        await tx.execute(
            """
            INSERT INTO {{tables.id_certificates}}
                (certificate_id, id, domain, parent_kind, parent_id, kind, issuer_key,
                 signed_json, supporting_chain_json, issuer_key_seq, invitation_id,
                 registered_at, superseded_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::uuid, $12, NULL)
            """,
            digest, cert["id"], domain, parent["kind"], parent["id"], cert["kind"], cert["issuer_key"],
            canonical_json(signed),
            canonical_json({"v": 1, "type": "aweb.id-chain", "certificates": chain}),
            issuer_key_seq, invitation_id, registered_at,
        )
    return {"certificate_id": digest, "registered_at": wire_time(registered_at)}


def _invitation(value) -> str | None:
    return None if value is None else str(value)


async def _namespace_issuer(tx, cert: dict, namespace) -> tuple[int, datetime]:
    """The open exact epoch of this domain, which must hold the issuer key."""
    epoch = None
    if namespace is not None:
        epoch = await tx.fetch_one(
            """
            SELECT seq, did_key, established_by, registered_at
            FROM {{tables.id_namespace_epochs}}
            WHERE domain = $1 AND retired_at IS NULL
            """,
            cert["domain"],
        )
    if epoch is None or epoch["established_by"] != DNS_EXACT:
        raise RegistrationRefused("evidence_unavailable")
    if epoch["did_key"] != cert["issuer_key"]:
        raise RegistrationRefused("issuer_key_not_current")
    return epoch["seq"], epoch["registered_at"]


async def _identity_issuer(tx, cert: dict, keys: dict[str, str]) -> tuple[int, datetime]:
    """The registered, unrevoked parent's current key version."""
    parent_id = cert["parent"]["id"]
    parent = await tx.fetch_one(
        """
        SELECT i.domain, i.kind, i.revoked_at
        FROM {{tables.id_identities}} i
        JOIN {{tables.id_certificates}} c ON c.id = i.id AND c.superseded_at IS NULL
        WHERE i.id = $1
        """,
        parent_id,
    )
    if parent is None or parent_id not in keys:
        raise RegistrationRefused("unregistered_parent")
    if parent["domain"] != cert["domain"]:
        raise RegistrationRefused("domain_mismatch")
    if cert["kind"] == "human" and parent["kind"] != "human":
        raise RegistrationRefused("human_issuer_is_agent")
    if parent["revoked_at"] is not None:
        raise RegistrationRefused("parent_revoked")
    if keys[parent_id] != cert["issuer_key"]:
        raise RegistrationRefused("issuer_key_not_current")
    epoch = await tx.fetch_one(
        """
        SELECT seq, created_at
        FROM {{tables.did_aw_log}}
        WHERE did_aw = $1
        ORDER BY seq DESC
        LIMIT 1
        """,
        parent_id,
    )
    return epoch["seq"], epoch["created_at"]


async def _require_registered_ancestry(tx, chain: list[dict]) -> None:
    """The presented ancestors are exactly the registered current heads.

    The registry retains the presented chain as the revision's supporting
    evidence, so it must be the ancestry the registry itself holds.
    """
    for link in chain[:-1]:
        current = await tx.fetch_value(
            """
            SELECT signed_json
            FROM {{tables.id_certificates}}
            WHERE id = $1 AND superseded_at IS NULL
            """,
            link["certificate"]["id"],
        )
        if current is None:
            raise RegistrationRefused("unregistered_parent")
        if json.loads(current) != link:
            raise RegistrationRefused("superseded_certificate")
