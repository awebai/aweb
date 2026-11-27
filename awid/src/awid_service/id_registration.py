"""The atomic identity-tree registration gate (docs/id-certificates.md §3).

One transaction serializes registration with namespace and parent rotation,
revocation and re-parenting (lock order in awid_service.id_tree_gate), checks
the current state after its last lock wait, and records the witnessed
registration with the exact issuer key version. Shape, signature and R1-R3
checks on the presented chain run before the transaction
(awid_service.id_chains).

The rule itself is ``registration_verdict``: the transaction reads its facts
under the locks, the verdict decides, and the transaction writes what it
admits.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime

from awid.dns_verify import DomainAuthority
from awid.id_certificates import id_certificate_id

from awid_service.id_tree_clock import Clock, serialization_time
from awid_service.id_tree_gate import (
    IdentityTreeRefusal,
    canonical_json,
    identity_parent_did,
    lock_domain,
    lock_keys_and_subject,
    current_root,
    wire_time,
)
from awid_service.id_status import verify_parent_chain
from awid_service.namespace_epochs import latest_domain_event


@dataclass(frozen=True)
class Receipt:
    """The stored registration of the presented certificate's exact bytes."""

    registered_at: datetime
    invitation_id: str | None


@dataclass(frozen=True)
class Subject:
    """The registered identity the certificate names, as the gate's locks hold it."""

    kind: str
    domain: str
    revoked_at: datetime | None


@dataclass(frozen=True)
class RootEpoch:
    """The domain's open root epoch, present only with current root authority."""

    did_key: str
    seq: int
    registered_at: datetime


@dataclass(frozen=True)
class ParentIdentity:
    """The issuing identity's registered row with its current head."""

    domain: str
    kind: str
    revoked_at: datetime | None


@dataclass(frozen=True)
class RegistrationFacts:
    """Everything the registration rule decides on, read under the gate's locks.

    ``keys`` maps each locked did:aw to its current did:key. ``registered``
    holds, for each presented ancestor in order, its registered current head
    (None when it has none). ``parent_chain`` is S1's verdict on an identity
    parent's whole chain, or the refusal its snapshot raised; it is None for a
    namespace parent or a parent without a current key.
    """

    chain: list[dict]
    signer: str
    expected_head: str | None
    invitation_id: str | None
    keys: dict[str, str]
    receipt: Receipt | None
    invitation_used: bool
    subject: Subject | None
    head: str | None
    root: RootEpoch | None
    parent: ParentIdentity | None
    registered: list[dict | None]
    parent_chain: dict | IdentityTreeRefusal | None


@dataclass(frozen=True)
class Refused:
    code: str
    status: int = 422


@dataclass(frozen=True)
class Repeated:
    """The exact certificate is already registered; its receipt is the answer."""

    registered_at: datetime


@dataclass(frozen=True)
class Admitted:
    """The certificate becomes its subject's head, issued under ``issuer``."""

    issuer: str  # "namespace" or "identity"


Verdict = Refused | Repeated | Admitted


def registration_verdict(facts: RegistrationFacts) -> Verdict:
    """The registration rule: the facts the gate's locks hold, and its verdict."""
    cert = facts.chain[-1]["certificate"]
    parent = cert["parent"]

    if facts.keys.get(cert["id"]) != facts.signer:
        return Refused("subject_mismatch", 403)

    if facts.receipt is not None:
        if facts.receipt.invitation_id != facts.invitation_id:
            return Refused("invitation_conflict", 409)
        return Repeated(facts.receipt.registered_at)

    if facts.invitation_used:
        return Refused("invitation_conflict", 409)

    if facts.subject is not None:
        if facts.subject.kind != cert["kind"]:
            return Refused("identity_kind_immutable")
        if facts.subject.domain != cert["domain"]:
            return Refused("domain_mismatch")
        if facts.subject.revoked_at is not None:
            return Refused("subject_revoked")
    if facts.expected_head != facts.head:
        return Refused("head_conflict", 409)

    if facts.root is None:
        return Refused("evidence_unavailable", 503)
    if parent["kind"] == "namespace":
        if facts.root.did_key != cert["issuer_key"]:
            return Refused("issuer_key_not_current")
    else:
        refused = _identity_issuer_refusal(facts, cert)
        if refused is not None:
            return refused

    for link, current in zip(facts.chain[:-1], facts.registered, strict=True):
        if current is None:
            return Refused("unregistered_parent")
        if current != link:
            return Refused("superseded_certificate")

    if parent["kind"] != "namespace":
        verdict = facts.parent_chain
        if isinstance(verdict, IdentityTreeRefusal):
            return Refused(verdict.code, verdict.status)
        if verdict["identity_valid"] is not True:
            return Refused(
                verdict["reason"], 503 if verdict["outcome"] == "unavailable" else 422
            )
    return Admitted(parent["kind"])


def _identity_issuer_refusal(facts: RegistrationFacts, cert: dict) -> Refused | None:
    """The registered, unrevoked parent must hold the issuer key now."""
    parent_id = cert["parent"]["id"]
    parent = facts.parent
    if parent is None or parent_id not in facts.keys:
        return Refused("unregistered_parent")
    if parent.domain != cert["domain"]:
        return Refused("domain_mismatch")
    if cert["kind"] == "human" and parent.kind != "human":
        return Refused("human_issuer_is_agent")
    if parent.revoked_at is not None:
        return Refused("parent_revoked")
    if facts.keys[parent_id] != cert["issuer_key"]:
        return Refused("issuer_key_not_current")
    return None


async def register_certificate(
    db,
    *,
    chain: list[dict],
    expected_head: str | None,
    invitation_id: str | None,
    signer: str,
    dns_authority: DomainAuthority | None,
    clock: Clock,
) -> dict:
    """Register the leaf of a structurally verified ``chain``; return the receipt."""
    signed = chain[-1]
    cert = signed["certificate"]
    digest = id_certificate_id(cert)
    domain = cert["domain"]
    parent = cert["parent"]
    parent_did = identity_parent_did(parent["kind"], parent["id"])

    async with db.transaction() as tx:
        namespace = await lock_domain(tx, domain)
        keys, subject = await lock_keys_and_subject(
            tx,
            dids={cert["id"], parent_did},
            subject_id=cert["id"],
            parent_id=parent_did,
        )
        # The last lock wait is behind us: everything below reads the state
        # those locks hold still, and the witness time is sampled from here.
        root = await current_root(tx, domain, namespace, dns_authority)
        facts = RegistrationFacts(
            chain=chain,
            signer=signer,
            expected_head=expected_head,
            invitation_id=invitation_id,
            keys=keys,
            receipt=await _receipt(tx, digest),
            invitation_used=invitation_id is not None
            and await _invitation_used(tx, invitation_id),
            subject=None
            if subject is None
            else Subject(subject["kind"], subject["domain"], subject["revoked_at"]),
            head=None if subject is None else await _head(tx, cert["id"]),
            root=None
            if root is None
            else RootEpoch(root["did_key"], root["seq"], root["registered_at"]),
            parent=None
            if parent_did is None
            else await _parent_identity(tx, parent_did),
            registered=[
                await _registered_head(tx, link["certificate"]["id"])
                for link in chain[:-1]
            ],
            parent_chain=await _parent_chain(
                tx, domain, parent_did, keys, dns_authority, clock
            ),
        )

        verdict = registration_verdict(facts)
        if isinstance(verdict, Refused):
            raise IdentityTreeRefusal(verdict.code, verdict.status)
        if isinstance(verdict, Repeated):
            return {
                "certificate_id": digest,
                "registered_at": wire_time(verdict.registered_at),
            }

        if verdict.issuer == "namespace":
            issuer_key_seq, issuer_epoch_at = root["seq"], root["registered_at"]
        else:
            issuer_key_seq, issuer_epoch_at = await _key_epoch(tx, parent_did)
        subject_epoch_at = await tx.fetch_value(
            "SELECT MAX(created_at) FROM {{tables.did_aw_log}} WHERE did_aw = $1",
            cert["id"],
        )
        registered_at = serialization_time(
            clock,
            await latest_domain_event(tx, domain),
            issuer_epoch_at,
            subject_epoch_at,
        )

        if subject is None:
            inserted = await tx.fetch_one(
                """
                INSERT INTO {{tables.id_identities}} (id, domain, kind, first_registered_at)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (id) DO NOTHING
                RETURNING id
                """,
                cert["id"],
                domain,
                cert["kind"],
                registered_at,
            )
            if inserted is None:
                raise IdentityTreeRefusal("head_conflict", 409)
        else:
            await tx.execute(
                """
                UPDATE {{tables.id_certificates}}
                SET superseded_at = $2
                WHERE id = $1 AND superseded_at IS NULL
                """,
                cert["id"],
                registered_at,
            )
        await tx.execute(
            """
            INSERT INTO {{tables.id_certificates}}
                (certificate_id, id, domain, parent_kind, parent_id, kind, issuer_key,
                 signed_json, supporting_chain_json, issuer_key_seq, invitation_id,
                 registered_at, superseded_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::uuid, $12, NULL)
            """,
            digest,
            cert["id"],
            domain,
            parent["kind"],
            parent["id"],
            cert["kind"],
            cert["issuer_key"],
            canonical_json(signed),
            canonical_json({"v": 1, "type": "aweb.id-chain", "certificates": chain}),
            issuer_key_seq,
            invitation_id,
            registered_at,
        )
    return {"certificate_id": digest, "registered_at": wire_time(registered_at)}


async def _receipt(tx, digest: str) -> Receipt | None:
    row = await tx.fetch_one(
        """
        SELECT registered_at, invitation_id
        FROM {{tables.id_certificates}}
        WHERE certificate_id = $1
        """,
        digest,
    )
    if row is None:
        return None
    invitation = row["invitation_id"]
    return Receipt(
        row["registered_at"], None if invitation is None else str(invitation)
    )


async def _invitation_used(tx, invitation_id: str) -> bool:
    used = await tx.fetch_one(
        "SELECT 1 FROM {{tables.id_certificates}} WHERE invitation_id = $1::uuid",
        invitation_id,
    )
    return used is not None


async def _head(tx, id_: str) -> str | None:
    return await tx.fetch_value(
        """
        SELECT certificate_id
        FROM {{tables.id_certificates}}
        WHERE id = $1 AND superseded_at IS NULL
        """,
        id_,
    )


async def _parent_identity(tx, parent_id: str) -> ParentIdentity | None:
    row = await tx.fetch_one(
        """
        SELECT i.domain, i.kind, i.revoked_at
        FROM {{tables.id_identities}} i
        JOIN {{tables.id_certificates}} c ON c.id = i.id AND c.superseded_at IS NULL
        WHERE i.id = $1
        """,
        parent_id,
    )
    if row is None:
        return None
    return ParentIdentity(row["domain"], row["kind"], row["revoked_at"])


async def _registered_head(tx, id_: str) -> dict | None:
    current = await tx.fetch_value(
        """
        SELECT signed_json
        FROM {{tables.id_certificates}}
        WHERE id = $1 AND superseded_at IS NULL
        """,
        id_,
    )
    return None if current is None else json.loads(current)


async def _parent_chain(
    tx,
    domain: str,
    parent_did: str | None,
    keys: dict[str, str],
    dns_authority: DomainAuthority | None,
    clock: Clock,
) -> dict | IdentityTreeRefusal | None:
    """S1's verdict on an identity parent's chain, or the refusal its snapshot raised."""
    if parent_did is None or parent_did not in keys:
        return None
    try:
        return await verify_parent_chain(
            tx,
            domain=domain,
            parent=parent_did,
            parent_key=keys[parent_did],
            dns_authority=dns_authority,
            clock=clock,
        )
    except IdentityTreeRefusal as refused:
        return refused


async def _key_epoch(tx, did_aw: str) -> tuple[int, datetime]:
    """The issuing identity's current key version and when it began."""
    epoch = await tx.fetch_one(
        """
        SELECT seq, created_at
        FROM {{tables.did_aw_log}}
        WHERE did_aw = $1
        ORDER BY seq DESC
        LIMIT 1
        """,
        did_aw,
    )
    return epoch["seq"], epoch["created_at"]
