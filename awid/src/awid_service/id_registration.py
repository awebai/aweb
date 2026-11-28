"""The atomic identity-tree registration gate (docs/id-certificates.md §3).

One transaction serializes registration with namespace and parent rotation,
revocation and re-parenting (lock order in awid_service.id_tree_gate), checks
the current state after its last lock wait, and records the witnessed
registration with the exact issuer key version. Shape, signature and R1-R3
checks on the presented chain run before the transaction
(awid_service.id_chains).

The rule itself is ``registration_rule``: it asks for each fact as it needs
it, the transaction reads that fact under the locks, and the transaction
writes what the rule admits.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, Generator
from dataclasses import dataclass
from datetime import datetime
from typing import Any

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


# The facts the rule asks for, each read when the rule reaches it.
RECEIPT = "receipt"  # Receipt | None: the stored registration of the exact digest
INVITATION_USED = "invitation_used"  # bool: another certificate holds the invitation
HEAD = "head"  # str | None: the registered subject's current head
ROOT = "root"  # RootEpoch | None: the open epoch, with current root authority
PARENT = "parent"  # ParentIdentity | None: the issuing identity's registered row
PARENT_EPOCH = "parent_epoch"  # (seq, created_at): the issuer's current key version
PARENT_CHAIN = "parent_chain"  # dict: S1's verdict on the issuer's whole chain


@dataclass(frozen=True)
class Ancestor:
    """Asks for the registered current head (dict | None) of ``chain[index]``."""

    index: int


Ask = str | Ancestor


@dataclass(frozen=True)
class RegistrationRequest:
    """What the request and the gate's locks give the rule before it asks.

    ``keys`` maps each locked did:aw to its current did:key; ``subject`` is the
    registered identity the certificate names, held by the locks.
    """

    chain: list[dict]
    signer: str
    expected_head: str | None
    invitation_id: str | None
    keys: dict[str, str]
    subject: Subject | None


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
    """The certificate becomes its subject's head under this issuer key version."""

    issuer_key_seq: int
    issuer_epoch_at: datetime


Verdict = Refused | Repeated | Admitted


def registration_rule(
    request: RegistrationRequest,
) -> Generator[Ask, Any, Verdict]:
    """The registration rule. It yields each fact it needs, in the order it needs
    them, receives that fact's value, and returns the verdict. It asks for
    nothing after the check that decides, so an earlier refusal or an exact
    repeat never reads the later facts.
    """
    cert = request.chain[-1]["certificate"]
    parent = cert["parent"]

    if request.keys.get(cert["id"]) != request.signer:
        return Refused("subject_mismatch", 403)

    receipt: Receipt | None = yield RECEIPT
    if receipt is not None:
        if receipt.invitation_id != request.invitation_id:
            return Refused("invitation_conflict", 409)
        return Repeated(receipt.registered_at)

    if request.invitation_id is not None and (yield INVITATION_USED):
        return Refused("invitation_conflict", 409)

    head = None
    subject = request.subject
    if subject is not None:
        if subject.kind != cert["kind"]:
            return Refused("identity_kind_immutable")
        if subject.domain != cert["domain"]:
            return Refused("domain_mismatch")
        if subject.revoked_at is not None:
            return Refused("subject_revoked")
        head = yield HEAD
    if request.expected_head != head:
        return Refused("head_conflict", 409)

    root: RootEpoch | None = yield ROOT
    if root is None:
        return Refused("evidence_unavailable", 503)
    if parent["kind"] == "namespace":
        if root.did_key != cert["issuer_key"]:
            return Refused("issuer_key_not_current")
        issuer_key_seq, issuer_epoch_at = root.seq, root.registered_at
    else:
        issuer: ParentIdentity | None = yield PARENT
        if issuer is None or parent["id"] not in request.keys:
            return Refused("unregistered_parent")
        if issuer.domain != cert["domain"]:
            return Refused("domain_mismatch")
        if cert["kind"] == "human" and issuer.kind != "human":
            return Refused("human_issuer_is_agent")
        if issuer.revoked_at is not None:
            return Refused("parent_revoked")
        if request.keys[parent["id"]] != cert["issuer_key"]:
            return Refused("issuer_key_not_current")
        issuer_key_seq, issuer_epoch_at = yield PARENT_EPOCH

    for index, link in enumerate(request.chain[:-1]):
        current = yield Ancestor(index)
        if current is None:
            return Refused("unregistered_parent")
        if current != link:
            return Refused("superseded_certificate")

    if parent["kind"] != "namespace":
        verdict = yield PARENT_CHAIN
        if verdict["identity_valid"] is not True:
            return Refused(
                verdict["reason"], 503 if verdict["outcome"] == "unavailable" else 422
            )
    return Admitted(issuer_key_seq, issuer_epoch_at)


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
        async def read(ask: Ask):
            if ask == RECEIPT:
                return await _receipt(tx, digest)
            if ask == INVITATION_USED:
                return await _invitation_used(tx, invitation_id)
            if ask == HEAD:
                return await _head(tx, cert["id"])
            if ask == ROOT:
                root = await current_root(tx, domain, namespace, dns_authority)
                if root is None:
                    return None
                return RootEpoch(root["did_key"], root["seq"], root["registered_at"])
            if ask == PARENT:
                return await _parent_identity(tx, parent_did)
            if ask == PARENT_EPOCH:
                return await _key_epoch(tx, parent_did)
            if ask == PARENT_CHAIN:
                return await verify_parent_chain(
                    tx,
                    domain=domain,
                    parent=parent_did,
                    parent_key=keys[parent_did],
                    dns_authority=dns_authority,
                    clock=clock,
                )
            return await _registered_head(tx, chain[ask.index]["certificate"]["id"])

        verdict = await _decide(
            registration_rule(
                RegistrationRequest(
                    chain=chain,
                    signer=signer,
                    expected_head=expected_head,
                    invitation_id=invitation_id,
                    keys=keys,
                    subject=None
                    if subject is None
                    else Subject(
                        subject["kind"], subject["domain"], subject["revoked_at"]
                    ),
                )
            ),
            read,
        )
        if isinstance(verdict, Refused):
            raise IdentityTreeRefusal(verdict.code, verdict.status)
        if isinstance(verdict, Repeated):
            return {
                "certificate_id": digest,
                "registered_at": wire_time(verdict.registered_at),
            }

        issuer_key_seq, issuer_epoch_at = (
            verdict.issuer_key_seq,
            verdict.issuer_epoch_at,
        )
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


async def _decide(
    rule: Generator[Ask, Any, Verdict], read: Callable[[Ask], Awaitable[Any]]
) -> Verdict:
    """Run ``rule``, answering each fact it asks for with ``read``."""
    try:
        ask = next(rule)
        while True:
            ask = rule.send(await read(ask))
    except StopIteration as done:
        return done.value


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
