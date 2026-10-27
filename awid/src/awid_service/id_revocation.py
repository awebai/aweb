"""Identity revocation (docs/id-certificates.md §"Revocation authority and cascade").

Revocation takes the registration gate's locks in the same order
(awid_service.id_tree_gate), so it serializes with registration,
re-parenting and rotation in the domain, and it times itself after its last
lock wait. The ID itself, its current parent while that parent is valid, and
the namespace root may revoke; only the root may name an earlier cutoff.
"""

from __future__ import annotations

from datetime import datetime

from awid_service.id_tree_clock import Clock, serialization_time
from awid_service.id_tree_gate import (
    IdentityTreeRefusal,
    identity_parent_did,
    lock_domain,
    lock_keys_and_subject,
    open_exact_epoch,
    wire_time,
)
from awid_service.namespace_epochs import latest_domain_event

SELF = "self"
PARENT = "parent"
ROOT = "root"


async def revoke_identity(
    db, *, domain: str, subject_id: str, expected_head: str | None, effective_from: datetime | None,
    signer: str, clock: Clock,
) -> dict:
    """Revoke ``subject_id`` for ``signer``; return its ``{revoked_at, effective_from}``."""
    async with db.transaction() as tx:
        namespace = await lock_domain(tx, domain)
        # Every writer of this domain's tree holds the domain lock, so the head
        # read here cannot be re-parented before the subject row is locked.
        head = await tx.fetch_one(
            """
            SELECT certificate_id, parent_kind, parent_id
            FROM {{tables.id_certificates}}
            WHERE id = $1 AND domain = $2 AND superseded_at IS NULL
            """,
            subject_id, domain,
        )
        parent_did = None if head is None else identity_parent_did(head["parent_kind"], head["parent_id"])
        keys, subject = await lock_keys_and_subject(tx, dids={subject_id, parent_did}, subject_id=subject_id)
        # The last lock wait is behind us: everything below reads the state
        # those locks hold still, and the witness time is sampled from here.

        if subject is None:
            raise IdentityTreeRefusal("unknown_id", 404)
        if subject["domain"] != domain:
            raise IdentityTreeRefusal("domain_mismatch")
        if expected_head != head["certificate_id"]:
            raise IdentityTreeRefusal("head_conflict", 409)

        actor = await _actor(tx, domain, namespace, subject_id, parent_did, keys, signer)
        if effective_from is not None and actor != ROOT:
            raise IdentityTreeRefusal("backdate_forbidden", 403)
        if actor == PARENT:
            # A parent's authority needs its whole current chain verified, which
            # the shared chain verifier does over a status snapshot; until that
            # runs here, no parent revocation can succeed.
            raise IdentityTreeRefusal("evidence_unavailable", 503)

        signer_key_epoch = None
        if actor == SELF:
            signer_key_epoch = await tx.fetch_value(
                "SELECT MAX(created_at) FROM {{tables.did_aw_log}} WHERE did_aw = $1", subject_id,
            )
        now = serialization_time(clock, await latest_domain_event(tx, domain), signer_key_epoch)
        cutoff = now if effective_from is None else effective_from
        if cutoff > now:
            raise IdentityTreeRefusal("invalid_cutoff")

        if subject["revoked_at"] is not None:
            # A repeat writes nothing; only the root corrects a cutoff, and
            # only to an earlier one.
            if effective_from is None or cutoff == subject["effective_from"]:
                return _revocation(subject["revoked_at"], subject["effective_from"])
            if cutoff > subject["effective_from"]:
                raise IdentityTreeRefusal("invalid_cutoff")
            await tx.execute(
                "UPDATE {{tables.id_identities}} SET effective_from = $2 WHERE id = $1", subject_id, cutoff,
            )
            return _revocation(subject["revoked_at"], cutoff)

        await tx.execute(
            """
            UPDATE {{tables.id_identities}}
            SET revoked_at = $2, effective_from = $3, revoked_by = $4
            WHERE id = $1
            """,
            subject_id, now, cutoff, signer,
        )
    return _revocation(now, cutoff)


async def _actor(tx, domain, namespace, subject_id, parent_did, keys, signer) -> str:
    """Which allowed revoker ``signer`` is; refuse any other signer."""
    if keys.get(subject_id) == signer:
        return SELF
    if parent_did is not None and keys.get(parent_did) == signer:
        parent_revoked = await tx.fetch_value(
            "SELECT revoked_at FROM {{tables.id_identities}} WHERE id = $1", parent_did,
        )
        if parent_revoked is not None:
            raise IdentityTreeRefusal("revocation_forbidden", 403)
        return PARENT
    epoch = await open_exact_epoch(tx, domain, namespace)
    if epoch is None:
        raise IdentityTreeRefusal("evidence_unavailable", 503)
    if epoch["did_key"] != signer:
        raise IdentityTreeRefusal("revocation_forbidden", 403)
    return ROOT


def _revocation(revoked_at: datetime, effective_from: datetime) -> dict:
    return {"revoked_at": wire_time(revoked_at), "effective_from": wire_time(effective_from)}
