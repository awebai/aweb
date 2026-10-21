"""The bytes an authenticator's challenge commits to.

Every adapter derives its challenge from the same binding, so a proof made for
one approval, candidate, request digest, policy version, purpose or task answer
cannot be replayed for another. The nonce is fresh per challenge and is held by
the adapter's trusted server state.
"""

from __future__ import annotations

import hashlib

from awid.signing import canonical_json_bytes

from aweb_naapp.runtime.approvals.model import Approval, Candidate, Purpose

DOMAIN_PREFIX = b"aweb.approval-challenge/1\n"


def challenge_binding(
    approval: Approval,
    candidate: Candidate,
    purpose: Purpose,
    nonce: bytes,
    task_answer_ref: str | None = None,
) -> bytes:
    fields = {
        "approval_id": approval.approval_id,
        "candidate_subject": candidate.subject,
        "candidate_subject_type": candidate.subject_type,
        "nonce": nonce.hex(),
        "policy_ref": approval.policy_ref,
        "policy_version": approval.policy_version,
        "purpose": purpose.value,
        "request_sha256": approval.request_sha256,
        "task_answer_ref": task_answer_ref,
    }
    return hashlib.sha256(DOMAIN_PREFIX + canonical_json_bytes(fields)).digest()
