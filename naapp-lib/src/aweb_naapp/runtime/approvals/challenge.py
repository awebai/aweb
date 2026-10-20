"""The bytes an authenticator's challenge commits to.

Every adapter derives its challenge from the same binding, so a proof made for
one approval, request digest, policy version or decision cannot be replayed for
another. The nonce is fresh per challenge and is held by the adapter's trusted
server state.
"""

from __future__ import annotations

import hashlib

from awid.signing import canonical_json_bytes

from aweb_naapp.runtime.approvals.model import Approval, Decision

DOMAIN_PREFIX = b"aweb.approval-challenge/1\n"


def challenge_binding(approval: Approval, decision: Decision, nonce: bytes) -> bytes:
    fields = {
        "approval_id": approval.approval_id,
        "decision": decision.value,
        "nonce": nonce.hex(),
        "policy_ref": approval.policy_ref,
        "policy_version": approval.policy_version,
        "request_sha256": approval.request_sha256,
    }
    return hashlib.sha256(DOMAIN_PREFIX + canonical_json_bytes(fields)).digest()
