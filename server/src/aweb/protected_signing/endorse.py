"""Root endorsement, with its own frozen-policy/head observation."""
import hashlib
from time import monotonic

from aweb_naapp.runtime.protected_signer import SignerRefused
from .admission import checked_policy, read_policy, root_head


class EndorseEffects:
    def __init__(self, composition, *, timer=monotonic):
        self.c, self.timer = composition, timer

    async def observe(self, operation, actor, *, purpose):
        c, subject = self.c, operation.intent()["subject"]
        if operation.audience != c.registry.registry_url:
            raise SignerRefused("scope_refused")
        started = self.timer()
        policy = await read_policy(c)
        if not set(subject["teams"]) <= set(policy.fields()["teams"]):
            raise SignerRefused("admission_policy_missing")
        head = await root_head(c, subject["root_id"], subject["root_key"], require_enrolled=False)
        return EndorsementObservation(self, operation, policy, head, started + 60)

    async def record_endorsement(self, tx, operation, request, result, evidence, *, artifact):
        from awid.id_certificates import id_certificate_id
        from aweb_naapp.runtime.protected_signer import VerifiedProtectedEffect

        if type(evidence) is not VerifiedProtectedEffect:
            raise SignerRefused("proof_invalid")
        await evidence.require_in(tx, operation, clock=self.c.signer.clock)
        c = operation.context
        await tx.execute(
            "INSERT INTO {{tables.protected_root_endorsements}} "
            "(service_id,root_id,human_id,human_domain,operation_id,certificate_id,policy_digest) "
            "VALUES($1,$2,$3,$4,$5,$6,$7)",
            c.service_id, operation.intent()["subject"]["root_id"], c.human_id, c.human_domain,
            operation.operation_id, id_certificate_id(artifact), request["admission_policy"]["digest"],
        )
        await evidence.require_in(tx, operation, clock=self.c.signer.clock)



class EndorsementObservation:
    def __init__(self, adapter, operation, policy, head, deadline):
        self.adapter, self.operation, self.policy, self.head, self.deadline = adapter, operation, policy, head, deadline

    def require_fresh(self):
        if self.adapter.timer() >= self.deadline:
            raise SignerRefused("evidence_unavailable")

    async def _current(self, tx):
        return await checked_policy(self.adapter.c, tx, self.policy)

    async def _hold_endorsement(self, tx, *, conflict="operation_conflict"):
        op = self.operation
        key = int.from_bytes(hashlib.sha256(
            b"aweb.root-endorsement/1\n" + op.context.service_id.encode() + b"\n" + op.intent()["subject"]["root_id"].encode()
        ).digest()[:8], "big", signed=True)
        await tx.execute("SELECT pg_advisory_xact_lock($1::bigint)", key)
        row = await tx.fetch_one(
            "SELECT operation_id FROM {{tables.protected_root_endorsements}} WHERE service_id=$1 AND root_id=$2 FOR SHARE",
            op.context.service_id, op.intent()["subject"]["root_id"],
        )
        if row is not None and row["operation_id"] != op.operation_id:
            raise SignerRefused(conflict)

    async def freeze(self, tx):
        op, subject = self.operation, self.operation.intent()["subject"]
        fields = await self._current(tx)
        await self._hold_endorsement(tx)
        if self.head is not None:
            # A new certificate over existing ancestry needs its own
            # re-endorsement/reparent path. Exact operation replay bypasses
            # minting and returns the original stored preparation.
            raise SignerRefused("subject_ineligible")
        existing = await tx.fetch_one(
            "SELECT operation_id FROM {{tables.protected_root_endorsements}} WHERE service_id=$1 AND root_id=$2 FOR SHARE",
            op.context.service_id, subject["root_id"],
        )
        if existing is not None:
            raise SignerRefused("operation_conflict")
        return {"registry": self.adapter.c.registry.registry_url, "expected_head": None,
            "responsibility_statement": op.spec.display.responsibility_statement,
            "admission_policy": fields}

    async def check(self, tx, request):
        fields = await self._current(tx)
        await self._hold_endorsement(tx, conflict="operation_mismatch")
        if request["admission_policy"] != fields:
            raise SignerRefused("policy_changed")
        if request["expected_head"] != self.head:
            raise SignerRefused("operation_mismatch")
        self.require_fresh()
