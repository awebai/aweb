"""Characterize the five served requester paths before moving their rules.

These are authority controls through the real registry, host, SQL and B2/B3.
They do not measure transport budgets; the existing native world's limiter
and notification transport stay unchanged.
"""

from contextlib import asynccontextmanager
from dataclasses import replace
from uuid import uuid4

import pytest
from aweb_naapp.runtime.protected_signer.types import owner_act_operation
from awid.signing import canonical_json_bytes
from nacl.signing import SigningKey

from tests.protected_consumer_support import ready_owner_act_consumer
from tests.test_independent_protected_signer import did
from tests.test_protected_admission_native import admit_operation, endorse, headers, prepare, root_operation
from tests.test_protected_owner_removal_native import legacy_member, owner_removal
from tests.test_protected_removal_native import admitted, removal, self_call

pytest_plugins = ("tests.test_protected_admission_native",)
ROWS = ("admit", "endorse", "remove", "owner_remove", "owner_act")


@asynccontextmanager
async def operation_case(a, row, tmp_path, test_db_factory):
    if row == "owner_act":
        async with ready_owner_act_consumer(a.w, tmp_path, test_db_factory):
            yield owner_act_operation(a.w.operation)
    elif row == "endorse":
        yield root_operation(a)
    elif row == "owner_remove":
        _, certificate = await legacy_member(a, "local")
        yield owner_removal(a, certificate)
    else:
        await endorse(a)
        if row == "admit":
            yield admit_operation(a)
        else:
            _, certificate = await admitted(a)
            yield removal(a, certificate)


def bad_proof(a, operation, *, purpose="prepare"):
    path = "/protected-operations" if purpose == "prepare" else "/protected-operations/" + operation.operation_id
    if purpose == "execute":
        path += "/execute"
    method = "GET" if purpose == "receipt" else "POST"
    body = canonical_json_bytes(operation.intent()) if purpose == "prepare" else b""
    proof = headers(a, body=body, path=path, method=method,
                    label="protected_operation_" + purpose, context=operation.context)
    proof["authorization"] = "DIDKey " + did(a.w.root) + " " + "A" * 86
    return method, path, body, proof


@pytest.mark.asyncio
@pytest.mark.parametrize("row", ROWS)
async def test_each_served_row_requires_proof_and_current_scoped_requester(
    admissions, tmp_path, test_db_factory, row
):
    a = admissions
    async with operation_case(a, row, tmp_path, test_db_factory) as operation:
        method, path, body, proof = bad_proof(a, operation)
        rejected = await a.client.request(method, path, content=body, headers=proof)
        assert (rejected.status_code, rejected.json()) == (401, {"detail": "requester_invalid"})
        assert await a.w.app.signer.lookup_context(operation.operation_id) is None
        # A current registered key is not an active requester grant. This
        # remains mandatory even for rows with no actor/subject equality.
        await a.w.db.execute(
            "UPDATE {{tables.protected_requester_bindings}} SET active=false WHERE principal=$1", a.w.root_id,
        )
        try:
            rejected = await prepare(a, operation)
            assert (rejected.status_code, rejected.json()) == (403, {"detail": "scope_refused"})
            assert await a.w.app.signer.lookup_context(operation.operation_id) is None
        finally:
            await a.w.db.execute(
                "UPDATE {{tables.protected_requester_bindings}} SET active=true WHERE principal=$1", a.w.root_id,
            )
        accepted = await prepare(a, operation)
        assert accepted.status_code == 200, accepted.text
        assert accepted.json()["payload"]["request"]["requester"] == a.w.root_id
        # The same proof rule applies to actual retained reads and execution,
        # including live-floor rows: malformed proofs never reach UV/signing.
        for purpose in ("receipt", "execute"):
            method, path, body, proof = bad_proof(a, operation, purpose=purpose)
            rejected = await a.client.request(method, path, content=body, headers=proof)
            assert (rejected.status_code, rejected.json()) == (401, {"detail": "requester_invalid"})
        # A valid original proof cannot use a grant withdrawn after prepare,
        # on either retained phase. No binding rule substitutes for that grant.
        await a.w.db.execute(
            "UPDATE {{tables.protected_requester_bindings}} SET active=false WHERE principal=$1", a.w.root_id,
        )
        try:
            for purpose in ("receipt", "execute"):
                method, path, body, _ = bad_proof(a, operation, purpose=purpose)
                proof = headers(a, body=body, path=path, method=method,
                                label="protected_operation_" + purpose, context=operation.context)
                rejected = await a.client.request(method, path, content=body, headers=proof)
                assert (rejected.status_code, rejected.json()) == (403, {"detail": "scope_refused"})
        finally:
            await a.w.db.execute(
                "UPDATE {{tables.protected_requester_bindings}} SET active=true WHERE principal=$1", a.w.root_id,
            )
        if row in {"owner_remove", "owner_act"}:
            # These rows bind no requester/target equality: an independent
            # owner may be asked to act about a different principal.
            subject = operation.intent()["subject"]
            assert subject.get("member_id", subject.get("principal")) != a.w.root_id
        stored = await a.w.db.fetch_one(
            "SELECT signed_result,result FROM {{tables.protected_signer_operations}} WHERE operation_id=$1",
            operation.operation_id,
        )
        assert stored["signed_result"] is None and stored["result"] is None


@pytest.mark.asyncio
@pytest.mark.parametrize("row", ("admit", "endorse", "remove"))
async def test_subject_root_must_be_the_authenticated_requester_at_prepare(
    admissions, tmp_path, test_db_factory, row
):
    a = admissions
    async with operation_case(a, row, tmp_path, test_db_factory) as operation:
        other = SigningKey.generate()
        other_id = (await a.w.registry.register_did(did(other), bytes(other))).did_aw
        subject = operation.intent()["subject"]
        subject["root_id_or_self" if row == "remove" else "root_id"] = other_id
        if "root_key" in subject:
            subject["root_key"] = did(other)
        changed = replace(operation, operation_id=str(uuid4()), subject=subject)
        rejected = await prepare(a, changed)
        assert (rejected.status_code, rejected.json()) == (403, {"detail": "scope_refused"})
        assert await a.w.app.signer.lookup_context(changed.operation_id) is None
        accepted = await prepare(a, operation)
        assert accepted.status_code == 200, accepted.text


@pytest.mark.asyncio
async def test_self_certificate_proof_cannot_be_replaced_or_mixed_with_root_proof(admissions):
    a = admissions
    await endorse(a)
    key, certificate = await admitted(a)
    operation = removal(a, certificate, self_remove=True)
    # A perfectly valid registered root proof is the wrong proof for self.
    wrong = await prepare(a, operation)
    assert (wrong.status_code, wrong.json()) == (401, {"detail": "requester_invalid"})
    mixed = await self_call(a, key, certificate, operation, extra_headers={"X-AWEB-DID-AW": a.w.root_id})
    assert (mixed.status_code, mixed.json()) == (401, {"detail": "requester_invalid"})
    accepted = await self_call(a, key, certificate, operation)
    assert accepted.status_code == 200, accepted.text
