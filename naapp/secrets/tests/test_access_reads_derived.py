"""The owner read and actual child admission must resolve the same CURRENT."""

import pytest

from aweb_secrets.access_reads import confirmed_access
from aweb_secrets.admission import AdmissionRefused
from tests.test_admission import BOB, POLICY_BODY, _define, _install, _operation, _request
from tests.test_derived_admission import _admit, _child
from tests.test_derived_admission import db as _db
from tests.test_derived_admission import fence as _fence

db = _db
fence = _fence


@pytest.mark.parametrize("edited", [False, True])
async def test_child_access_read_matches_real_ancestor_operation_admission(db, fence, edited):
    # Same identity, child grant/policy, params and ancestor pin as the existing
    # test_child_resolves_current_ancestor_operation_and_refuses_edit case.
    operation = _operation()
    pin = {"operation_id": operation.operation_id, "digest": operation.digest}
    await _install(db)
    await _define(db, operation)
    child = await _child(
        db, policy={**POLICY_BODY, "rate": [], "operations": [pin]}, operations=[pin]
    )
    request = _request(
        secret_ref=child["ref"], operation_id=operation.operation_id, params={"charge": "ch_1"}
    )
    admitted = await _admit(db, fence, BOB, request)
    expected = operation
    if edited:
        expected = _operation(response={**operation.after["response"], "max_bytes": 1024})
        await _define(db, expected)
        with pytest.raises(AdmissionRefused) as refused:
            await _admit(
                db,
                fence,
                BOB,
                _request(
                    "req_2",
                    secret_ref=child["ref"],
                    operation_id=operation.operation_id,
                    params=request.params,
                ),
            )
        assert refused.value.code == "operation_not_allowed"
    async with db.transaction() as tx:
        await tx.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        snapshot = await confirmed_access(
            tx,
            admitted.installation,
            principal_did=BOB.did_aw,
            roles=[],
            secret_id=child["secret_id"],
        )
    [candidate] = snapshot.candidates
    [selected] = candidate.operations
    assert candidate.grant.grant_id == admitted.grant_id
    assert selected.granted_digest == operation.digest
    assert selected.current == expected
    assert candidate.grant.covers_operation(
        selected.current.operation_id, selected.current.digest
    ) is (not edited)
