"""In-process evidence binding, not a substitute for real B2/B3 admission tests."""

from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta

import pytest

from aweb_naapp.runtime.protected_signer import (
    AdmittedHuman,
    SignerRefused,
    VerifiedProtectedEffect,
)
from aweb_naapp.runtime.protected_signer.types import _verified_effect
from tests.runtime.test_protected_identity_artifacts import operation as identity_operation


def operation():
    return identity_operation("identity.root.endorse")


def admitted():
    op = operation()
    human = AdmittedHuman(op.context.human_id, "b3-subject", "b3-scope", op.context)
    deadline = datetime.now(UTC) + timedelta(minutes=1)
    return op, human, deadline


def test_bare_fields_cannot_construct_effect_admission():
    op, human, deadline = admitted()
    fields = dict(
        operation_id=op.operation_id,
        operation=op.operation,
        variant=op.variant,
        audience=op.audience,
        context=op.context,
        human=human,
        transaction_id=7,
        evidence_ref="retained-proof",
        expires_at=deadline,
        subject_bytes=b"{}",
        intent_bytes=b"{}",
    )
    for extra in ({}, {"_admission": object()}):
        with pytest.raises(SignerRefused, match="proof_invalid"):
            VerifiedProtectedEffect(**fields, **extra)


def test_trusted_executor_mint_snapshots_its_subject_and_original_deadline():
    op, human, deadline = admitted()
    evidence = _verified_effect(op, human, 7, "retained-proof", deadline)
    subject = evidence.subject
    subject["deployment_label"] = "another deployment"
    assert evidence.subject == op.intent()["subject"]
    assert evidence.expires_at is deadline
    with pytest.raises(FrozenInstanceError):
        evidence.transaction_id = 8
    with pytest.raises(SignerRefused, match="scope_refused"):
        _verified_effect(op, replace(human, principal="another-human"), 7, "proof", deadline)


@pytest.mark.asyncio
async def test_effect_consumer_requires_the_original_transaction_request_and_deadline():
    op, human, deadline = admitted()
    evidence = _verified_effect(op, human, 7, "retained-proof", deadline)
    calls = []

    class Transaction:
        async def fetch_value(self, query):
            calls.append(query)
            return 7

    tx = Transaction()
    await evidence.require_in(tx, op, clock=lambda: deadline - timedelta(seconds=1))
    assert calls == ["SELECT txid_current()"]
    with pytest.raises(SignerRefused, match="operation_mismatch"):
        await evidence.require_in(
            tx,
            replace(op, operation_id="00000000-0000-4000-8000-000000000099"),
            clock=lambda: deadline - timedelta(seconds=1),
        )

    with pytest.raises(SignerRefused, match="operation_mismatch"):
        await evidence.require_in(
            tx,
            replace(op, audience="https://other.example.org"),
            clock=lambda: deadline - timedelta(seconds=1),
        )
    from types import SimpleNamespace

    other_variant = SimpleNamespace(
        operation_id=op.operation_id,
        context=op.context,
        intent=lambda: {**op.intent(), "variant": "another"},
    )
    with pytest.raises(SignerRefused, match="operation_mismatch"):
        await evidence.require_in(tx, other_variant, clock=lambda: deadline - timedelta(seconds=1))

    class OtherTransaction(Transaction):
        async def fetch_value(self, query):
            return 8

    with pytest.raises(SignerRefused, match="proof_invalid"):
        await evidence.require_in(
            OtherTransaction(), op, clock=lambda: deadline - timedelta(seconds=1)
        )
    with pytest.raises(SignerRefused, match="gesture_expired"):
        await evidence.require_in(tx, op, clock=lambda: deadline)


@pytest.mark.asyncio
async def test_effect_admission_rechecks_the_original_deadline_after_the_transaction_await():
    op, human, deadline = admitted()
    evidence = _verified_effect(op, human, 7, "retained-proof", deadline)
    clock = [deadline - timedelta(seconds=1)]

    class DelayedTransaction:
        async def fetch_value(self, query):
            clock[0] = deadline
            return 7

    with pytest.raises(SignerRefused, match="gesture_expired"):
        await evidence.require_in(DelayedTransaction(), op, clock=lambda: clock[0])
