from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from typer.main import get_command

from awid.did import did_from_public_key, generate_keypair
from awid.dns_verify import DomainAuthority
from awid.signing import canonical_json_bytes, sign_message
import awid_service.controller_rollover_operator as rollover_operator_module
from awid_service.cli import app
from awid_service.controller_rollover_operator import (
    MAX_ROLLOVER_RISK_SAFETY_WINDOW_SECONDS,
    ControllerRolloverOperator,
    RolloverRiskAcceptanceError,
)
from awid_service.db import AwidDatabaseInfra


def test_risk_safety_window_bounds_service_and_cli():
    assert ControllerRolloverOperator.validate_safety_window_seconds(
        MAX_ROLLOVER_RISK_SAFETY_WINDOW_SECONDS
    ) == MAX_ROLLOVER_RISK_SAFETY_WINDOW_SECONDS
    for invalid in (
        True,
        1.5,
        "600",
        MAX_ROLLOVER_RISK_SAFETY_WINDOW_SECONDS + 1,
        10**100,
    ):
        with pytest.raises(RolloverRiskAcceptanceError, match="must be an integer"):
            ControllerRolloverOperator.validate_safety_window_seconds(invalid)

    root = get_command(app)
    risk_command = root.commands["controller-rollover"].commands[
        "accept-overlap-risk"
    ]
    safety_window = next(
        param
        for param in risk_command.params
        if param.name == "assumed_previous_ttl_seconds"
    )
    assert safety_window.type.min == 1
    assert safety_window.type.max == MAX_ROLLOVER_RISK_SAFETY_WINDOW_SECONDS


@pytest.mark.asyncio
async def test_risk_admission_clock_is_captured_after_rollover_lock(
    shared_test_pool, monkeypatch,
):
    infra = AwidDatabaseInfra(schema="awid_rollover_risk_clock")
    await infra.initialize(shared_pool=shared_test_pool, run_migrations=True)
    try:
        db = infra.get_manager("aweb")
        key, public = generate_keypair()
        did = did_from_public_key(public)
        rollover_id = str(uuid4())
        await db.execute(
            """
            INSERT INTO {{tables.namespace_controller_rollovers}}
                (rollover_id,parent_domain,old_controller_did,new_controller_did,
                 state,recovery_mode,cutover_at,first_new_dns_observed_at)
            VALUES ($1::uuid,'clock.example','did:key:z6Mkold',$2,
                    'recovery_overlap_unbounded','exact_dns',
                    '2026-08-26T18:00:00Z','2026-08-26T18:00:00Z')
            """,
            rollover_id, did,
        )

        async def verify_domain(_domain):
            return DomainAuthority(
                controller_did=did, registry_url="https://new.example",
                dns_name="_awid.clock.example", inherited=False,
            )

        operator = ControllerRolloverOperator(
            db, verify_domain=verify_domain, public_origin="https://new.example"
        )
        reason = b"Controlled lock timing risk acceptance."
        signature_time = "2026-08-26T18:01:00Z"
        payload = operator.acceptance_payload(
            domain="clock.example", rollover_id=rollover_id,
            dns_changed_at="2026-08-26T18:00:00Z",
            assumed_previous_ttl_seconds=600, reason_bytes=reason,
            signature_timestamp=signature_time,
        )
        signature = sign_message(key, canonical_json_bytes(payload))

        class ControlledDateTime(datetime):
            calls = 0

            @classmethod
            def now(cls, tz=None):
                cls.calls += 1
                return cls(2026, 8, 26, 18, 1, 0, tzinfo=timezone.utc)

        monkeypatch.setattr(rollover_operator_module, "datetime", ControlledDateTime)
        async with db.transaction() as locking_tx:
            await locking_tx.fetch_one(
                "SELECT rollover_id FROM {{tables.namespace_controller_rollovers}} WHERE rollover_id=$1::uuid FOR UPDATE",
                rollover_id,
            )
            task = asyncio.create_task(operator.accept_overlap_risk(
                rollover_id=rollover_id,
                dns_changed_at="2026-08-26T18:00:00Z",
                assumed_previous_ttl_seconds=600,
                reason_bytes=reason,
                operator_id="operations@example",
                new_controller_signature=signature,
                signature_timestamp=signature_time,
                explicit_acceptance=True,
            ))
            await asyncio.sleep(0.05)
            assert ControlledDateTime.calls == 0
        accepted = await task
        assert accepted["risk_accepted"] is True
        assert ControlledDateTime.calls >= 2
        assert await db.fetch_value(
            "SELECT live_dns_observed_at FROM {{tables.namespace_controller_rollover_risk_acceptances}} WHERE rollover_id=$1::uuid",
            rollover_id,
        ) == datetime(2026, 8, 26, 18, 1, tzinfo=timezone.utc)
    finally:
        await infra.close()


@pytest.mark.asyncio
async def test_exact_dns_recovery_risk_acceptance_is_explicit_audited_and_idempotent(
    shared_test_pool,
):
    infra = AwidDatabaseInfra(schema="awid_rollover_risk")
    await infra.initialize(shared_pool=shared_test_pool, run_migrations=True)
    try:
        db = infra.get_manager("aweb")
        new_key, new_public = generate_keypair()
        new_did = did_from_public_key(new_public)
        rollover_id = str(uuid4())
        first_observed = datetime(2026, 8, 26, 18, 0, tzinfo=timezone.utc)
        await db.execute(
            """
            INSERT INTO {{tables.dns_namespaces}}
                (namespace_id,domain,controller_did,verification_status)
            VALUES ($1,'risk.example',$2,'verified')
            """,
            uuid4(),
            new_did,
        )
        await db.execute(
            """
            INSERT INTO {{tables.namespace_controller_rollovers}}
                (rollover_id,parent_domain,old_controller_did,new_controller_did,
                 state,recovery_mode,cutover_at,first_new_dns_observed_at)
            VALUES ($1::uuid,'risk.example','did:key:z6Mkold',$2,
                    'recovery_overlap_unbounded','exact_dns',$3,$3)
            """,
            rollover_id,
            new_did,
            first_observed,
        )

        dns_controller = {"did": new_did}

        async def verify_domain(domain):
            assert domain == "risk.example"
            return DomainAuthority(
                controller_did=dns_controller["did"],
                registry_url="https://new.example",
                dns_name="_awid.risk.example",
                inherited=False,
                ttl_seconds=60,
            )

        operator = ControllerRolloverOperator(
            db, verify_domain=verify_domain, public_origin="https://new.example"
        )
        reason = b"Emergency recovery accepted by operations ticket OPS-42."
        signature_time = "2026-08-26T18:01:00Z"
        payload = operator.acceptance_payload(
            domain="risk.example",
            rollover_id=rollover_id,
            dns_changed_at="2026-08-26T18:00:00Z",
            assumed_previous_ttl_seconds=600,
            reason_bytes=reason,
            signature_timestamp=signature_time,
        )
        signature = sign_message(new_key, canonical_json_bytes(payload))
        now = datetime(2026, 8, 26, 18, 1, tzinfo=timezone.utc)

        with pytest.raises(RolloverRiskAcceptanceError, match="explicit"):
            await operator.accept_overlap_risk(
                rollover_id=rollover_id,
                dns_changed_at="2026-08-26T18:00:00Z",
                assumed_previous_ttl_seconds=600,
                reason_bytes=reason,
                operator_id="operations@example",
                new_controller_signature=signature,
                signature_timestamp=signature_time,
                explicit_acceptance=False,
                now=now,
            )
        for invalid_time in (
            "2026-08-26T18:00:00+00:00",
            "2026-08-26T19:00:00+01:00",
            "2026-08-26T18:00:00",
            "2026-08-26T18:00:00.1234567Z",
            "2026-08-26T18:00:00Z ",
        ):
            with pytest.raises(RolloverRiskAcceptanceError, match="canonical RFC3339"):
                await operator.accept_overlap_risk(
                    rollover_id=rollover_id,
                    dns_changed_at=invalid_time,
                    assumed_previous_ttl_seconds=600,
                    reason_bytes=reason,
                    operator_id="operations@example",
                    new_controller_signature=signature,
                    signature_timestamp=signature_time,
                    explicit_acceptance=True,
                    now=now,
                )
        with pytest.raises(RolloverRiskAcceptanceError, match="operator id"):
            await operator.accept_overlap_risk(
                rollover_id=rollover_id,
                dns_changed_at="2026-08-26T18:00:00Z",
                assumed_previous_ttl_seconds=600,
                reason_bytes=reason,
                operator_id="",
                new_controller_signature=signature,
                signature_timestamp=signature_time,
                explicit_acceptance=True,
                now=now,
            )
        with pytest.raises(RolloverRiskAcceptanceError, match="DNS change time"):
            await operator.accept_overlap_risk(
                rollover_id=rollover_id,
                dns_changed_at="2026-08-26T19:00:00Z",
                assumed_previous_ttl_seconds=600,
                reason_bytes=reason,
                operator_id="operations@example",
                new_controller_signature=signature,
                signature_timestamp=signature_time,
                explicit_acceptance=True,
                now=now,
            )
        with pytest.raises(RolloverRiskAcceptanceError, match="signature is invalid"):
            await operator.accept_overlap_risk(
                rollover_id=rollover_id,
                dns_changed_at="2026-08-26T18:00:00Z",
                assumed_previous_ttl_seconds=600,
                reason_bytes=reason,
                operator_id="operations@example",
                new_controller_signature=("A" if signature[0] != "A" else "B") + signature[1:],
                signature_timestamp=signature_time,
                explicit_acceptance=True,
                now=now,
            )
        dns_controller["did"] = "did:key:z6MkhFwXNFWosLeugvSf4wcL9t3uuRXueGSFTRgSvHhWj5G2"
        with pytest.raises(RolloverRiskAcceptanceError, match="live exact DNS"):
            await operator.accept_overlap_risk(
                rollover_id=rollover_id,
                dns_changed_at="2026-08-26T18:00:00Z",
                assumed_previous_ttl_seconds=600,
                reason_bytes=reason,
                operator_id="operations@example",
                new_controller_signature=signature,
                signature_timestamp=signature_time,
                explicit_acceptance=True,
                now=now,
            )
        dns_controller["did"] = new_did
        with pytest.raises(RolloverRiskAcceptanceError, match="timestamp is stale"):
            await operator.accept_overlap_risk(
                rollover_id=rollover_id,
                dns_changed_at="2026-08-26T18:00:00Z",
                assumed_previous_ttl_seconds=600,
                reason_bytes=reason,
                operator_id="operations@example",
                new_controller_signature=signature,
                signature_timestamp=signature_time,
                explicit_acceptance=True,
                now=datetime(2026, 8, 26, 18, 10, tzinfo=timezone.utc),
            )

        accepted = await operator.accept_overlap_risk(
            rollover_id=rollover_id,
            dns_changed_at="2026-08-26T18:00:00Z",
            assumed_previous_ttl_seconds=600,
            reason_bytes=reason,
            operator_id="operations@example",
            new_controller_signature=signature,
            signature_timestamp=signature_time,
            explicit_acceptance=True,
            now=now,
        )
        assert accepted["risk_accepted"] is True
        assert accepted["previous_ttl_independently_established"] is False
        assert accepted["dns_changed_at"] == "2026-08-26T18:00:00Z"
        assert accepted["live_dns_observed_at"] == "2026-08-26T18:01:00Z"
        assert accepted["complete_after"] == "2026-08-26T18:10:00Z"
        assert accepted["canonical_acceptance"] == canonical_json_bytes(payload).decode()
        assert accepted["new_controller_signature"] == signature
        assert accepted["signature_timestamp"] == signature_time
        assert accepted["created_at"].endswith("Z")
        assert set(accepted) == {
            "rollover_id", "canonical_acceptance", "acceptance_hash",
            "operator_id", "reason_hash", "dns_changed_at",
            "assumed_previous_ttl_seconds", "new_controller_signature",
            "signature_timestamp", "live_dns_name", "live_dns_answer_digest",
            "live_dns_observed_at", "complete_after", "created_at",
            "previous_ttl_independently_established", "risk_accepted", "warning",
        }
        retries = await asyncio.gather(
            *[
                operator.accept_overlap_risk(
                    rollover_id=rollover_id,
                    dns_changed_at="2026-08-26T18:00:00Z",
                    assumed_previous_ttl_seconds=600,
                    reason_bytes=reason,
                    operator_id="operations@example",
                    new_controller_signature=signature,
                    signature_timestamp=signature_time,
                    explicit_acceptance=True,
                    now=now,
                )
                for _ in range(2)
            ]
        )
        assert retries == [accepted, accepted]
        assert await operator.accept_overlap_risk(
            rollover_id=rollover_id,
            dns_changed_at="2026-08-26T18:00:00Z",
            assumed_previous_ttl_seconds=600,
            reason_bytes=reason,
            operator_id="operations@example",
            new_controller_signature=signature,
            signature_timestamp=signature_time,
            explicit_acceptance=True,
            now=datetime(2026, 8, 26, 18, 20, tzinfo=timezone.utc),
        ) == accepted

        with pytest.raises(RolloverRiskAcceptanceError, match="conflicts"):
            await operator.accept_overlap_risk(
                rollover_id=rollover_id,
                dns_changed_at="2026-08-26T18:00:00Z",
                assumed_previous_ttl_seconds=601,
                reason_bytes=reason,
                operator_id="operations@example",
                new_controller_signature=signature,
                signature_timestamp=signature_time,
                explicit_acceptance=True,
                now=now,
            )
        row = await db.fetch_one(
            "SELECT state,complete_after FROM {{tables.namespace_controller_rollovers}} WHERE rollover_id=$1::uuid",
            rollover_id,
        )
        assert row["state"] == "overlap_risk_accepted"
        assert row["complete_after"] == datetime(2026, 8, 26, 18, 10, tzinfo=timezone.utc)
        assert await db.fetch_value(
            "SELECT controller_did FROM {{tables.dns_namespaces}} WHERE domain='risk.example'"
        ) == new_did
        assert await db.fetch_value(
            "SELECT COUNT(*) FROM {{tables.namespace_delegation_signatures}}"
        ) == 0
        assert await db.fetch_value(
            "SELECT COUNT(*) FROM {{tables.namespace_controller_rollover_children}}"
        ) == 0
    finally:
        await infra.close()
