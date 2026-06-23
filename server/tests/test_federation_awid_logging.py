from __future__ import annotations

import logging
from datetime import datetime, timezone
from uuid import uuid4

import httpx
import pytest
from fastapi import HTTPException

from aweb.federation.envelope import FederationEnvelope
from aweb.routes.federation import _resolve_target_identity, _verify_sender_current_key


class SenderKeyRegistryUnavailable:
    async def resolve_key(self, _did_aw: str):
        raise httpx.ConnectError("registry down")


class SenderKeyRegistryBug:
    async def resolve_key(self, _did_aw: str):
        raise RuntimeError("key resolver invariant broke")


class TargetIdentityRegistryUnavailable:
    async def resolve_address(self, _domain: str, _name: str):
        raise httpx.ConnectError("registry down")


class TargetIdentityRegistryBug:
    async def resolve_address(self, _domain: str, _name: str):
        raise RuntimeError("resolver invariant broke")


def _envelope() -> FederationEnvelope:
    return FederationEnvelope(
        type="mail",
        sender_did_aw="did:aw:sender",
        sender_current_did_key="did:key:sender-current",
        sender_address="sender.example/alice",
        sender_delivery_origin="https://sender.example",
        target_address="target.example/bob",
        target_did_aw="did:aw:target",
        target_current_did_key="did:key:target-current",
        target_delivery_origin="https://local.example",
        body="hello",
        message_id=str(uuid4()),
        conversation_id=str(uuid4()),
        timestamp=datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    )


@pytest.mark.asyncio
async def test_federation_sender_key_awid_dependency_logs_exc_info(caplog):
    caplog.set_level(logging.WARNING, logger="aweb.routes.federation")

    with pytest.raises(HTTPException) as raised:
        await _verify_sender_current_key(SenderKeyRegistryUnavailable(), _envelope())

    assert raised.value.status_code == 503
    assert "AWID federation sender key verification" in raised.value.detail
    records = [record for record in caplog.records if "federation sender key verification" in record.getMessage()]
    assert records
    assert records[0].levelno == logging.WARNING
    assert records[0].exc_info is not None


@pytest.mark.asyncio
async def test_federation_sender_key_unexpected_awid_error_logs_exception(caplog):
    caplog.set_level(logging.ERROR, logger="aweb.routes.federation")

    with pytest.raises(HTTPException) as raised:
        await _verify_sender_current_key(SenderKeyRegistryBug(), _envelope())

    assert raised.value.status_code == 500
    assert "Unexpected AWID federation sender key verification dependency error" in raised.value.detail
    records = [record for record in caplog.records if "federation sender key verification" in record.getMessage()]
    assert records
    assert records[0].levelno == logging.ERROR
    assert records[0].exc_info is not None


@pytest.mark.asyncio
async def test_federation_target_identity_awid_dependency_logs_exc_info(caplog):
    caplog.set_level(logging.WARNING, logger="aweb.routes.federation")

    with pytest.raises(HTTPException) as raised:
        await _resolve_target_identity(TargetIdentityRegistryUnavailable(), _envelope())

    assert raised.value.status_code == 503
    assert "AWID federation target identity resolution" in raised.value.detail
    records = [record for record in caplog.records if "federation target identity resolution" in record.getMessage()]
    assert records
    assert records[0].levelno == logging.WARNING
    assert records[0].exc_info is not None


@pytest.mark.asyncio
async def test_federation_target_identity_unexpected_awid_error_logs_exception(caplog):
    caplog.set_level(logging.ERROR, logger="aweb.routes.federation")

    with pytest.raises(HTTPException) as raised:
        await _resolve_target_identity(TargetIdentityRegistryBug(), _envelope())

    assert raised.value.status_code == 500
    assert "Unexpected AWID federation target identity resolution dependency error" in raised.value.detail
    records = [record for record in caplog.records if "federation target identity resolution" in record.getMessage()]
    assert records
    assert records[0].levelno == logging.ERROR
    assert records[0].exc_info is not None
