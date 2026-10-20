"""The AWS KMS provider fails closed when KMS cannot be reached.

These tests talk to a real local port that refuses connections; there is no
KMS stand-in. Round trips against a real KMS key need the E2E key (HO6)."""

from __future__ import annotations

import socket

import boto3
import pytest
from botocore import UNSIGNED
from botocore.config import Config

from aweb_secrets.custody import AwsKmsProvider, CustodyUnavailable, SealContext, seal, seal_canary

CONTEXT = SealContext(
    installation_id="installation-1", team_id="team-1", secret_id="secret-1", version=1
)


@pytest.fixture
def unreachable_kms() -> AwsKmsProvider:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    client = boto3.client(
        "kms",
        region_name="eu-west-1",
        endpoint_url=f"http://127.0.0.1:{port}",
        config=Config(
            signature_version=UNSIGNED,
            retries={"max_attempts": 1},
            connect_timeout=1,
            read_timeout=1,
        ),
    )
    return AwsKmsProvider(key_id="alias/secrets-test", client=client)


def test_sealing_refuses_when_kms_is_unreachable(
    unreachable_kms: AwsKmsProvider, canary: bytes
) -> None:
    with pytest.raises(CustodyUnavailable) as refused:
        seal(unreachable_kms, CONTEXT, canary)
    assert canary.decode() not in str(refused.value)


def test_the_canary_fails_when_kms_is_unreachable(unreachable_kms: AwsKmsProvider) -> None:
    with pytest.raises(CustodyUnavailable):
        seal_canary(unreachable_kms)
