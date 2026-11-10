"""Original renderer inputs use real native envelopes and their exact scope."""

import secrets
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from aweb_naapp.runtime.installation import AdmittedInstallation

from aweb_secrets.custody import CustodyUnavailable, LocalKeyFileProvider
from aweb_secrets.custody.run_redaction import RunRedaction, SealedRunRedaction
from aweb_secrets.redaction import KnownValues


@pytest.fixture
def redaction(tmp_path):
    key_file = tmp_path / "key"
    key_file.write_text(secrets.token_bytes(32).hex())
    key_file.chmod(0o600)
    return RunRedaction(LocalKeyFileProvider(key_file))


async def original(redaction):
    known = KnownValues()
    value = secrets.token_urlsafe(32)
    known.add("original", value)
    scope = AdmittedInstallation(
        team_id="team", app_id="secrets", installation_id="installation", generation=1
    )
    dispatch_id = uuid4()
    sealed = await redaction.seal(scope, dispatch_id, known)
    if value.encode() in sealed.ciphertext:
        raise AssertionError("original value is not sealed")
    return value, SealedRunRedaction(
        scope, dispatch_id, datetime.now(UTC) + timedelta(minutes=1), sealed
    )


async def test_native_snapshot_recovers_original_renderer(redaction):
    value, snapshot = await original(redaction)
    known = await redaction.open(snapshot)
    if known.redact(value.encode()) != (b"[REDACTED:original]", 1):
        raise AssertionError("original redaction was not restored")


@pytest.mark.parametrize("field", ["team_id", "installation_id", "dispatch_id"])
async def test_native_snapshot_cannot_be_relabelled(redaction, field):
    _, snapshot = await original(redaction)
    if field == "dispatch_id":
        copied = replace(snapshot, dispatch_id=uuid4())
    else:
        copied = replace(snapshot, scope=replace(snapshot.scope, **{field: "another"}))
    with pytest.raises(CustodyUnavailable):
        await redaction.open(copied)
