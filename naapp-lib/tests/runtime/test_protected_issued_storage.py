"""Pure storage/port controls; database commit behavior has separate native cases."""

from copy import deepcopy
from datetime import timedelta

import pytest
from awid.did import did_from_public_key
from nacl.signing import SigningKey

from aweb_naapp.runtime.protected_signer import ProtectedSigner, SignerRefused
from aweb_naapp.runtime.protected_signer.codecs import artifact_for
from aweb_naapp.runtime.protected_signer.execution_intent import (
    materialize_artifact,
    prepare_artifact_intent,
)
from tests.runtime.test_protected_execution_intent import live_operation
from tests.runtime.test_protected_identity_artifacts import NOW


@pytest.mark.parametrize("name", ["root", "owner_act", "removal"])
def test_issued_storage_is_historical_and_never_rebuilds_or_rewrites_the_request(name, monkeypatch):
    op = live_operation(name)
    key = SigningKey.generate()
    descriptor = prepare_artifact_intent(op, did_from_public_key(bytes(key.verify_key)), NOW, NOW + timedelta(hours=24))
    actual = materialize_artifact(op, descriptor, NOW + timedelta(hours=2))
    row = {"request": {**op.intent(), "artifact": descriptor}, "issued_artifact": actual}
    saved = deepcopy(row)
    engine = object.__new__(ProtectedSigner)
    engine.clock = lambda: NOW + timedelta(days=3)

    def no_issue(*args):
        pytest.fail("a historical load must not issue a new artifact")

    monkeypatch.setattr("aweb_naapp.runtime.protected_signer.service.materialize_artifact", no_issue)
    assert engine._issued_artifact(row) == actual
    assert row == saved
    row["issued_artifact"] = None
    with pytest.raises(SignerRefused, match="evidence_unavailable"):
        engine._issued_artifact(row)


def test_old_format_is_readable_as_history_but_cannot_be_executed():
    op = live_operation("owner_act")
    key = did_from_public_key(bytes(SigningKey.generate().verify_key))
    old = op.intent()
    del old["approval_format"]
    old["artifact"] = artifact_for(op, key, NOW)
    engine = object.__new__(ProtectedSigner)
    assert engine._issued_artifact({"request": old}) == old["artifact"]
    with pytest.raises(SignerRefused, match="upgrade_aw_required"):
        engine._require_current_format(old)
