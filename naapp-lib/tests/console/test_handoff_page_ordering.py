"""The exact page script under a DOM/fetch double, for orderings a browser
test cannot hold still: a decision submitted, its answer delayed, and the
request's local expiry firing in between. Kept from the boundary review of
acxy.16 (security-fixes, d2b5738fa): the page must never say nothing was
signed when a submitted decision may already have committed."""

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]


@pytest.mark.skipif(shutil.which("node") is None, reason="node is required for the page-script probe")
def test_a_local_expiry_never_overrides_a_submitted_decision():
    probe = Path(__file__).with_name("handoff_expiry_probe.cjs")
    result = subprocess.run(["node", str(probe)], cwd=ROOT, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.skipif(shutil.which("node") is None, reason="node is required for the page-script probe")
def test_a_retained_outcome_is_read_only_and_requires_the_supported_applied_mode():
    probe = Path(__file__).with_name("handoff_retained_probe.cjs")
    import base64
    import json
    from datetime import timedelta

    from awid.protected_effect import artifact_digest

    from aweb_naapp.runtime.approvals import request_sha256
    from aweb_naapp.runtime.protected_signer.catalog import presentation_catalog
    from aweb_naapp.runtime.protected_signer.execution_intent import prepare_artifact_intent
    from tests.runtime.test_protected_identity_artifacts import NOW
    from tests.runtime.test_protected_member_removal import CONTROLLER
    from tests.runtime.test_protected_owner_removal import owner_operation

    op = owner_operation()
    request = {**op.intent(), "artifact": prepare_artifact_intent(op, CONTROLLER, NOW, NOW + timedelta(hours=24)),
        "requester": CONTROLLER, "requester_key": CONTROLLER, "target_kind": "kind not verified",
        "policy_ref": "aweb.human-assurance/1", "policy_version": 1}
    payload = {"policy": {"ref": request["policy_ref"], "version": 1}, "request": request}
    signing, signature = b"retained exact bytes", bytes(range(64))
    fixture = {"table": presentation_catalog(), "state": {"mode": "governance", "handoff_id": "same-handoff",
        "operation_id": op.operation_id, "state": "committed", "payload": payload, "digest": request_sha256(payload),
        "expires_at": (NOW + timedelta(hours=24)).isoformat().replace("+00:00", "Z")},
        "artifact": {"signing": base64.b64encode(signing).decode(), "signature": base64.b64encode(signature).decode()},
        "artifact_sha256": artifact_digest(signing, base64.b64encode(signature).decode().rstrip("="))}
    result = subprocess.run(["node", str(probe)], cwd=ROOT, input=json.dumps(fixture), capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
