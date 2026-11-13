"""Definition-owned request bytes; no registry or custody authority is simulated."""

import base64
import hashlib
import json
from dataclasses import replace
from uuid import uuid4

import pytest
from awid.did import did_from_public_key, generate_keypair
from awid.signing import canonical_json_bytes, sign_message

from aweb_naapp.runtime.protected_signer import CatalogOperation, RevokeHumanRole
from aweb_naapp.runtime.protected_signer.codecs import artifact_for, signing_bytes
from aweb_naapp.runtime.protected_signer.types import owner_act_operation
from tests.runtime.test_protected_identity_artifacts import HKEY, NOW, operation
from tests.runtime.test_protected_member_removal import subject as removal_subject

STAMP = "2026-11-13T12:00:00Z"


def signed(op):
    key, public = generate_keypair()
    controller = did_from_public_key(public)
    artifact = artifact_for(op, controller, NOW)
    signing = signing_bytes(op, artifact)
    signature = base64.b64decode(sign_message(key, signing) + "==")
    return key, controller, artifact, signing, signature


@pytest.mark.parametrize("local", [True, False])
def test_registration_plan_binds_full_existing_certificate_and_covering_auth(local):
    op = operation("team.agent.admit")
    if local:
        op = operation("team.agent.admit", subject={**op.subject, "child_id": None})
    key, controller, artifact, signing, signature = signed(op)
    plan = op.spec.effect.delivery_plan(op, artifact, signing, signature, STAMP)
    body = json.loads(plan.body)
    assert body == {"certificate_id": artifact["certificate_id"], "member_did_key": artifact["member_did_key"],
        "member_did_aw": artifact.get("member_did_aw"), "member_address": None, "alias": artifact["alias"],
        "identity_scope": artifact["identity_scope"], "certificate": body["certificate"]}
    assert json.loads(base64.b64decode(body["certificate"])) == {**artifact,
        "signature": base64.b64encode(signature).rstrip(b"=").decode()}
    fields = json.loads(plan.controller_envelope)
    assert fields == {"v": 2, "type": "aweb.awid-controller-request", "aud": op.audience,
        "method": "POST", "path": "/v1/namespaces/customer.example/teams/engineering/certificates",
        "domain": "customer.example", "operation": "register_certificate", "team_name": "engineering",
        "certificate_id": artifact["certificate_id"], "timestamp": STAMP,
        "body_sha256": hashlib.sha256(plan.body).hexdigest()}
    assert plan.artifact_type == "aweb.team-certificate"
    auth = base64.b64decode(sign_message(key, plan.controller_envelope) + "==")
    delivery = plan.authenticate(auth)
    assert delivery.body == plan.body and delivery.audience == op.audience and delivery.path == fields["path"]
    assert delivery.headers["X-AWEB-Timestamp"] == STAMP
    assert base64.urlsafe_b64decode(delivery.headers["X-AWEB-Signed-Payload"] + "==") == plan.controller_envelope
    assert delivery.headers["Authorization"] == "DIDKey " + controller + " " + base64.b64encode(auth).rstrip(b"=").decode()
    with pytest.raises(ValueError):
        plan.authenticate(signature)  # a certificate signature is not request authentication
    with pytest.raises(ValueError):
        replace(plan, body=plan.body + b" ").authenticate(auth)


def test_removal_reuses_exact_artifact_request_and_does_not_mint_new_auth():
    admit = operation("team.agent.admit")
    op = CatalogOperation(str(uuid4()), admit.context, admit.audience, "team.agent.remove", "default", removal_subject())
    _, _, artifact, signing, signature = signed(op)
    plan = op.spec.effect.delivery_plan(op, artifact, signing, signature, "2026-11-13T12:01:00Z")
    assert plan.controller_envelope == signing
    assert plan.artifact_type == "aweb.awid-controller-request"
    assert json.loads(plan.body) == {"certificate_id": op.subject["certificate_id"]}
    assert plan.authenticate(signature).headers["X-AWEB-Timestamp"] == STAMP


def test_owner_act_plan_preserves_consumer_bytes_without_a_second_controller_signature():
    context = operation("team.agent.admit").context
    op = owner_act_operation(RevokeHumanRole(str(uuid4()), context, "https://app.customer.example", "app", str(uuid4()), "app.owner", context.human_id))
    _, _, artifact, signing, signature = signed(op)
    plan = op.spec.effect.delivery_plan(op, artifact, signing, signature, STAMP)
    assert plan.artifact_type == "aweb.owner-act" and plan.controller_envelope is None
    assert plan.path == "/.well-known/aweb-owner-act"
    assert plan.body == canonical_json_bytes({"signing": base64.b64encode(signing).decode(),
        "signature": base64.b64encode(signature).rstrip(b"=").decode()})
    assert dict(plan.authenticate().headers) == {"Content-Type": "application/json"}
    with pytest.raises(ValueError):
        plan.authenticate(signature)


def test_human_endorsement_has_no_team_controller_delivery_plan():
    op = operation("identity.root.endorse")
    artifact = artifact_for(op, HKEY, NOW)
    assert op.spec.effect.delivery_plan is None
    assert artifact["type"] == "aweb.id-certificate"


def test_definition_builder_rejects_a_changed_signed_artifact():
    op = operation("team.agent.admit")
    _, _, artifact, signing, signature = signed(op)
    with pytest.raises(ValueError):
        op.spec.effect.delivery_plan(op, artifact, signing + b" ", signature, STAMP)
