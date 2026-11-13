"""OATS artifacts retain the existing ID and membership consumer encodings."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from awid.did import did_from_public_key, generate_keypair, stable_id_from_public_key
from awid.id_certificates import id_certificate_signing_bytes
from awid.signing import canonical_json_bytes

from aweb_naapp.runtime.protected_signer import CatalogOperation, ProtectedKeyContext, SignerRefused
from aweb_naapp.runtime.protected_signer.codecs import artifact_for, authority_key, signing_bytes


def identity():
    _, public = generate_keypair()
    return stable_id_from_public_key(public), did_from_public_key(public)


H, HKEY = identity()
ROOT, ROOTKEY = identity()
CHILD, CHILDKEY = identity()
DOMAIN, TEAM, SERVICE = "customer.example", "engineering:customer.example", "customer-signer"
NOW = datetime(2026, 11, 13, 12, 0, tzinfo=UTC)


def operation(name, *, subject=None):
    if name == "identity.root.endorse":
        context = ProtectedKeyContext(SERVICE, "human_identity", H, DOMAIN, H, DOMAIN, 1)
        fields = {"domain": DOMAIN, "root_id": ROOT, "root_key": ROOTKEY, "teams": [TEAM], "deployment_label": "deployment"}
    else:
        context = ProtectedKeyContext(SERVICE, "team_controller", TEAM, DOMAIN, H, DOMAIN, 1)
        fields = {"team_id": TEAM, "root_id": ROOT, "root_key": ROOTKEY, "child_id": CHILD,
            "child_key": CHILDKEY, "member_alias": "agent-one", "admission_policy_digest": "sha256:"+"a"*64,
            "expected_policy_version": 1}
    return CatalogOperation(str(uuid4()), context, "https://registry.customer.example", name, "default", fields if subject is None else subject)


def test_root_endorsement_uses_the_existing_id_certificate_without_an_extra_root_key_field():
    op = operation("identity.root.endorse")
    artifact = artifact_for(op, HKEY, NOW)
    assert artifact == {"v": 1, "type": "aweb.id-certificate", "id": ROOT, "domain": DOMAIN,
        "parent": {"kind": "identity", "id": H}, "kind": "agent", "issuer_key": HKEY,
        "issued_at": "2026-11-13T12:00:00Z"}
    assert signing_bytes(op, artifact) == id_certificate_signing_bytes(artifact)
    assert authority_key(op, artifact) == HKEY


@pytest.mark.parametrize("local", [True, False])
def test_root_admission_uses_existing_unsigned_team_certificate_fields_without_a_prefix(local):
    op = operation("team.agent.admit")
    if local:
        op = operation("team.agent.admit", subject={**op.intent()["subject"], "child_id": None})
    artifact = artifact_for(op, HKEY, NOW)
    assert set(artifact) == {"version", "certificate_id", "team_id", "team_did_key", "member_did_key", "alias", "identity_scope", "issued_at"} | (set() if local else {"member_did_aw"})
    assert artifact["identity_scope"] == ("local" if local else "global")
    assert artifact["member_did_key"] == CHILDKEY and artifact["alias"] == "agent-one"
    assert artifact.get("member_did_aw") == (None if local else CHILD)
    assert signing_bytes(op, artifact) == canonical_json_bytes(artifact)
    assert authority_key(op, artifact) == HKEY


@pytest.mark.parametrize("name,changed", [
    ("identity.root.endorse", {"root_id": ROOTKEY}),
    ("identity.root.endorse", {"teams": []}),
    ("identity.root.endorse", {"teams": [TEAM, TEAM]}),
    ("identity.root.endorse", {"parent": {"kind": "namespace", "id": DOMAIN}}),
    ("identity.root.endorse", {"domain": "Customer.example"}),
    ("team.agent.admit", {"child_id": CHILDKEY}),
    ("team.agent.admit", {"child_key": CHILD}),
    ("team.agent.admit", {"root_id": ROOTKEY}),
    ("team.agent.admit", {"expected_policy_version": True}),
    ("team.agent.admit", {"admission_policy_digest": "sha256:"+"A"*64}),
    ("team.agent.admit", {"admin": True}),
    ("team.agent.admit", {"member_alias": "bad\nname"}),
])
def test_artifact_inputs_are_closed_typed_subjects(name, changed):
    subject = operation(name).intent()["subject"]
    with pytest.raises(SignerRefused, match="request_invalid"):
        operation(name, subject={**subject, **changed})


@pytest.mark.parametrize("name", ["identity.root.endorse", "team.agent.admit"])
@pytest.mark.parametrize("changed", ["subject", "key", "extra", "timestamp"])
def test_a_retained_artifact_cannot_change_its_frozen_fields(name, changed):
    op = operation(name)
    artifact = artifact_for(op, HKEY, NOW)
    if changed == "subject":
        artifact["id" if name.startswith("identity") else "member_did_key"] = H
    elif changed == "key":
        artifact["issuer_key" if name.startswith("identity") else "team_did_key"] = "bad-key"
    elif changed == "extra":
        artifact["roles"] = ["admin"]
    else:
        artifact["issued_at"] = "not-a-timestamp"
    with pytest.raises(SignerRefused, match="operation_mismatch"):
        signing_bytes(op, artifact)


def test_browser_accepts_the_frozen_endorsement_and_refuses_artifact_or_policy_substitutions():
    import json
    import subprocess
    from pathlib import Path

    from aweb_naapp.runtime.protected_signer.admission_policy import AdmissionPolicy
    from aweb_naapp.runtime.protected_signer.catalog import presentation_catalog

    op = operation("identity.root.endorse")
    policy = AdmissionPolicy.from_unsigned({"version": 1, "teams": [TEAM],
        "root_selector": {"kind": "service_endorsed_root", "service_id": SERVICE},
        "subject_kinds": ["local_agent"], "member_role": "member",
        "bounds": {"max_active": 10, "rate_window_seconds": 60, "max_per_window": 2}}, service_id=SERVICE)
    request = {**op.intent(), "artifact": artifact_for(op, HKEY, NOW), "registry": op.audience,
        "expected_head": None, "admission_policy": policy.fields(),
        "responsibility_statement": "Everything this root spawns counts as yours for human responsibility; this grants no resource permissions."}
    script = r'''
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {validateProtectedPresentation} from './src/aweb_naapp/assets/protected-presentation.mjs';
import {coveredRequestDigest} from './src/aweb_naapp/assets/canonical-json.mjs';
const {request,table} = JSON.parse(readFileSync(0,'utf8'));
const state = {mode:'governance',handoff_id:'handoff',state:'pending',operation_id:request.operation_id,
 expires_at:'2026-11-13T12:10:00Z',payload:{policy:{ref:'aweb.human-assurance/1',version:1},request}};
state.digest = await coveredRequestDigest(state.payload);
assert.deepEqual((await validateProtectedPresentation(state,'handoff',table)).artifact,request.artifact);
for (const mutation of [
 r=>r.artifact.parent.id=r.subject.root_id,
 r=>r.artifact.domain='other.example',
 r=>r.artifact.root_key=r.subject.root_key,
 r=>r.registry='https://other.example',
 r=>r.admission_policy.bounds.max_active++,
 r=>r.admission_policy.member_role='admin',
 r=>r.responsibility_statement='You delegate all resource rights',
 r=>r.subject.teams.push('other:customer.example'),
]) {
 const changed=structuredClone(state); mutation(changed.payload.request);
 changed.digest=await coveredRequestDigest(changed.payload);
 await assert.rejects(validateProtectedPresentation(changed,'handoff',table));
}
const changed=structuredClone(state);
changed.payload.request.subject.deployment_label='another deployment';
await assert.rejects(validateProtectedPresentation(changed,'handoff',table));
'''
    result = subprocess.run(["node", "--input-type=module", "-e", script],
        input=json.dumps({"request": request, "table": presentation_catalog()}), text=True,
        capture_output=True, cwd=Path(__file__).resolve().parents[2], timeout=20)
    assert result.returncode == 0, result.stdout + result.stderr
