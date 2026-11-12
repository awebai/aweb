"""The executable operation registry is exactly the frozen signer catalog."""

import json
from pathlib import Path

import pytest

from aweb_naapp.runtime.protected_signer import SignerRefused
from aweb_naapp.runtime.protected_signer.catalog import OPERATIONS, operation_spec

CATALOG = Path(__file__).resolve().parents[3] / "docs/vectors/human-assurance-v1.json"


def test_operation_registry_matches_all_frozen_signer_rows_only():
    source = json.loads(CATALOG.read_bytes())
    expected = {
        (row["operation"], row["variant"]): row
        for row in source["operations"]
        if row["enforced_by"] == "signer"
    }
    assert set(OPERATIONS) == set(expected)
    assert len(OPERATIONS) == 53
    for key, spec in OPERATIONS.items():
        row = expected[key]
        assert spec.key_role == row["key_role"]
        assert spec.rule == row["rule"]
        assert spec.payload_binding == tuple(row["payload_binding"])
        assert spec.bounds == tuple(row["bounds"])
        assert spec.needs_human == (row["rule"] == "live_floor")
    assert sum(spec.needs_human for spec in OPERATIONS.values()) == 45


@pytest.mark.parametrize(
    "operation,variant",
    [
        ("sign_bytes", "default"),
        ("human-role.revoke", "surprise"),
        ("identity.agent.rotate", "default"),
        ("controller.export", "default"),
    ],
)
def test_unknown_or_non_signer_operation_has_no_signing_route(operation, variant):
    with pytest.raises(SignerRefused, match="operation_refused"):
        operation_spec(operation, variant)


def test_catalog_registry_is_immutable():
    with pytest.raises(TypeError):
        OPERATIONS[("raw", "default")] = next(iter(OPERATIONS.values()))


def test_owner_act_family_reuses_the_closed_wire_subject_and_freezes_its_input():
    from aweb_naapp.runtime.protected_signer import OwnerActOperation, ProtectedKeyContext

    context = ProtectedKeyContext(
        "signer",
        "team_controller",
        "demo:example.org",
        "example.org",
        "did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w",
        "example.org",
        1,
    )
    subject = {
        "app_id": "demo",
        "installation_id": "00000000-0000-4000-8000-000000000001",
        "role": "demo.owner",
        "cap": 3,
    }
    operation = OwnerActOperation(
        "00000000-0000-4000-8000-000000000002",
        context,
        "https://app.example.org",
        "human-credential.cap-set",
        "app",
        subject,
    )
    subject["cap"] = 100
    assert operation.intent()["subject"]["cap"] == 3
    assert operation.spec.operation == "human-credential.cap-set"
    assert operation.spec.needs_human
    with pytest.raises(SignerRefused):
        OwnerActOperation(
            operation.operation_id,
            context,
            operation.audience,
            "human-credential.cap-set",
            "app",
            {**subject, "cap": True},
        )
    with pytest.raises(SignerRefused):
        OwnerActOperation(
            operation.operation_id,
            context,
            operation.audience,
            "human-credential.cap-set",
            "app",
            {**subject, "signing_bytes": "raw"},
        )


def test_unimplemented_consumer_rows_are_named_but_never_turn_into_signing_requests():
    from aweb_naapp.runtime.protected_signer import OwnerActOperation, ProtectedKeyContext

    context = ProtectedKeyContext(
        "signer",
        "team_controller",
        "demo:example.org",
        "example.org",
        "did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w",
        "example.org",
        1,
    )
    for name in ("team.owner.change", "team.controller-permissions.change"):
        assert operation_spec(name).consumer_available is False
        with pytest.raises(SignerRefused, match="operation_refused"):
            OwnerActOperation(
                "00000000-0000-4000-8000-000000000002",
                context,
                "https://app.example.org",
                name,
                "default",
                {},
            )


def test_browser_uses_the_same_typed_catalog_and_exact_b2_commitment():
    """Real shipped JS, actual schema and existing signed wire neighbours."""
    import subprocess

    from aweb_naapp.runtime.protected_signer.catalog import presentation_catalog

    root = Path(__file__).resolve().parents[3]
    vectors = json.loads((root / "docs/vectors/owner-act-v1.json").read_bytes())
    cases = []
    table = presentation_catalog()
    for item in vectors["positive_cases"]:
        artifact = item["act"]
        spec = next(
            spec
            for spec in OPERATIONS.values()
            if spec.family == "owner_act" and spec.operation == artifact["act"]
        )
        cases.append(
            {
                "operation": spec.operation,
                "variant": spec.variant,
                "artifact": artifact,
            }
        )
    # The cap subject is the newer app owner-act variant, sharing this path.
    artifact = json.loads(json.dumps(cases[0]["artifact"]))
    artifact["act"] = "human-credential.cap-set"
    artifact["subject"] = {
        "app_id": "logs",
        "installation_id": "00000000-0000-4000-8000-000000000001",
        "role": "logs.owner",
        "cap": 3,
    }
    cases.append({"operation": artifact["act"], "variant": "app", "artifact": artifact})
    assert {case["operation"] for case in cases} == {
        spec.operation for spec in OPERATIONS.values() if spec.family == "owner_act"
    }
    script = r"""
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { validateProtectedPresentation } from './naapp-lib/src/aweb_naapp/assets/protected-presentation.mjs';
import { coveredRequestDigest } from './naapp-lib/src/aweb_naapp/assets/canonical-json.mjs';
const {table, cases} = JSON.parse(readFileSync(0, 'utf8'));
for (const {operation, variant, artifact} of cases) {
  const state = {
    mode: 'governance', handoff_id: 'handoff', state: 'pending',
    operation_id: 'operation', expires_at: artifact.expires_at,
    payload: {policy: {ref: 'aweb.human-assurance/1', version: 1}, request: {
      operation_id: 'operation', operation, variant, artifact,
      subject: structuredClone(artifact.subject), audience: artifact.aud,
      scope: {authority: {kind: 'team_controller', id: artifact.team_id}},
    }},
  };
  state.digest = await coveredRequestDigest(state.payload);
  assert.deepEqual((await validateProtectedPresentation(state, 'handoff', table)).subject, artifact.subject);
  // Consistent request+artifact substitution retains the original approval digest.
  const substituted = structuredClone(state);
  substituted.payload.request.subject.app_id = 'another-app';
  substituted.payload.request.artifact.subject.app_id = 'another-app';
  await assert.rejects(validateProtectedPresentation(substituted, 'handoff', table));
  // A recomputed digest cannot enable an unregistered field or mismatched typed artifact.
  for (const mutate of [
    s => {s.payload.request.artifact.subject.extra = 'raw'; s.payload.request.subject.extra = 'raw';},
    s => {s.payload.request.artifact.act = 'sign_bytes';},
    s => {s.payload.request.artifact.team_id = 'another:example.org';},
    s => {s.payload.request.variant = 'unknown';},
  ]) {
    const changed = structuredClone(state); mutate(changed);
    changed.digest = await coveredRequestDigest(changed.payload);
    await assert.rejects(validateProtectedPresentation(changed, 'handoff', table));
  }
}
console.log(`${cases.length} actual owner-act neighbours and substitution refusals passed`);
"""
    result = subprocess.run(
        ["node", "--input-type=module", "-e", script],
        input=json.dumps({"table": table, "cases": cases}),
        text=True,
        capture_output=True,
        cwd=root,
        timeout=20,
    )
    assert result.returncode == 0, result.stdout + result.stderr
