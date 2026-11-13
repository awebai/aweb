"""Detached effects bind independent service authority to exact retained bytes."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from awid.did import did_from_public_key, generate_keypair
from awid.protected_effect import (
    EffectRefused,
    artifact_digest,
    http_consumer,
    issue_proof,
    verify_proof,
)
from awid.signing import canonical_json_bytes, sign_message

NOW = datetime(2026, 11, 13, 12, tzinfo=timezone.utc)


def example():
    service_key, service_public = generate_keypair()
    controller_key, controller_public = generate_keypair()
    binding = {
        "mode": "protected",
        "service_id": "test-service",
        "service_did_key": did_from_public_key(service_public),
        "history_id": str(uuid4()),
        "generation": 1,
    }
    artifact = canonical_json_bytes(
        {"team_id": "team:example.test", "action": "revoke"}
    )
    signature = sign_message(controller_key, artifact)
    consumer = http_consumer(
        audience="https://registry.example",
        method="POST",
        path="/v1/team/revoke?a=1",
        body=b'{"certificate_id":"exact"}',
        controller_envelope=b"exact-envelope",
    )
    fields = {
        "v": 1,
        "type": "aweb.protected-effect",
        "service_id": binding["service_id"],
        "team_id": "team:example.test",
        "history_id": binding["history_id"],
        "generation": 1,
        "controller_did_key": did_from_public_key(controller_public),
        "operation": "team.agent.remove",
        "variant": "default",
        "operation_id": str(uuid4()),
        "artifact_type": "controller-request",
        "artifact_sha256": artifact_digest(artifact, signature),
        "consumer": consumer,
        "issued_at": NOW.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": (NOW + timedelta(seconds=120)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    return service_key, binding, fields, artifact, signature


def check(proof, binding, fields, artifact, signature, **overrides):
    args = dict(
        binding=binding,
        team_id=fields["team_id"],
        controller_did_key=fields["controller_did_key"],
        operations={("team.agent.remove", "default")},
        artifact_type=fields["artifact_type"],
        artifact=artifact,
        artifact_signature=signature,
        consumer=fields["consumer"],
        now=NOW,
    )
    args.update(overrides)
    return verify_proof(proof, **args)


def test_exact_retained_service_proof_verifies_and_retries_unchanged():
    key, binding, fields, artifact, signature = example()
    proof = issue_proof(fields, key)
    assert check(proof, binding, fields, artifact, signature) == fields
    assert check(proof, binding, fields, artifact, signature) == fields
    assert proof == issue_proof(fields, key)


@pytest.mark.parametrize(
    "dimension",
    [
        "team",
        "controller",
        "service",
        "history",
        "generation",
        "operation",
        "artifact",
        "signature",
        "route",
        "audience",
        "body",
        "envelope",
        "expired",
    ],
)
def test_service_proof_cannot_move_between_authorities_effects_or_consumers(dimension):
    key, binding, fields, artifact, signature = example()
    proof = issue_proof(fields, key)
    override = {}
    if dimension in {"service", "history", "generation"}:
        binding = {
            **binding,
            {
                "service": "service_id",
                "history": "history_id",
                "generation": "generation",
            }[dimension]: 2 if dimension == "generation" else "different",
        }
    elif dimension == "team":
        override["team_id"] = "other:example.test"
    elif dimension == "controller":
        override["controller_did_key"] = binding["service_did_key"]
    elif dimension == "operation":
        override["operations"] = {("team.controller.rotate", "default")}
    elif dimension == "artifact":
        artifact += b" "
    elif dimension == "signature":
        signature = sign_message(key, artifact)
    elif dimension == "expired":
        override["now"] = NOW + timedelta(seconds=120)
    else:
        consumer = deepcopy(fields["consumer"])
        field = {
            "route": "path",
            "audience": "audience",
            "body": "body_sha256",
            "envelope": "controller_envelope_sha256",
        }[dimension]
        consumer[field] += "different"
        override["consumer"] = consumer
    with pytest.raises(EffectRefused):
        check(proof, binding, fields, artifact, signature, **override)


def test_controller_key_is_not_the_isolated_service_key():
    _, binding, fields, artifact, signature = example()
    wrong_key, _ = generate_keypair()
    with pytest.raises(EffectRefused):
        check(issue_proof(fields, wrong_key), binding, fields, artifact, signature)


@pytest.mark.parametrize(
    "mutation", ["extra", "float", "bool-generation", "missing", "bad-deadline"]
)
def test_proof_encoding_is_closed_and_portable(mutation):
    key, _, fields, _, _ = example()
    if mutation == "extra":
        fields["extra"] = "refuse"
    elif mutation == "float":
        fields["generation"] = 1.0
    elif mutation == "bool-generation":
        fields["generation"] = True
    elif mutation == "missing":
        del fields["operation_id"]
    else:
        fields["expires_at"] = fields["issued_at"]
    with pytest.raises(EffectRefused):
        issue_proof(fields, key)


@pytest.mark.parametrize("evidence", [None, {}, {"mode": "unsupported"}])
def test_unknown_protection_evidence_never_becomes_legacy(evidence):
    from awid.protected_effect import validate_binding

    with pytest.raises(EffectRefused) as error:
        validate_binding(evidence)
    assert error.value.code == "protected_state_unavailable"


def test_original_observation_deadline_is_not_extended_by_read_or_legacy_check(
    monkeypatch,
):
    from awid import protected_membership

    observation = protected_membership.TeamProtectionObservation(
        "team:example.test",
        "unused-in-this-clock-control",
        {"mode": "legacy"},
        100.0,
    )
    monkeypatch.setattr(protected_membership, "monotonic", lambda: 99.0)
    observation.require_legacy_admission()
    assert observation.deadline == 100.0
    monkeypatch.setattr(protected_membership, "monotonic", lambda: 100.0)
    with pytest.raises(EffectRefused, match="protected_state_unavailable"):
        observation.require_legacy_admission()


@pytest.mark.parametrize(
    "changed",
    [
        None,
        "member_did_key",
        "alias",
        "identity_scope",
        "member_did_aw",
        "member_address",
        "certificate_sha256",
    ],
)
def test_retained_membership_pure_check_matches_every_consumed_authoritative_field(
    changed,
):
    from time import monotonic
    from types import SimpleNamespace
    from awid.protected_membership import (
        TeamProtectionObservation,
        check_retained_membership_record,
    )
    from awid.team_certificate import TeamCertificateError

    _, binding, fields, _, _ = example()
    observation = TeamProtectionObservation(
        fields["team_id"], fields["controller_did_key"], binding, monotonic() + 60
    )
    values = dict(
        certificate_id=str(uuid4()),
        member_did_key="original-key",
        alias="original-alias",
        identity_scope="global",
        member_did_aw="original-id",
        member_address="example.test/original",
        certificate_sha256="a" * 64,
    )
    record = SimpleNamespace(**values, revoked_at=None)
    if changed is not None:
        values[changed] = "changed"
        with pytest.raises(TeamCertificateError, match="certificate_binding_mismatch"):
            check_retained_membership_record(observation, record, **values)
    else:
        check_retained_membership_record(observation, record, **values)


@pytest.mark.parametrize(
    "principal,accepted",
    [
        ("did:key:original", True),
        ("did:aw:original", True),
        ("did:key:other", False),
        ("did:aw:other", False),
    ],
)
def test_subject_only_retained_baseline_never_copies_unused_fields(principal, accepted):
    from time import monotonic
    from types import SimpleNamespace
    from awid.protected_membership import (
        TeamProtectionObservation,
        check_retained_subject_record,
    )
    from awid.team_certificate import TeamCertificateError

    _, binding, fields, _, _ = example()
    observation = TeamProtectionObservation(
        fields["team_id"], fields["controller_did_key"], binding, monotonic() + 60
    )
    record = SimpleNamespace(
        certificate_id="original-cert",
        member_did_key="did:key:original",
        member_did_aw="did:aw:original",
        revoked_at=None,
        certificate_sha256="a" * 64,
    )
    arguments = dict(
        certificate_id="original-cert",
        controller_did_key=fields["controller_did_key"],
        principal=principal,
    )
    if accepted:
        check_retained_subject_record(observation, record, **arguments)
    else:
        with pytest.raises(TeamCertificateError, match="certificate_binding_mismatch"):
            check_retained_subject_record(observation, record, **arguments)


def test_public_protected_effect_vector_and_authority_refusals():
    import base64
    import json
    from pathlib import Path

    fixture = (
        Path(__file__).resolve().parents[2] / "docs/vectors/protected-effect-v1.json"
    )
    vector = json.loads(fixture.read_bytes())
    fields = vector["fields"]
    artifact = base64.b64decode(vector["artifact_signing_b64"], validate=True)
    signature = vector["artifact_signature"]
    assert artifact_digest(artifact, signature) == vector["artifact_sha256"]
    assert (
        check(
            vector["proof"],
            vector["binding"],
            fields,
            artifact,
            signature,
            now=datetime.fromisoformat(vector["now"].replace("Z", "+00:00")),
        )
        == fields
    )
    for case in vector["invalid"]:
        with pytest.raises(EffectRefused):
            check(
                vector["proof"],
                {**vector["binding"], **case["binding_override"]},
                fields,
                artifact,
                signature,
            )
