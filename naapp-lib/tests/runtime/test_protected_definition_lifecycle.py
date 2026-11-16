"""Lifecycle choices belong to definitions; the generic engine has no name list."""

from datetime import timedelta
from uuid import uuid4

import pytest

from aweb_naapp.runtime.protected_signer import RevokeHumanRole
from aweb_naapp.runtime.protected_signer.catalog import operation_spec
from aweb_naapp.runtime.protected_signer.codecs import artifact_for
from aweb_naapp.runtime.protected_signer.http import parse_operation
from tests.runtime.test_protected_identity_artifacts import HKEY, NOW, operation


@pytest.mark.parametrize("name,fields,port,persist,expiry", [
    ("identity.root.endorse", {"registry", "expected_head", "responsibility_statement", "admission_policy"}, "sign_operation", True, True),
    ("team.agent.admit", {"request_id", "admission_policy_version"}, "sign_operation", True, False),
    ("team.agent.remove", {"requester_key"}, "sign_operation", True, False),
    ("human-role.revoke", set(), "sign_owner_act", False, False),
])
def test_existing_definition_retains_its_prepared_members_ports_and_receipt_rules(name, fields, port, persist, expiry):
    spec = operation_spec(name)
    assert spec.prepared_fields == frozenset(fields)
    assert spec.signing_port == port
    assert spec.finalize_execution_refusal is persist
    assert spec.receipt_uv_expiry is expiry
    assert spec.supports_self_removal is (name == "team.agent.remove")


def test_request_deadlines_preserve_artifact_and_existing_request_window():
    for name in ["identity.root.endorse", "team.agent.admit"]:
        op = operation(name)
        assert op.spec.effect_deadline(artifact_for(op, HKEY, NOW), NOW + timedelta(seconds=600)) == NOW + timedelta(seconds=600)
    spec = operation_spec("team.agent.remove")
    artifact = {"request": {"timestamp": "2026-11-13T12:00:00Z"}}
    assert spec.effect_deadline(artifact, NOW + timedelta(seconds=600)) == NOW + timedelta(seconds=300)
    assert spec.effect_deadline(artifact, NOW + timedelta(seconds=60)) == NOW + timedelta(seconds=60)


def test_http_definition_preserves_released_revoke_type_and_exact_body():
    context = operation("team.agent.admit").context
    legacy = RevokeHumanRole(str(uuid4()), context, "https://app.customer.example", "app", str(uuid4()), "app.owner", context.human_id)
    parsed = parse_operation(legacy.intent())
    assert type(parsed) is RevokeHumanRole and parsed == legacy
    assert callable(operation_spec("human-role.revoke").codec.decode_intent)
    for name in ["identity.root.endorse", "team.agent.admit"]:
        op = operation(name)
        assert parse_operation(op.intent()).intent() == op.intent()
