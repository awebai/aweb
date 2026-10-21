"""change/1 items for the records secrets admits by: secrets, grants, grant templates, policies."""

from __future__ import annotations

import copy
from typing import Any

import pytest
from awid.did import stable_id_from_public_key
from nacl.signing import SigningKey

from aweb_secrets.change import KINDS, ChangeRefused, validate_change
from aweb_secrets.policy import Policy

DID_AW = stable_id_from_public_key(bytes(SigningKey(b"\x01" * 32).verify_key))

SECRET = {
    "v": 1,
    "secret_id": "sec_19ab42",
    "ref": "payments-live",
    "description": "Live payments API key",
    "kind": "bearer",
    "kind_params": {},
    "sensitivity": "sensitive",
    "approve_only": True,
    "backend": "native",
}
POLICY_BODY = {
    "approval": "per_use",
    "approvers": ["finance-approver"],
    "approval_ttl_s": 900,
    "rate": [{"per": "principal_secret", "capacity": 30, "window_s": 3600}],
    "windows": None,
    "operations": [{"operation_id": "refund", "digest": "a" * 64}],
    "open_request": False,
    "request": {"max_bytes": 65536},
    "result": {"max_bytes": 65536},
    "requires_attestation": None,
    "distinct_approver": "required",
}
POLICY_DIGEST = Policy.from_body(POLICY_BODY).digest
GRANT = {
    "v": 1,
    "grant_id": "grt_77c1aa",
    "secret_id": "sec_19ab42",
    "subject": {"principal": DID_AW},
    "capability": "use",
    "operations": [{"operation_id": "refund", "digest": "a" * 64}],
    "open_request": False,
    "jobs": [],
    "policy_digest": POLICY_DIGEST,
}
TEMPLATE = {
    "v": 1,
    "grant_template_id": "gtp_sts-derived",
    "subject": {"role": "secrets.role.deployers"},
    "capability": "use",
    "operations": [{"operation_id": "refund", "digest": "a" * 64}],
    "open_request": False,
    "jobs": [],
    "policy_digest": POLICY_DIGEST,
}

DESTINATION = {
    "v": 1,
    "destination_id": "dst_refunds01",
    "secret_id": "sec_19ab42",
    "scheme": "https",
    "host": "api.payments.example",
    "port": 443,
    "path": "/v1/refunds/**",
    "methods": ["POST"],
    "query_rules": {},
    "header_allow": ["idempotency-key"],
    "network": "public",
    "cidr": None,
}

OPERATION = {
    "v": 1,
    "operation_id": "charge-status",
    "secret_id": "sec_19ab42",
    "method": "GET",
    "url": {"host": "api.payments.example", "port": 443, "path": "/v1/charges/{charge}"},
    "params": {
        "charge": {
            "schema": {"type": "string", "minLength": 3, "maxLength": 64},
            "charset": "base64url",
            "placement": "path",
        }
    },
    "body": None,
    "headers": {"fixed": {}, "allowed": []},
    "response": {
        "projection": ["/status"],
        "max_bytes": 4096,
        "content_types": ["application/json"],
    },
    "side_effect": "none",
    "token_issuing": False,
    "result_handling": "deny",
    "store_as_secret": None,
    "idempotency": None,
    "reconcile": None,
    "timeout_s": 10,
}

ITEMS = {
    "operation": {
        "kind": "operation",
        "op": "create",
        "ref": "charge-status",
        "after": OPERATION,
    },
    "destination": {
        "kind": "destination",
        "op": "create",
        "ref": "dst_refunds01",
        "after": DESTINATION,
    },
    "secret": {"kind": "secret", "op": "create", "ref": "payments-live", "after": SECRET},
    "policy": {
        "kind": "policy",
        "op": "create",
        "ref": POLICY_DIGEST,
        "after": {"v": 1, **POLICY_BODY},
    },
    "grant": {"kind": "grant", "op": "create", "ref": "grt_77c1aa", "after": GRANT},
    "grant_template": {
        "kind": "grant_template",
        "op": "create",
        "ref": "gtp_sts-derived",
        "after": TEMPLATE,
    },
}


def _change(*items: dict[str, Any]) -> dict[str, Any]:
    return {
        "v": 1,
        "type": "aweb.secrets.change",
        "change_id": "chg_1",
        "installation_id": "inst_1",
        "install_generation": 1,
        "team_id": "backend:acme.com",
        "drafter": {"via": "console", "scope": "secrets.owner.p1", "subject": "approver-1"},
        "base_revision": 7,
        "changes": [copy.deepcopy(item) for item in items],
        "reason": "set up refunds",
        "issued_at": "2026-10-20T12:00:00Z",
        "expires_at": "2026-10-20T12:15:00Z",
    }


def _item(name: str, **changes: Any) -> dict[str, Any]:
    item = copy.deepcopy(ITEMS[name])
    after = changes.pop("after", {})
    item.update(changes)
    item["after"].update(after)
    return item


def test_the_record_kinds_and_their_widening_ops() -> None:
    assert KINDS["secret"] == {"create", "update"}
    assert KINDS["policy"] == {"create"}
    assert KINDS["destination"] == {"create"}
    assert KINDS["operation"] == {"create"}
    assert KINDS["grant"] == {"create"}
    assert KINDS["grant_template"] == {"create", "update"}


def test_one_change_set_can_carry_each_record() -> None:
    validate_change(_change(*ITEMS.values()))


@pytest.mark.parametrize("op", ["create", "update"])
def test_a_secret_and_a_grant_template_take_both_widening_ops(op) -> None:
    validate_change(_change(_item("secret", op=op), _item("grant_template", op=op)))


@pytest.mark.parametrize(
    "item",
    [
        _item("secret", after={"kind": "api_key"}),
        _item("secret", after={"approve_only": True, "sensitivity": "standard"}),
        _item("secret", ref="payroll"),
        _item("grant", after={"subject": {"principal": "did:aw:2rMeyRyvQbWUZYjT8Jx6Kq"}}),
        _item("grant", after={"operations": [], "open_request": False}),
        _item("grant", ref="grt_other1"),
        _item("grant", op="update"),
        _item("grant_template", ref="gtp_other1"),
        _item("policy", ref="b" * 64),
        _item("policy", after={"approval_ttl_s": 600}),
        _item("policy", after={"approval": "sometimes"}),
        _item("policy", op="update"),
        _item("secret", after={"value": "fixture"}),
        _item("operation", ref="refund"),
        _item("operation", op="update"),
        _item("operation", after={"timeout_s": 31}),
        _item("operation", after={"method": "TRACE"}),
        _item("destination", ref="dst_other01"),
        _item("destination", op="update"),
        _item("destination", after={"host": "API.payments.example"}),
        _item("destination", after={"scheme": "http"}),
        _item("destination", after={"methods": ["POST", "GET"]}),
    ],
)
def test_a_malformed_record_item_is_refused(item) -> None:
    with pytest.raises(ChangeRefused):
        validate_change(_change(item))


def test_a_policy_is_referenced_by_the_digest_of_its_body() -> None:
    changed = {**POLICY_BODY, "approval_ttl_s": 600}
    item = _item("policy", ref=Policy.from_body(changed).digest, after={"approval_ttl_s": 600})
    validate_change(_change(item))


def test_the_same_record_twice_in_one_change_set_is_refused() -> None:
    with pytest.raises(ChangeRefused):
        validate_change(_change(ITEMS["grant"], ITEMS["grant"]))
    with pytest.raises(ChangeRefused):
        validate_change(_change(ITEMS["policy"], ITEMS["policy"]))


def test_a_derived_field_never_shadows_an_after_field(monkeypatch) -> None:
    from aweb_secrets import change

    shape = change.AFTER_SHAPES[("grant", 1)]
    shadowing = change.AfterShape(
        fields=shape.fields,
        ref_field=shape.ref_field,
        identity=shape.identity,
        derived=lambda after, where: {"capability": "run"},
    )
    monkeypatch.setitem(change.AFTER_SHAPES, ("grant", 1), shadowing)
    with pytest.raises(ChangeRefused):
        validate_change(_change(ITEMS["grant"]))


def test_two_templates_of_one_operation_are_two_objects() -> None:
    edited = {**OPERATION, "timeout_s": 5}
    validate_change(_change(ITEMS["operation"], {**ITEMS["operation"], "after": edited}))
    with pytest.raises(ChangeRefused):
        validate_change(_change(ITEMS["operation"], ITEMS["operation"]))
