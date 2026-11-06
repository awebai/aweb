"""The identity-tree registry request layout: paths, bodies and covering-v2 payloads.

These are pure functions shared by RegistryClient and by any host that checks,
before it signs, that a payload is exactly the request it intends.
"""

from __future__ import annotations

import pytest

from awid.id_tree_requests import (
    REGISTER_OPERATION,
    REGISTER_PATH,
    REVOKE_OPERATION,
    REVOKE_PATH,
    ROTATE_OPERATION,
    covering_payload,
    register_body,
    revoke_body,
    rotate_body,
    rotate_claims,
    rotate_path,
)

from id_tree_support import VECTORS

EXAMPLE = VECTORS["registration_example"]
ROTATION = VECTORS["namespace_rotation_requests"]


def test_the_registration_request_is_the_frozen_example():
    body = register_body(
        EXAMPLE["body"]["certificate"],
        expected_head=EXAMPLE["body"]["expected_head"],
        invitation_id=EXAMPLE["body"]["invitation_id"],
    )
    payload = covering_payload(
        aud=EXAMPLE["payload"]["aud"], path=REGISTER_PATH, domain=EXAMPLE["payload"]["domain"],
        operation=REGISTER_OPERATION, body=body, timestamp=EXAMPLE["payload"]["timestamp"],
    )

    assert body == EXAMPLE["body_utf8"].encode()
    assert payload == EXAMPLE["canonical_payload_utf8"].encode()


def test_the_signed_rotation_request_is_the_frozen_example():
    frozen = ROTATION["valid"]
    domain = frozen["body"]["domain"]
    claims = rotate_claims(
        from_seq=frozen["body"]["from_seq"],
        previous_did_key=frozen["body"]["previous_did_key"],
        new_did_key=frozen["body"]["new_did_key"],
    )
    body = rotate_body(domain, claims)
    payload = covering_payload(
        aud=frozen["payload"]["aud"], path=rotate_path(domain), domain=domain,
        operation=ROTATE_OPERATION, body=body, timestamp=frozen["payload"]["timestamp"], claims=claims,
    )

    assert body == frozen["body_utf8"].encode()
    assert payload == frozen["canonical_payload_utf8"].encode()


@pytest.mark.parametrize("effective_from", [None, "2026-10-26T00:05:00Z"])
def test_the_revocation_body_has_exactly_the_contract_fields_in_canonical_form(effective_from):
    body = revoke_body(
        "example.com", "did:aw:2e2SPDJNyxg5Dt6EFJX3Tcn8Tauj",
        expected_head="sha256:" + "0" * 64, effective_from=effective_from,
    )

    expected = (
        '{"domain":"example.com","effective_from":%s,"expected_head":"sha256:%s","id":"did:aw:2e2SPDJNyxg5Dt6EFJX3Tcn8Tauj"}'
        % ("null" if effective_from is None else f'"{effective_from}"', "0" * 64)
    )
    assert body == expected.encode()


def test_the_paths_and_operations_are_the_registry_routes():
    assert (REGISTER_PATH, REGISTER_OPERATION) == (EXAMPLE["payload"]["path"], EXAMPLE["payload"]["operation"])
    assert REVOKE_PATH == "/v1/id-certificates/revoke"
    assert REVOKE_OPERATION == "revoke_id_certificate"
    assert (rotate_path("example.com"), ROTATE_OPERATION) == (
        ROTATION["valid"]["payload"]["path"], ROTATION["valid"]["payload"]["operation"],
    )


def test_the_layout_needs_no_server_framework():
    import subprocess
    import sys

    probe = "import sys, awid.id_tree_requests; print('fastapi' in sys.modules)"
    out = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "False"
