"""Native connect must bind a protected membership to its exact registry artifact.

A real controller registers the baseline certificate before a synthetic cutover.
This is future-contract RED, not an already activated production policy or proof
of the protected signer's success. The ID-only feature flag is enabled even on
legacy controls so its existing check cannot hide the reused-ID defect.
"""

from __future__ import annotations

import json
from uuid import uuid4

import pytest

from awid.signing import canonical_json_bytes, sign_message
from test_connect_http import (
    _encode_certificate,
    _make_certificate,
    _make_keypair,
    _register_controller,
    _signed_request,
    connect_app as connect_app,
)


@pytest.mark.asyncio
@pytest.mark.parametrize("protected", [False, True], ids=["legacy", "protected"])
@pytest.mark.parametrize(
    "case",
    [
        "genuine",
        "reused-id-member",
        "reused-id-alias",
        "unsigned-alteration",
        "unknown-id",
    ],
)
async def test_connect_binds_the_full_protected_registered_certificate(
    connect_app,
    monkeypatch,
    protected,
    case,
):
    env = connect_app
    monkeypatch.setenv("AWEB_REQUIRE_REGISTERED_CERTIFICATES", "1")
    team_key, _, team_did = _make_keypair()
    member_key, _, member_did = _make_keypair()
    await _register_controller(env, team_did)
    cert = _make_certificate(
        team_key,
        team_did,
        member_did,
        identity_scope="local",
        certificate_id=str(uuid4()),
        alias="admitted-member",
    )
    env.registry_app.state.awid_public_origins = ("http://registry.test",)
    registry = env.app.state.awid_registry_client
    await registry.register_team_certificate(
        "acme.com",
        "backend",
        team_controller_signing_key=team_key,
        certificate_id=cert["certificate_id"],
        member_did_key=member_did,
        alias=cert["alias"],
        identity_scope="local",
        certificate=_encode_certificate(cert),
    )
    if protected:
        _, _, service_did = _make_keypair()
        await env.registry_db.execute(
            "INSERT INTO {{tables.team_protection}} "
            "(domain, name, service_id, service_did_key, generation) VALUES ($1,$2,$3,$4,$5)",
            "acme.com",
            "backend",
            "independent-signer",
            service_did,
            1,
        )
    presented = dict(cert)
    if case == "reused-id-member":
        member_key, _, member_did = _make_keypair()
        presented["member_did_key"] = member_did
    elif case in {"reused-id-alias", "unsigned-alteration"}:
        presented["alias"] = "different-member"
    elif case == "unknown-id":
        presented["certificate_id"] = str(uuid4())
    if case not in {"genuine", "unsigned-alteration"}:
        fields = {k: v for k, v in presented.items() if k != "signature"}
        presented["signature"] = sign_message(team_key, canonical_json_bytes(fields))
    body = json.dumps(
        {"hostname": "task-test", "workspace_path": "/disposable/connect"}
    ).encode()
    signed = _signed_request(member_key, member_did, cert["team_id"], body)
    response = await env.client.post(
        "/v1/connect",
        content=body,
        headers={
            **signed,
            "Content-Type": "application/json",
            "X-AWID-Team-Certificate": _encode_certificate(presented),
        },
    )
    refuses = case in {"unsigned-alteration", "unknown-id"} or (
        protected and case.startswith("reused-id")
    )
    assert response.status_code == (401 if refuses else 200), response.text
    rows = await env.db.fetch_all(
        "SELECT did_key, alias FROM {{tables.agents}} WHERE team_id=$1", cert["team_id"]
    )
    if refuses:
        assert not rows
        if protected and case.startswith("reused-id"):
            assert "certificate_binding_mismatch" in response.text
    else:
        assert len(rows) == 1
        assert rows[0]["did_key"] == member_did
        assert rows[0]["alias"] == presented["alias"]
