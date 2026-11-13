"""The OATS slice adds two signers, without exposing the unfinished catalog."""

import json
from pathlib import Path

import pytest

from aweb_naapp.runtime.protected_signer import SignerRefused
from aweb_naapp.runtime.protected_signer.catalog import OPERATIONS, operation_spec


def test_runtime_selectors_are_exactly_the_reviewed_slice_and_existing_revoke():
    assert set(OPERATIONS) == {
        ("identity.root.endorse", "default"),
        ("team.agent.admit", "default"),
        ("human-role.revoke", "default"),
    }
    frozen = json.loads((Path(__file__).resolve().parents[3] / "docs/vectors/human-assurance-v1.json").read_bytes())
    assert len(frozen["operations"]) == 80
    enforced = [row for row in frozen["operations"] if row["enforced_by"] == "signer"]
    assert len(enforced) == 53
    for row in enforced:
        selector = row["operation"], row["variant"]
        if selector not in OPERATIONS:
            with pytest.raises(SignerRefused, match="operation_refused"):
                operation_spec(*selector)
            continue
        spec = operation_spec(*selector)
        assert spec.key_role == row["key_role"] and spec.rule == row["rule"]
        assert spec.payload_binding == tuple(row["payload_binding"])
        assert spec.bounds == tuple(row["bounds"])


@pytest.mark.parametrize("name", ["sign_bytes", "team.log-key.sign", "team.owner.change", "team.controller-permissions.change"])
def test_no_unreviewed_route_or_generic_signing_operation_is_enabled(name):
    with pytest.raises(SignerRefused, match="operation_refused"):
        operation_spec(name)


@pytest.mark.asyncio
async def test_released_revoke_type_reaches_the_live_floor_execute_refusal():
    from types import SimpleNamespace
    from uuid import uuid4

    from aweb_naapp.runtime.protected_signer import (
        ProtectedKeyContext,
        ProtectedSigner,
        RestrictedRequester,
        RevokeHumanRole,
    )

    context = ProtectedKeyContext("signer", "team_controller", "team:example.org", "example.org", "did:aw:human", "example.org", 1)
    legacy = RevokeHumanRole(str(uuid4()), context, "https://app.example.org", "app", str(uuid4()), "app.owner", "did:aw:human")
    requester = RestrictedRequester("did:aw:root", context)
    service = object.__new__(ProtectedSigner)
    service.admission = SimpleNamespace()

    async def authorized(operation_id, actor, purpose):
        assert operation_id == legacy.operation_id and actor is requester and purpose == "execute"
        return {"request": legacy.intent()}

    service._authorized = authorized
    with pytest.raises(SignerRefused, match="live_approval_required"):
        await service._execute_request(legacy.operation_id, requester=requester)
