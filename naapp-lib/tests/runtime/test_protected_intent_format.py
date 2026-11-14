"""One live approval format; old execution is refused before any state access."""

from copy import deepcopy

import pytest

from aweb_naapp.runtime.protected_signer import SignerRefused
from aweb_naapp.runtime.protected_signer.http import _http, parse_operation
from tests.runtime.test_protected_execution_intent import live_operation
from tests.runtime.test_protected_identity_artifacts import operation


@pytest.mark.parametrize("name", ["root", "owner_act", "removal"])
def test_live_rows_emit_and_accept_only_the_current_approval_format(name):
    op = live_operation(name)
    body = op.intent()
    assert body["approval_format"] == "intent_v1"
    assert parse_operation(body).intent() == body
    for version in [None, "artifact_v0", "intent_v2", {}, 1]:
        old = deepcopy(body)
        if version is None:
            del old["approval_format"]
        else:
            old["approval_format"] = version
        with pytest.raises(SignerRefused) as error:
            parse_operation(old)
        assert error.value.code == "upgrade_aw_required"
        response = _http(error.value)
        assert response.status_code == 426 and response.detail == "upgrade_aw_required"


def test_bounded_neighbor_keeps_the_released_exact_members():
    op = operation("team.agent.admit")
    assert "approval_format" not in op.intent()
    assert parse_operation(op.intent()).intent() == op.intent()
    with pytest.raises(SignerRefused, match="request_invalid"):
        parse_operation({**op.intent(), "approval_format": "intent_v1"})
