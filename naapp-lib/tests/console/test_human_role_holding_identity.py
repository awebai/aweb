"""A human-role holding's identity, ``human-role-holding/1``
(human-role-holders.md, The holding's identity), against its vector: the
public digest a console session binds to, which grants nothing."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from aweb_naapp.console.handoff_authority import PublicScope
from aweb_naapp.console.human_role_authority import (
    HumanRoleSessionTarget,
    holding_identity,
    human_role_holding_identity,
)
from aweb_naapp.runtime.installation import AdmittedInstallation

VECTOR = json.loads(
    (Path(__file__).resolve().parents[3] / "docs/vectors/human-role-holding-v1.json").read_text()
)


@pytest.mark.parametrize("case", VECTOR["cases"], ids=[c["name"] for c in VECTOR["cases"]])
def test_each_holding_has_the_vectors_identity(case: dict[str, Any]) -> None:
    assert holding_identity(case["fields"]) == case["identity"]


@pytest.mark.parametrize("case", VECTOR["refused"], ids=[c["name"] for c in VECTOR["refused"]])
def test_a_refused_holding_has_no_identity(case: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        holding_identity(case["fields"])


def test_identities_differ_whenever_the_holding_does() -> None:
    identities = [case["identity"] for case in VECTOR["cases"]]
    assert len(set(identities)) == len(identities)


@pytest.mark.parametrize(
    "change",
    [{"extra": "x"}, {"subject": ""}, {"app_id": 7}],
    ids=["an extra field", "an empty field", "a field that is not a string"],
)
def test_only_the_nine_nonempty_strings_name_a_holding(change: dict[str, Any]) -> None:
    fields = {**VECTOR["cases"][0]["fields"], **change}
    with pytest.raises(ValueError):
        holding_identity(fields)


def test_a_session_target_has_the_identity_of_its_holding() -> None:
    case = VECTOR["cases"][0]
    fields = case["fields"]
    admitted = AdmittedInstallation(
        team_id=fields["team_id"],
        app_id=fields["app_id"],
        installation_id=fields["installation_id"],
        generation=int(fields["generation"]),
    )
    target = HumanRoleSessionTarget(
        PublicScope(fields["installation_id"], fields["role"], fields["principal"]),
        admitted,
        fields["b3_scope"],
        fields["subject"],
        datetime.fromisoformat(fields["held_since"]),
    )
    assert human_role_holding_identity(target) == case["identity"]
