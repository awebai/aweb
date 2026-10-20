"""B3 scopes for secrets' owners and approvers (decision 40)."""

from __future__ import annotations

import hashlib
import re

import pytest

from aweb_secrets.owners import approver_scope, is_owner_scope, owner_scope

INSTALLATION = "1b4e28ba-2fa1-4d3b-a3f5-ef19b5a7633b"
OTHER_INSTALLATION = "6f9619ff-8b86-4011-b42d-00c04fc964ff"
TEAM = "backend:acme.com"
OTHER_TEAM = "backend:other.com"
PRINCIPAL = "did:aw:jPUMBAvNeJo8USHNtJ81Wm7cqnk"
# K2's role token: the scope travels as the role of an aweb.owner-act/1 subject.
OWNER_ACT_ROLE = re.compile(r"[a-z][a-z0-9_.-]{0,63}")


def test_an_owner_scope_is_named_by_installation_team_and_principal() -> None:
    digest = hashlib.sha256(f"{INSTALLATION}\n{TEAM}\n{PRINCIPAL}".encode()).hexdigest()
    assert owner_scope(INSTALLATION, TEAM, PRINCIPAL) == "secrets.owner." + digest[:40]


def test_one_principal_owns_a_distinct_scope_per_installation_and_team() -> None:
    here = owner_scope(INSTALLATION, TEAM, PRINCIPAL)
    assert here != owner_scope(OTHER_INSTALLATION, TEAM, PRINCIPAL)
    assert here != owner_scope(INSTALLATION, OTHER_TEAM, PRINCIPAL)


def test_an_approver_scope_is_named_by_installation_team_and_approver() -> None:
    digest = hashlib.sha256(f"{INSTALLATION}\n{TEAM}\nfinance".encode()).hexdigest()
    scope = approver_scope(INSTALLATION, TEAM, "finance")
    assert scope == "secrets.approver." + digest[:40]
    assert scope != approver_scope(OTHER_INSTALLATION, TEAM, "finance")
    assert scope != approver_scope(INSTALLATION, OTHER_TEAM, "finance")


@pytest.mark.parametrize(
    "scope",
    [owner_scope(INSTALLATION, TEAM, PRINCIPAL), approver_scope(INSTALLATION, TEAM, "finance")],
)
def test_every_scope_fits_an_owner_acts_role(scope: str) -> None:
    assert OWNER_ACT_ROLE.fullmatch(scope)


def test_only_owner_scopes_are_owner_scopes() -> None:
    assert is_owner_scope(owner_scope(INSTALLATION, TEAM, PRINCIPAL))
    assert not is_owner_scope(approver_scope(INSTALLATION, TEAM, "finance"))
    assert not is_owner_scope("secrets.owner")
    assert not is_owner_scope("secrets.owner." + "A" * 40)
