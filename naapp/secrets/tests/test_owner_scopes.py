"""B3 scopes for secrets' owners and approvers (decision 40)."""

from __future__ import annotations

import hashlib
import re

import pytest

from aweb_secrets.owners import approver_scope, is_owner_scope, owner_scope

INSTALLATION = "1b4e28ba-2fa1-4d3b-a3f5-ef19b5a7633b"
OTHER_INSTALLATION = "6f9619ff-8b86-4011-b42d-00c04fc964ff"
PRINCIPAL = "did:aw:jPUMBAvNeJo8USHNtJ81Wm7cqnk"
# K2's role token: the scope travels as the role of an aweb.owner-act/1 subject.
OWNER_ACT_ROLE = re.compile(r"[a-z][a-z0-9_.-]{0,63}")


def test_an_owner_scope_is_named_by_installation_and_principal() -> None:
    digest = hashlib.sha256(f"{INSTALLATION}\n{PRINCIPAL}".encode()).hexdigest()
    assert owner_scope(INSTALLATION, PRINCIPAL) == "secrets.owner." + digest[:40]


def test_one_principal_owns_a_distinct_scope_in_each_installation() -> None:
    assert owner_scope(INSTALLATION, PRINCIPAL) != owner_scope(OTHER_INSTALLATION, PRINCIPAL)


def test_an_approver_scope_is_named_by_installation_and_approver() -> None:
    digest = hashlib.sha256(f"{INSTALLATION}\nfinance".encode()).hexdigest()
    assert approver_scope(INSTALLATION, "finance") == "secrets.approver." + digest[:40]
    assert approver_scope(INSTALLATION, "finance") != approver_scope(OTHER_INSTALLATION, "finance")


@pytest.mark.parametrize(
    "scope",
    [owner_scope(INSTALLATION, PRINCIPAL), approver_scope(INSTALLATION, "finance")],
)
def test_every_scope_fits_an_owner_acts_role(scope: str) -> None:
    assert OWNER_ACT_ROLE.fullmatch(scope)


def test_only_owner_scopes_are_owner_scopes() -> None:
    assert is_owner_scope(owner_scope(INSTALLATION, PRINCIPAL))
    assert not is_owner_scope(approver_scope(INSTALLATION, "finance"))
    assert not is_owner_scope("secrets.owner")
    assert not is_owner_scope("secrets.owner." + "A" * 40)
