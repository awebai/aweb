"""The B3 scope of a human-role holding (human-role-holders.md, Reading a holding).

The scope is named by the installation, the team and the principal, with the
role as its prefix only, so it equals the scope secrets already gives its
owners. It is never derived from a contact.
"""

from __future__ import annotations

import pytest

from aweb_naapp.roles import holding_scope

INSTALLATION = "9d7f1c2e-4b1a-4c55-8f0e-2a6b3c4d5e6f"
TEAM = "aweb:example.com"
PRINCIPAL = "did:aw:2Wq7mXn4kP9rT1vY5zA8bC3dE6"


def test_a_holding_scope_matches_its_vector() -> None:
    assert (
        holding_scope(INSTALLATION, TEAM, "logs.reader", PRINCIPAL)
        == "logs.reader.b6fb3a967c72ce75acb186ac9a82bd5a18bc40a0"
    )


def test_the_role_names_only_the_prefix() -> None:
    reader = holding_scope(INSTALLATION, TEAM, "logs.reader", PRINCIPAL)
    owner = holding_scope(INSTALLATION, TEAM, "secrets.owner", PRINCIPAL)
    assert reader.removeprefix("logs.reader.") == owner.removeprefix("secrets.owner.")


def test_each_installation_team_and_principal_has_its_own_scope() -> None:
    here = holding_scope(INSTALLATION, TEAM, "logs.reader", PRINCIPAL)
    assert here != holding_scope("other-installation", TEAM, "logs.reader", PRINCIPAL)
    assert here != holding_scope(INSTALLATION, "acme:example.org", "logs.reader", PRINCIPAL)
    assert here != holding_scope(INSTALLATION, TEAM, "logs.reader", "did:aw:3Xr8nYo5lQ0sU2wZ6aB9cD4eF7")


@pytest.mark.parametrize("role", ["logs", "Logs.Reader", "logs..reader"])
def test_a_scope_needs_an_app_named_role(role: str) -> None:
    with pytest.raises(ValueError):
        holding_scope(INSTALLATION, TEAM, role, PRINCIPAL)


def test_a_scope_needs_a_did_aw_principal() -> None:
    with pytest.raises(ValueError):
        holding_scope(INSTALLATION, TEAM, "logs.reader", "did:key:z6MkfirstKey")
