"""Local operator input grammar; the native suite proves current authority."""

import pytest
from aweb_naapp.runtime.protected_signer import SignerRefused
from awid.did import did_from_public_key, generate_keypair, stable_id_from_did_key

from aweb.protected_signing.operator import parser
from aweb.protected_signing.root_binding import binding_inputs


def principal():
    _, public = generate_keypair()
    return stable_id_from_did_key(did_from_public_key(public))


def test_local_binding_names_one_human_registered_root_and_explicit_teams():
    human, root, old = principal(), principal(), principal()
    teams = ["zeta:example.org", "alpha:example.org"]
    assert binding_inputs(human, root, teams, old) == (human, root, sorted(teams), old)
    assert teams == ["zeta:example.org", "alpha:example.org"]
    args = parser().parse_args(["bind-root", "--human", human, "--root", root,
        "--team", teams[0], "--team", teams[1], "--replace-root", old])
    assert args.human == human and args.root == root and args.team == teams and args.replace_root == old


@pytest.mark.parametrize("case", ["local_root", "empty_human", "no_teams", "duplicate_team", "bad_team", "same_replacement", "local_replacement"])
def test_binding_cannot_infer_a_root_human_or_team(case):
    human, root, old, teams = principal(), principal(), None, ["team:example.org"]
    _, public = generate_keypair()
    if case == "local_root":
        root = did_from_public_key(public)
    if case == "empty_human":
        human = ""
    if case == "no_teams":
        teams = []
    if case == "duplicate_team":
        teams *= 2
    if case == "bad_team":
        teams = ["not a canonical team"]
    if case == "same_replacement":
        old = root
    if case == "local_replacement":
        old = did_from_public_key(public)
    with pytest.raises(SignerRefused, match="request_invalid"):
        binding_inputs(human, root, teams, old)
